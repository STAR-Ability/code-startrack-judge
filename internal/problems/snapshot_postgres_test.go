package problems

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/STAR-Ability/code-startrack-judge/internal/catalog"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	persistence "github.com/STAR-Ability/code-startrack-judge/internal/persistence/problems"
)

func TestPostgresSnapshotFreezesPagesTombstonesAndWholeExpiryCleanup(t *testing.T) {
	db := isolatedDB(t)
	ctx := context.Background()
	repo := persistence.New(db, nil)
	key := []byte(strings.Repeat("s", 32))
	snapshots, err := catalog.New(repo, key)
	if err != nil {
		t.Fatal(err)
	}
	service := New(repo, Options{})
	empty, err := snapshots.Page(ctx, nil, 1)
	if err != nil || len(empty.Items) != 0 || empty.NextCursor != nil || empty.CatalogVersion != "1" {
		t.Fatal("empty snapshot shape invalid")
	}
	if _, err := db.Exec(secondProblemFixture); err != nil {
		t.Fatal("second immutable problem fixture failed")
	}
	for _, item := range []struct {
		problem contract.ID
		version contract.UUID
	}{{"1", "00000000-0000-0000-0000-000000000011"}, {"10", "00000000-0000-0000-0000-000000000045"}} {
		if _, err := service.Publish(ctx, item.problem, contract.PublishRequest{RequestID: uuid(t), ProblemVersionID: item.version}); err != nil {
			t.Fatal(err)
		}
	}
	first, err := snapshots.Page(ctx, nil, 1)
	if err != nil || len(first.Items) != 1 || first.Items[0].Problem.ProblemRef.ProblemID != "1" || first.NextCursor == nil || first.CatalogVersion != "3" {
		t.Fatalf("snapshot first page: %v", err)
	}
	if _, err := service.Withdraw(ctx, "10", contract.WithdrawRequest{RequestID: uuid(t), Reason: "Synthetic rights review"}); err != nil {
		t.Fatal(err)
	}
	second, err := snapshots.Page(ctx, first.NextCursor, 1)
	if err != nil || second.SnapshotID != first.SnapshotID || second.CatalogVersion != first.CatalogVersion || len(second.Items) != 1 || second.Items[0].Problem.ProblemRef.ProblemID != "10" || second.Items[0].Status != contract.ProblemPublished || second.NextCursor != nil {
		t.Fatal("later page mixed newer publication state or lexical ID order")
	}
	current, err := snapshots.Page(ctx, nil, 100)
	if err != nil || current.CatalogVersion != "4" || len(current.Items) != 2 || current.Items[1].Status != contract.ProblemWithdrawn || current.Items[1].Problem.Title == nil || *current.Items[1].Problem.Title != "Gamma" {
		t.Fatal("fresh snapshot lost immutable withdrawal tombstone")
	}
	_, err = snapshots.Page(ctx, first.NextCursor, 2)
	if err == nil {
		t.Fatal("changed page limit accepted")
	}
	tampered := *first.NextCursor + "!"
	if _, err := snapshots.Page(ctx, &tampered, 1); err == nil {
		t.Fatal("tampered cursor accepted")
	}
	expiredID := uuid(t)
	if _, err := db.Exec(`INSERT INTO judge.catalog_snapshots(id,catalog_version,item_count,page_limit,created_at,expires_at) VALUES($1,4,0,1,clock_timestamp()-interval '31 minutes',clock_timestamp()-interval '1 minute')`, string(expiredID)); err != nil {
		t.Fatal("expired fixture registration failed")
	}
	payload := []byte(fmt.Sprintf(`{"v":1,"snapshotId":"%s","offset":1,"limit":1}`, expiredID))
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("startrack-catalog-cursor-v1\x00"))
	mac.Write(payload)
	cursor := base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	_, err = snapshots.Page(ctx, &cursor, 1)
	codeIs(t, err, "SNAPSHOT_EXPIRED")
	cleaned, err := snapshots.Cleanup(ctx, 100)
	if err != nil || cleaned != 1 {
		t.Fatal("expired whole snapshot cleanup failed")
	}
	_, err = snapshots.Page(ctx, &cursor, 1)
	codeIs(t, err, "SNAPSHOT_EXPIRED")
	if _, err := snapshots.Page(ctx, first.NextCursor, 1); err != nil {
		t.Fatal("cleanup touched unexpired snapshot")
	}
	var problems, versions int
	if db.QueryRow("SELECT count(*) FROM judge.platform_problems").Scan(&problems) != nil || db.QueryRow("SELECT count(*) FROM judge.problem_versions").Scan(&versions) != nil || problems != 3 || versions != 2 {
		t.Fatal("snapshot cleanup changed business history")
	}
}

const secondProblemFixture = `BEGIN;
INSERT INTO judge.platform_problems(id,source,repository_url,package_path,status) OVERRIDING SYSTEM VALUE VALUES(10,'OJ_LAB','https://github.com/oj-lab/problem-packages','problems/gamma','DRAFT');
INSERT INTO judge.license_evidence SELECT(jsonb_populate_record(NULL::judge.license_evidence,to_jsonb(l)||jsonb_build_object('id','00000000-0000-0000-0000-000000000044','package_path','problems/gamma'))).* FROM judge.license_evidence l;
INSERT INTO judge.package_source_identities SELECT(jsonb_populate_record(NULL::judge.package_source_identities,to_jsonb(s)||jsonb_build_object('id','00000000-0000-0000-0000-000000000041','package_path','problems/gamma'))).* FROM judge.package_source_identities s;
INSERT INTO judge.package_content_identities SELECT(jsonb_populate_record(NULL::judge.package_content_identities,to_jsonb(c)||jsonb_build_object('id','00000000-0000-0000-0000-000000000042','source_identity_id','00000000-0000-0000-0000-000000000041'))).* FROM judge.package_content_identities c;
INSERT INTO judge.package_artifacts SELECT(jsonb_populate_record(NULL::judge.package_artifacts,to_jsonb(a)||jsonb_build_object('id','00000000-0000-0000-0000-000000000040','problem_id',10,'content_identity_id','00000000-0000-0000-0000-000000000042','package_path','problems/gamma','license_evidence_id','00000000-0000-0000-0000-000000000044','validation_run_id','00000000-0000-0000-0000-000000000043','evidence_set_hash',repeat('c',64)))).* FROM judge.package_artifacts a;
INSERT INTO judge.problem_test_cases SELECT(jsonb_populate_record(NULL::judge.problem_test_cases,to_jsonb(c)||jsonb_build_object('id',gen_random_uuid(),'package_artifact_id','00000000-0000-0000-0000-000000000040'))).* FROM judge.problem_test_cases c;
INSERT INTO judge.reference_solutions SELECT(jsonb_populate_record(NULL::judge.reference_solutions,to_jsonb(r)||jsonb_build_object('id',gen_random_uuid(),'package_artifact_id','00000000-0000-0000-0000-000000000040'))).* FROM judge.reference_solutions r;
INSERT INTO judge.package_validation_runs SELECT(jsonb_populate_record(NULL::judge.package_validation_runs,to_jsonb(r)||jsonb_build_object('id','00000000-0000-0000-0000-000000000043','package_artifact_id','00000000-0000-0000-0000-000000000040'))).* FROM judge.package_validation_runs r;
INSERT INTO judge.problem_versions SELECT(jsonb_populate_record(NULL::judge.problem_versions,to_jsonb(v)||jsonb_build_object('id','00000000-0000-0000-0000-000000000045','problem_id',10,'package_artifact_id','00000000-0000-0000-0000-000000000040','title','Gamma'))).* FROM judge.problem_versions v;
UPDATE judge.platform_problems SET latest_version_id='00000000-0000-0000-0000-000000000045' WHERE id=10;
COMMIT;`
