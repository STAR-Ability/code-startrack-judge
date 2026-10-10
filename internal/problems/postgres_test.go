package problems

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/persistence/migrate"
	persistence "github.com/STAR-Ability/code-startrack-judge/internal/persistence/problems"
	"github.com/STAR-Ability/code-startrack-judge/migrations"
	"github.com/jackc/pgx/v5"
)

func isolatedDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("JUDGE_TEST_ADMIN_DATABASE_URL")
	if name := os.Getenv("JUDGE_TEST_ADMIN_DSN_FILE"); name != "" {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal("private test DSN unavailable")
		}
		dsn = strings.TrimSpace(string(raw))
	}
	if dsn == "" {
		t.Skip("PostgreSQL integration requires private admin DSN")
	}
	ctx := context.Background()
	admin, err := migrate.Open(ctx, dsn)
	if err != nil {
		t.Fatal("test database connect failed")
	}
	id, err := contract.NewUUID()
	if err != nil {
		t.Fatal("test identity unavailable")
	}
	name := "judge_problem_test_" + strings.ReplaceAll(string(id), "-", "")
	role := "judge_problem_migration_" + strings.ReplaceAll(string(id), "-", "")
	password := strings.ReplaceAll(string(uuid(t)), "-", "")
	if _, err := admin.ExecContext(ctx, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD '"+password+"'"); err != nil {
		t.Fatal("isolated migration role creation failed")
	}
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal("isolated database creation failed")
	}
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("test DSN invalid")
	}
	parsed.Path = "/" + name
	db, err := migrate.Open(ctx, parsed.String())
	if err != nil {
		t.Fatal("isolated database connect failed")
	}
	db.SetMaxOpenConns(8)
	t.Cleanup(func() {
		db.Close()
		admin.ExecContext(ctx, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
		admin.ExecContext(ctx, "DROP ROLE "+pgx.Identifier{role}.Sanitize())
		admin.Close()
	})
	if _, err := db.Exec("CREATE SCHEMA judge AUTHORIZATION " + pgx.Identifier{role}.Sanitize()); err != nil {
		t.Fatal("test schema creation failed")
	}
	if _, err := db.Exec("REVOKE ALL ON DATABASE " + pgx.Identifier{name}.Sanitize() + " FROM PUBLIC;GRANT CONNECT ON DATABASE " + pgx.Identifier{name}.Sanitize() + " TO " + pgx.Identifier{role}.Sanitize() + ";REVOKE ALL ON SCHEMA public FROM PUBLIC"); err != nil {
		t.Fatal("isolated migration boundary failed")
	}
	files, err := migrate.Load(migrations.Files)
	if err != nil {
		t.Fatal(err)
	}
	parsed.User = url.UserPassword(role, password)
	migrationDB, err := migrate.Open(ctx, parsed.String())
	if err != nil {
		t.Fatal("isolated migration connection failed")
	}
	defer migrationDB.Close()
	if _, err := migrate.Apply(ctx, migrationDB, files, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(problemFixture); err != nil {
		t.Fatal("problem fixture registration failed")
	}
	return db
}
func uuid(t *testing.T) contract.UUID {
	t.Helper()
	id, err := contract.NewUUID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func codeIs(t *testing.T, err error, code string) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("expected %s, got %v", code, err)
	}
}
func catalogVersion(t *testing.T, db *sql.DB) string {
	t.Helper()
	var s string
	if db.QueryRow("SELECT catalog_version::text FROM judge.catalog_state").Scan(&s) != nil {
		t.Fatal("catalog query failed")
	}
	return s
}

func TestPostgresMetadataPublicationWithdrawalFrozenReplay(t *testing.T) {
	db := isolatedDB(t)
	ctx := context.Background()
	ready := true
	s := New(persistence.New(db, nil), Options{FreshReady: func(context.Context) bool { return ready }})
	base := contract.UUID("00000000-0000-0000-0000-000000000011")
	_, err := s.Current(ctx, "1")
	codeIs(t, err, "PROBLEM_NOT_FOUND")
	rejected := contract.WithdrawRequest{RequestID: uuid(t), Reason: "Initial draft"}
	_, err = s.Withdraw(ctx, "2", rejected)
	codeIs(t, err, "PROBLEM_NOT_SUBMITTABLE")
	rejected.Reason = "changed"
	_, err = s.Withdraw(ctx, "2", rejected)
	codeIs(t, err, "IDEMPOTENCY_CONFLICT")
	rating := contract.SafeInt(1800)
	metadata := contract.MetadataVersionRequest{RequestID: uuid(t), BaseProblemVersionID: base, Tags: contract.Array[string]{" graph ", "graph", "DP"}, Difficulty: &rating, DifficultyScale: contract.DifficultyPlatform}
	draft, replay, err := s.Metadata(ctx, "1", metadata)
	if err != nil || replay || draft.Status != contract.ProblemDraft || len(draft.Tags) != 2 || catalogVersion(t, db) != "1" {
		t.Fatalf("metadata draft invariant: %v", err)
	}
	var artifact, basis string
	if db.QueryRow("SELECT package_artifact_id::text,rating_basis FROM judge.problem_versions WHERE id=$1", string(draft.ProblemRef.ProblemVersionID)).Scan(&artifact, &basis) != nil || artifact != "00000000-0000-0000-0000-000000000010" || basis != "MANUAL:"+string(metadata.RequestID) {
		t.Fatal("metadata did not share artifact and manual review declaration")
	}
	original, err := s.Publish(ctx, "1", contract.PublishRequest{RequestID: uuid(t), ProblemVersionID: base})
	if err != nil || original.CatalogVersion != "2" {
		t.Fatalf("publish original: %v", err)
	}
	after, err := s.Current(ctx, "1")
	if err != nil || after.ProblemRef.ProblemVersionID != base {
		t.Fatal("draft changed current")
	}
	publish := contract.PublishRequest{RequestID: uuid(t), ProblemVersionID: draft.ProblemRef.ProblemVersionID}
	published, err := s.Publish(ctx, "1", publish)
	if err != nil || published.Status != contract.ProblemPublished || published.CatalogVersion != "3" {
		t.Fatalf("publish metadata: %v", err)
	}
	noop, err := s.Publish(ctx, "1", contract.PublishRequest{RequestID: uuid(t), ProblemVersionID: draft.ProblemRef.ProblemVersionID})
	if err != nil || noop.CatalogVersion != "3" || noop.UpdatedAt != published.UpdatedAt {
		t.Fatal("no-op publication advanced public state")
	}
	old, err := s.Version(ctx, "1", base)
	if err != nil || old.Status != contract.ProblemPublished || len(old.Tags) != 0 || old.Difficulty != nil {
		t.Fatal("historical original rewritten")
	}
	withdrawn, err := s.Withdraw(ctx, "1", contract.WithdrawRequest{RequestID: uuid(t), Reason: "Rights review"})
	if err != nil || withdrawn.CatalogVersion != "4" {
		t.Fatalf("withdraw: %v", err)
	}
	ready = false
	frozen, err := s.Publish(ctx, "1", publish)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(frozen)
	b, _ := json.Marshal(published)
	if string(a) != string(b) {
		t.Fatal("replay recomputed current catalog/status")
	}
	draftAgain, replay, err := s.Metadata(ctx, "1", metadata)
	if err != nil || !replay || draftAgain.Status != contract.ProblemDraft || draftAgain.CatalogVersion != "1" {
		t.Fatal("metadata replay lost frozen response")
	}
	_, err = s.Current(ctx, "1")
	codeIs(t, err, "PROBLEM_NOT_FOUND")
	old, err = s.Version(ctx, "1", base)
	if err != nil || old.Status != contract.ProblemWithdrawn {
		t.Fatal("withdrawal lost history")
	}
	list, meta, err := s.List(ctx, ListQuery{Pagination: Pagination{Page: 1, PageSize: 20}, Status: contract.ProblemWithdrawn})
	if err != nil || len(list) != 1 || meta.Total != 1 || list[0].CatalogVersion != "4" {
		t.Fatal("withdrawn query mismatch")
	}
	_, err = s.Publish(ctx, "1", contract.PublishRequest{RequestID: uuid(t), ProblemVersionID: base})
	codeIs(t, err, "JUDGE_UNAVAILABLE")
}

func TestPostgresLiveLanguagesDoNotRewriteManagementReplay(t *testing.T) {
	db := isolatedDB(t)
	ctx := context.Background()
	live := contract.Array[string]{"cpp17"}
	providerCalls := 0
	s := New(persistence.New(db, nil), Options{LanguageCapabilities: func(context.Context) contract.Array[string] {
		providerCalls++
		return live
	}})
	base := contract.UUID("00000000-0000-0000-0000-000000000011")
	publish := contract.PublishRequest{RequestID: uuid(t), ProblemVersionID: base}
	original, err := s.Publish(ctx, "1", publish)
	if err != nil || len(original.LanguageIDs) != 1 || original.LanguageIDs[0] != "cpp17" || providerCalls != 1 {
		t.Fatalf("fresh publication did not capture measured language availability: %v", err)
	}
	assertQueryLanguages := func(want int) {
		t.Helper()
		before := providerCalls
		current, err := s.Current(ctx, "1")
		if err != nil || len(current.LanguageIDs) != want || providerCalls != before+1 {
			t.Fatal("current query did not take one live language snapshot")
		}
		version, err := s.Version(ctx, "1", base)
		if err != nil || len(version.LanguageIDs) != want || providerCalls != before+2 {
			t.Fatal("version query did not take one live language snapshot")
		}
		list, _, err := s.List(ctx, ListQuery{Pagination: Pagination{Page: 1, PageSize: 20}})
		if err != nil || len(list) != 1 || len(list[0].LanguageIDs) != want || providerCalls != before+3 {
			t.Fatal("list query did not take one live language snapshot")
		}
		history, _, err := s.History(ctx, "1", Pagination{Page: 1, PageSize: 20})
		if err != nil || len(history) == 0 || providerCalls != before+4 {
			t.Fatal("history query did not take one live language snapshot")
		}
		for _, item := range history {
			if len(item.LanguageIDs) != want {
				t.Fatal("history query mixed language snapshots")
			}
		}
		if want == 0 {
			raw, err := json.Marshal(current)
			if err != nil || !strings.Contains(string(raw), `"languageIds":[]`) {
				t.Fatal("unavailable languages were not emitted as an empty array")
			}
		}
	}
	assertQueryLanguages(1)
	live = nil
	assertQueryLanguages(0)
	beforeReplay := providerCalls
	replayed, err := s.Publish(ctx, "1", publish)
	originalJSON, _ := json.Marshal(original)
	replayJSON, _ := json.Marshal(replayed)
	if err != nil || providerCalls != beforeReplay || string(originalJSON) != string(replayJSON) {
		t.Fatal("readiness loss changed a frozen publication response or invoked the provider")
	}
	metadata := contract.MetadataVersionRequest{RequestID: uuid(t), BaseProblemVersionID: base, Tags: contract.Array[string]{"outage"}, DifficultyScale: contract.DifficultyUnrated}
	draft, replay, err := s.Metadata(ctx, "1", metadata)
	if err != nil || replay || len(draft.LanguageIDs) != 0 || providerCalls != beforeReplay+1 {
		t.Fatalf("fresh metadata did not freeze unavailable languages: %v", err)
	}
	outagePublish := contract.PublishRequest{RequestID: uuid(t), ProblemVersionID: draft.ProblemRef.ProblemVersionID}
	publication, err := s.Publish(ctx, "1", outagePublish)
	if err != nil || len(publication.LanguageIDs) != 0 || providerCalls != beforeReplay+2 {
		t.Fatalf("fresh publication did not freeze unavailable languages: %v", err)
	}
	live = contract.Array[string]{"cpp17"}
	assertQueryLanguages(1)
	beforeReplay = providerCalls
	draftReplay, replay, err := s.Metadata(ctx, "1", metadata)
	draftJSON, _ := json.Marshal(draft)
	draftReplayJSON, _ := json.Marshal(draftReplay)
	if err != nil || !replay || providerCalls != beforeReplay || string(draftJSON) != string(draftReplayJSON) {
		t.Fatal("restored readiness changed a frozen metadata response or invoked the provider")
	}
	publicationReplay, err := s.Publish(ctx, "1", outagePublish)
	publicationJSON, _ := json.Marshal(publication)
	publicationReplayJSON, _ := json.Marshal(publicationReplay)
	if err != nil || providerCalls != beforeReplay || string(publicationJSON) != string(publicationReplayJSON) {
		t.Fatal("restored readiness changed a frozen publication response or invoked the provider")
	}
}

func TestPostgresConcurrentOperationAndFrozenFailures(t *testing.T) {
	db := isolatedDB(t)
	ctx := context.Background()
	repo := persistence.New(db, nil)
	request := uuid(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := repo.Operation(ctx, "PUBLISH", request, strings.Repeat("a", 64), "1", nil, func(*persistence.Tx) (any, error) {
			close(entered)
			<-release
			return map[string]any{"accepted": true}, nil
		})
		done <- err
	}()
	<-entered
	start := time.Now()
	_, err := repo.Operation(ctx, "PUBLISH", request, strings.Repeat("a", 64), "1", nil, func(*persistence.Tx) (any, error) { t.Error("operation applied twice"); return nil, nil })
	codeIs(t, err, "REQUEST_IN_PROGRESS")
	if time.Since(start) > time.Second {
		t.Fatal("in-progress request blocked")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	out, err := repo.Operation(ctx, "PUBLISH", request, strings.Repeat("a", 64), "1", func(context.Context) bool { return false }, func(*persistence.Tx) (any, error) { t.Error("replay applied twice"); return nil, nil })
	if err != nil || !out.Replay {
		t.Fatal("replay failed after readiness loss")
	}
	s := New(repo, Options{})
	req := contract.PublishRequest{RequestID: uuid(t), ProblemVersionID: contract.UUID("00000000-0000-0000-0000-000000000011")}
	_, err = s.Publish(ctx, "2", req)
	codeIs(t, err, "PROBLEM_VERSION_CONFLICT")
	_, err = s.Publish(ctx, "1", req)
	codeIs(t, err, "IDEMPOTENCY_CONFLICT")
	ids := make([]contract.UUID, 8)
	var wg sync.WaitGroup
	failure := make(chan error, 8)
	for i := range ids {
		ids[i] = uuid(t)
		wg.Add(1)
		go func(id contract.UUID) {
			defer wg.Done()
			_, _, err := s.Metadata(ctx, "1", contract.MetadataVersionRequest{RequestID: id, BaseProblemVersionID: req.ProblemVersionID, Tags: contract.Array[string]{"concurrent"}, DifficultyScale: contract.DifficultyUnrated})
			failure <- err
		}(ids[i])
	}
	wg.Wait()
	close(failure)
	for err := range failure {
		if err != nil {
			t.Fatal(err)
		}
	}
	var count, maxNumber int
	if db.QueryRow("SELECT count(*),max(version_number) FROM judge.problem_versions WHERE problem_id=1").Scan(&count, &maxNumber) != nil || count != 9 || maxNumber != 9 {
		t.Fatal("concurrent allocation duplicated/lost versions")
	}
}

const problemFixture = `BEGIN;
INSERT INTO judge.platform_problems(source,repository_url,package_path,status) VALUES
 ('OJ_LAB','https://github.com/oj-lab/problem-packages','problems/alpha','DRAFT'),
 ('OJ_LAB','https://github.com/oj-lab/problem-packages','problems/beta','DRAFT');
INSERT INTO judge.license_evidence(id,repository_url,source_revision,package_path,status,license_scope,spdx_id,notice,source_url,license_files,evidence,reviewed_by,reviewed_at)
 VALUES('00000000-0000-0000-0000-000000000001','https://github.com/oj-lab/problem-packages',repeat('a',40),'problems/alpha','VERIFIED','PACKAGE','MIT','fixture license','https://github.com/oj-lab/problem-packages/blob/fixture/LICENSE','[{"path":"LICENSE","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","spdxId":"MIT"}]','{"policy":"ADMIN_HUMAN_OFFLINE_V1","sourceSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","coverage":"Package reviewed","thirdPartyReview":"All files checked","approvalEvidence":"Human fixture review"}','admin:fixture',now());
INSERT INTO judge.package_source_identities(id,repository_url,source_revision,package_path,source_sha256)
 VALUES('00000000-0000-0000-0000-000000000002','https://github.com/oj-lab/problem-packages',repeat('a',40),'problems/alpha',repeat('a',64));
INSERT INTO judge.package_content_identities(id,source_identity_id,adapter_version,source_format,manifest_version,normalized_sha256,manifest_sha256,manifest)
 VALUES('00000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000002','ojlab-kattis-v0.2.1','oj-lab-v1','0.2.0',repeat('a',64),repeat('a',64),'{"testCount":2}');
INSERT INTO judge.package_artifacts(id,problem_id,content_identity_id,source,repository_url,source_revision,package_path,source_format,adapter_version,manifest_version,source_archive_key,source_sha256,normalized_archive_key,normalized_sha256,manifest,source_metadata,license_evidence_id,validation_run_id,validation_context,evidence_set_hash)
 VALUES('00000000-0000-0000-0000-000000000010',1,'00000000-0000-0000-0000-000000000003','OJ_LAB','https://github.com/oj-lab/problem-packages',repeat('a',40),'problems/alpha','oj-lab-v1','ojlab-kattis-v0.2.1','0.2.0','private/source',repeat('a',64),'private/normalized',repeat('a',64),'{"testCount":2}','{"upstream":true}','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000004',jsonb_build_object('problemtoolsVersion','v1.20260907','adapterVersion','ojlab-kattis-v0.2.1','toolchainVersion','gcc-fixture','imageDigest','sha256:'||repeat('a',64),'configSha256',repeat('a',64),'sourceSha256',repeat('a',64),'normalizedSha256',repeat('a',64)),repeat('a',64));
INSERT INTO judge.package_validation_runs(id,package_artifact_id,status,problemtools_version,adapter_version,toolchain_version,image_digest,config_sha256,source_sha256,normalized_sha256,results,errors,adaptations,started_at,finished_at)
 VALUES('00000000-0000-0000-0000-000000000004','00000000-0000-0000-0000-000000000010','PASSED','v1.20260907','ojlab-kattis-v0.2.1','gcc-fixture','sha256:'||repeat('a',64),repeat('a',64),repeat('a',64),repeat('a',64),
 (SELECT jsonb_object_agg(name,jsonb_build_object('passed',true,'evidence',jsonb_build_array(jsonb_build_object('check','FIXTURE_VALIDATION','subjectSha256',repeat('a',64),'logObjectKey',NULL,'summary','Fixture checkpoint passed')))) FROM unnest(ARRAY['structure','statement','testData','validators','referenceSolutions']) name),'[]','[]',now(),now());
INSERT INTO judge.problem_versions(id,problem_id,version_number,package_artifact_id,title,statement_format,statement_content,samples,difficulty_scale,time_limit_ms,wall_limit_ms,memory_limit_bytes,output_limit_bytes,language_ids,judge_mode,checker_config,metadata_hash)
 VALUES('00000000-0000-0000-0000-000000000011',1,1,'00000000-0000-0000-0000-000000000010','Alpha','MARKDOWN','fixture statement','[{"input":"sample","output":"answer"}]','UNRATED',1000,2000,10000,10000,ARRAY['cpp17'],'BATCH_PASS_FAIL','{}',repeat('a',64));
INSERT INTO judge.problem_test_cases(id,package_artifact_id,ordinal,visibility,input_object_key,answer_object_key,input_sha256,answer_sha256,input_size_bytes,answer_size_bytes)
 VALUES('00000000-0000-0000-0000-000000000020','00000000-0000-0000-0000-000000000010',1,'SAMPLE','private/input','private/answer',repeat('a',64),repeat('a',64),1,1);
INSERT INTO judge.problem_test_cases(id,package_artifact_id,ordinal,visibility,input_object_key,answer_object_key,input_sha256,answer_sha256,input_size_bytes,answer_size_bytes)
 VALUES('00000000-0000-0000-0000-000000000022','00000000-0000-0000-0000-000000000010',2,'SECRET','private/secret-input','private/secret-answer',repeat('b',64),repeat('b',64),1,1);
INSERT INTO judge.reference_solutions(id,package_artifact_id,role,language_id,source_object_key,source_sha256,upstream_path)
 VALUES('00000000-0000-0000-0000-000000000021','00000000-0000-0000-0000-000000000010','ACCEPTED','cpp17','private/reference',repeat('a',64),'submissions/accepted/main.cpp');
INSERT INTO judge.judge_language_configs(language_id,config_version,display_name,language_family,compiler_version,source_filename,compile_template,run_template,compile_limits,toolchain_digest,analysis_supported,is_active)
 VALUES('cpp17','fixture-1','C++17','C++','gcc-fixture','main.cpp','{}','{}','{}','sha256:'||repeat('a',64),false,true);
UPDATE judge.platform_problems SET latest_version_id='00000000-0000-0000-0000-000000000011' WHERE id=1;
COMMIT;`
