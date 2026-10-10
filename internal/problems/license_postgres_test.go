package problems

import (
	"archive/tar"
	"bytes"
	"context"
	"database/sql"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/STAR-Ability/code-startrack-judge/internal/persistence/migrate"
	persistence "github.com/STAR-Ability/code-startrack-judge/internal/persistence/problems"
	"github.com/STAR-Ability/code-startrack-judge/internal/storage"
	"github.com/STAR-Ability/code-startrack-judge/internal/testutil/postgres"
)

func TestPostgresHumanLicenseApprovalIsAppendOnlySourceBoundAndIdempotent(t *testing.T) {
	db := isolatedDB(t)
	postgres.ReserveLicenseReviewer(t)
	ctx := context.Background()
	var exists bool
	if db.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='judge_license_reviewer')`).Scan(&exists) != nil {
		t.Fatal("reviewer role inspection failed")
	}
	if exists {
		t.Skip("dedicated reviewer identity reserved by another qualification")
	}
	password := strings.ReplaceAll(string(uuid(t)), "-", "")
	if _, err := db.Exec(`CREATE ROLE judge_license_reviewer LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD '` + password + `'`); err != nil {
		t.Fatal("dedicated reviewer role creation failed")
	}
	t.Cleanup(func() { db.Exec(`DROP OWNED BY judge_license_reviewer;DROP ROLE judge_license_reviewer`) })
	if _, err := db.Exec(`GRANT USAGE ON SCHEMA judge TO judge_license_reviewer;GRANT SELECT ON judge.license_evidence,judge.rejected_package_evidence,judge.private_objects TO judge_license_reviewer;GRANT INSERT ON judge.license_evidence TO judge_license_reviewer;GRANT EXECUTE ON FUNCTION judge.valid_package_path(text) TO judge_license_reviewer;GRANT CONNECT ON DATABASE ` + quotedDatabase(t, db) + ` TO judge_license_reviewer`); err != nil {
		t.Fatal("reviewer narrow grants failed")
	}
	for _, setting := range []string{"log_statement='none'", "log_min_error_statement='panic'", "log_min_duration_statement=-1", "log_min_duration_sample=-1", "log_duration=off", "log_parameter_max_length=0", "log_parameter_max_length_on_error=0", "log_transaction_sample_rate=0", "log_error_verbosity='terse'", "log_min_messages='panic'"} {
		if _, err := db.Exec(`ALTER ROLE judge_license_reviewer IN DATABASE ` + quotedDatabase(t, db) + ` SET ` + setting); err != nil {
			t.Fatal("reviewer private SQL logging policy failed")
		}
	}
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	text := "Synthetic package license.\n"
	if writer.WriteHeader(&tar.Header{Name: "LICENSE", Mode: 0644, Typeflag: tar.TypeReg, Size: int64(len(text))}) != nil {
		t.Fatal("license archive fixture failed")
	}
	writer.Write([]byte(text))
	writer.Close()
	storagePath := t.TempDir()
	if os.Chmod(storagePath, 0700) != nil {
		t.Fatal("private storage fixture chmod failed")
	}
	store, err := storage.New(storagePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	object, err := store.Put(ctx, bytes.NewReader(archive.Bytes()), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	approval := licenseReceipt()
	approval.EvidenceID = uuid(t)
	approval.RejectedEvidenceID = uuid(t)
	approval.SourceSHA256 = object.SHA256
	approval.SourceRevision = strings.Repeat("b", 40)
	approval.SourceURL = approval.RepositoryURL + "/tree/" + approval.SourceRevision + "/" + approval.PackagePath
	previous := uuid(t)
	approval.PreviousEvidenceID = &previous
	job, item := uuid(t), uuid(t)
	if _, err := db.Exec(`INSERT INTO judge.private_objects(object_key,sha256,size_bytes) VALUES($1,$2,$3)`, object.Key, object.SHA256, object.SizeBytes); err != nil {
		t.Fatal("private source object fixture failed")
	}
	if _, err := db.Exec(`INSERT INTO judge.license_evidence(id,repository_url,source_revision,package_path,status,license_scope,notice,source_url,license_files,evidence) VALUES($1,$2,$3,$4,'REVIEW_REQUIRED','UNKNOWN','','','[]','{"automaticSuggestion":"human review required"}')`, string(previous), approval.RepositoryURL, approval.SourceRevision, approval.PackagePath); err != nil {
		t.Fatal("automatic evidence fixture failed")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal("retained evidence transaction failed")
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO judge.import_jobs(id,request_id,request_hash,source,repository_url,source_revision,status,package_count,completed_package_count,error,started_at,finished_at) VALUES($1,$1,repeat('a',64),'OJ_LAB',$2,$3,'FAILED',1,1,'{"code":"PACKAGE_LICENSE_MISSING","message":"Human review required","retryable":false}',now(),now())`, string(job), approval.RepositoryURL, approval.SourceRevision); err != nil {
		t.Fatal("retained job fixture failed")
	}
	if _, err := tx.Exec(`INSERT INTO judge.import_items(id,import_job_id,ordinal,package_path,status,license_status,validation_status,errors) VALUES($1,$2,1,$3,'REJECTED','REVIEW_REQUIRED','PENDING','[{"code":"PACKAGE_LICENSE_MISSING","message":"Human review required","retryable":false}]')`, string(item), string(job), approval.PackagePath); err != nil {
		t.Fatal("retained item fixture failed")
	}
	if _, err := tx.Exec(`INSERT INTO judge.rejected_package_evidence(id,import_item_id,repository_url,source_revision,package_path,failure_stage,source_archive_key,source_sha256,license_evidence_id,provenance,source_metadata,adaptations,errors,evidence_sha256) VALUES($1,$2,$3,$4,$5,'LICENSE_REVIEW',$6,$7,$8,'{"fixture":true}','{}','[]','[{"code":"PACKAGE_LICENSE_MISSING","message":"Human review required","retryable":false}]',repeat('a',64))`, string(approval.RejectedEvidenceID), string(item), approval.RepositoryURL, approval.SourceRevision, approval.PackagePath, object.Key, object.SHA256, string(previous)); err != nil {
		t.Fatal("retained rejected evidence fixture failed")
	}
	if err := tx.Commit(); err != nil {
		t.Fatal("retained evidence commit failed")
	}
	dsn := os.Getenv("JUDGE_TEST_ADMIN_DATABASE_URL")
	if filename := os.Getenv("JUDGE_TEST_ADMIN_DSN_FILE"); filename != "" {
		raw, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal("private DSN unavailable")
		}
		dsn = strings.TrimSpace(string(raw))
	}
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("private DSN invalid")
	}
	var name string
	if db.QueryRow(`SELECT current_database()`).Scan(&name) != nil {
		t.Fatal("isolated DB identity failed")
	}
	parsed.Path = "/" + name
	parsed.User = url.UserPassword("judge_license_reviewer", password)
	reviewDB, err := migrate.Open(ctx, parsed.String())
	if err != nil {
		t.Fatal("reviewer connection failed")
	}
	defer reviewDB.Close()
	reviewDB.SetMaxOpenConns(6)
	repo := persistence.New(reviewDB, nil)
	bad := approval
	bad.SourceSHA256 = strings.Repeat("f", 64)
	if _, err := ApproveLicense(ctx, repo, store, "ADMIN:human", bad); err == nil {
		t.Fatal("another source checksum was approved")
	}
	var wg sync.WaitGroup
	failures := make(chan error, 4)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := ApproveLicense(ctx, repo, store, "ADMIN:human", approval)
			failures <- err
		}()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	var count int
	var status, actor, sourceHash string
	if db.QueryRow(`SELECT count(*) FROM judge.license_evidence WHERE id=$1`, string(approval.EvidenceID)).Scan(&count) != nil || count != 1 {
		t.Fatal("concurrent approval duplicated evidence")
	}
	if db.QueryRow(`SELECT status,reviewed_by,evidence->>'sourceSha256' FROM judge.license_evidence WHERE id=$1`, string(approval.EvidenceID)).Scan(&status, &actor, &sourceHash) != nil || status != "VERIFIED" || actor != "ADMIN:human" || sourceHash != object.SHA256 {
		t.Fatal("human approval lost exact source or reviewer")
	}
	if db.QueryRow(`SELECT status FROM judge.license_evidence WHERE id=$1`, string(previous)).Scan(&status) != nil || status != "REVIEW_REQUIRED" {
		t.Fatal("approval rewrote automatic predecessor")
	}
	bad = approval
	bad.Notice = "changed"
	_, err = ApproveLicense(ctx, repo, store, "ADMIN:human", bad)
	codeIs(t, err, "IDEMPOTENCY_CONFLICT")
	if _, err := reviewDB.Exec(`UPDATE judge.license_evidence SET notice='rewrite' WHERE id=$1`, string(approval.EvidenceID)); err == nil {
		t.Fatal("reviewer mutated prior evidence")
	}
	if _, err := reviewDB.Exec(`UPDATE judge.catalog_state SET catalog_version=catalog_version+1`); err == nil {
		t.Fatal("reviewer gained publication authority")
	}
	for _, policy := range []struct{ unsafe, restore string }{
		{"log_transaction_sample_rate=1", "log_transaction_sample_rate=0"},
		{"log_error_verbosity='default'", "log_error_verbosity='terse'"},
		{"log_min_messages='warning'", "log_min_messages='panic'"},
	} {
		if _, err := db.Exec(`ALTER ROLE judge_license_reviewer IN DATABASE ` + quotedDatabase(t, db) + ` SET ` + policy.unsafe); err != nil {
			t.Fatal("unsafe reviewer logging fixture failed")
		}
		unsafeDB, err := migrate.Open(ctx, parsed.String())
		if err != nil {
			t.Fatal("unsafe reviewer connection failed")
		}
		_, err = ApproveLicense(ctx, persistence.New(unsafeDB, nil), store, "ADMIN:human", approval)
		unsafeDB.Close()
		codeIs(t, err, "SERVICE_UNAUTHORIZED")
		if _, err := db.Exec(`ALTER ROLE judge_license_reviewer IN DATABASE ` + quotedDatabase(t, db) + ` SET ` + policy.restore); err != nil {
			t.Fatal("reviewer logging policy restoration failed")
		}
	}
}

func quotedDatabase(t *testing.T, db interface{ QueryRow(string, ...any) *sql.Row }) string {
	t.Helper()
	var name string
	if db.QueryRow(`SELECT quote_ident(current_database())`).Scan(&name) != nil {
		t.Fatal("database identifier query failed")
	}
	return name
}
