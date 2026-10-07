package migrate

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/migrations"
	"github.com/jackc/pgx/v5"
)

// Integration tests own a newly named disposable database and two newly named
// roles. They never reset a supplied database. The admin DSN stays in a private
// file/environment and driver/server diagnostics are omitted from test output.
func testDatabase(t *testing.T) (string, string, *sql.DB) {
	t.Helper()
	adminDSN := os.Getenv("JUDGE_TEST_ADMIN_DATABASE_URL")
	if path := os.Getenv("JUDGE_TEST_ADMIN_DSN_FILE"); path != "" {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("cannot read private test admin DSN file")
		}
		adminDSN = strings.TrimSpace(string(body))
	}
	if adminDSN == "" {
		t.Skip("PostgreSQL integration requires JUDGE_TEST_ADMIN_DSN_FILE or JUDGE_TEST_ADMIN_DATABASE_URL")
	}
	ctx := context.Background()
	admin, err := Open(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		t.Fatal("cannot generate isolated database identity")
	}
	suffix := hex.EncodeToString(random)
	dbName, migrationRole, runtimeRole := "judge_test_"+suffix, "judge_migrate_"+suffix, "judge_runtime_"+suffix
	passwordBytes := make([]byte, 32)
	if _, err := rand.Read(passwordBytes); err != nil {
		t.Fatal("cannot generate disposable role credential")
	}
	password := hex.EncodeToString(passwordBytes)
	for _, role := range []string{migrationRole, runtimeRole} {
		_, err := admin.ExecContext(ctx, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD '"+password+"'")
		if err != nil {
			t.Fatal(dbError("provision isolated role", err))
		}
	}
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+pgx.Identifier{dbName}.Sanitize()); err != nil {
		t.Fatal(dbError("provision isolated database", err))
	}
	connectionURL, err := url.Parse(adminDSN)
	if err != nil || connectionURL.Host == "" || (connectionURL.Scheme != "postgres" && connectionURL.Scheme != "postgresql") {
		t.Fatal("invalid test admin connection")
	}
	connectionURL.Path = "/" + dbName
	isolatedAdmin, err := Open(ctx, connectionURL.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = isolatedAdmin.Close()
		_, _ = admin.ExecContext(ctx, "DROP DATABASE "+pgx.Identifier{dbName}.Sanitize()+" WITH (FORCE)")
		_, _ = admin.ExecContext(ctx, "DROP ROLE "+pgx.Identifier{runtimeRole}.Sanitize())
		_, _ = admin.ExecContext(ctx, "DROP ROLE "+pgx.Identifier{migrationRole}.Sanitize())
		_ = admin.Close()
	})
	statements := []string{
		"REVOKE ALL ON DATABASE " + pgx.Identifier{dbName}.Sanitize() + " FROM PUBLIC",
		"GRANT CONNECT ON DATABASE " + pgx.Identifier{dbName}.Sanitize() + " TO " + pgx.Identifier{migrationRole}.Sanitize() + "," + pgx.Identifier{runtimeRole}.Sanitize(),
		"REVOKE ALL ON SCHEMA public FROM PUBLIC",
		"CREATE SCHEMA judge AUTHORIZATION " + pgx.Identifier{migrationRole}.Sanitize(),
		"REVOKE ALL ON SCHEMA judge FROM PUBLIC",
		"CREATE SCHEMA backend",
		"CREATE TABLE backend.private_source (source text)",
		"CREATE SCHEMA algorithm",
		"CREATE TABLE algorithm.private_analysis (data text)",
	}
	for _, statement := range statements {
		if _, err := isolatedAdmin.ExecContext(ctx, statement); err != nil {
			t.Fatal(dbError("provision schema boundary", err))
		}
	}
	connectionURL.User = url.UserPassword(migrationRole, password)
	migrationDSN := connectionURL.String()
	connectionURL.User = url.UserPassword(runtimeRole, password)
	return migrationDSN, connectionURL.String(), isolatedAdmin
}

func applyTest(t *testing.T, dsn string, files []Migration) {
	t.Helper()
	db, err := Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	status, err := Apply(context.Background(), db, files, 0)
	if err != nil || status.Applied != len(files) || status.Dirty {
		t.Fatalf("apply: status=%+v, error=%v", status, err)
	}
}

func TestPostgresFreshRepeatChecksumFailureAndPrivileges(t *testing.T) {
	migrationDSN, runtimeDSN, admin := testDatabase(t)
	files, err := Load(migrations.Files)
	if err != nil {
		t.Fatal(err)
	}
	before, err := Inspect(context.Background(), admin, files)
	if err != nil || before.Initialized || before.Applied != 0 {
		t.Fatalf("status initialized a fresh DB: %+v, %v", before, err)
	}
	applyTest(t, migrationDSN, files)
	applyTest(t, migrationDSN, files)
	changed := append([]Migration(nil), files...)
	changed[0].SHA256 = strings.Repeat("f", 64)
	if _, err := Inspect(context.Background(), admin, changed); err == nil {
		t.Fatal("status accepted historical checksum mutation")
	}
	var runtimeRole string
	runtime, err := Open(context.Background(), runtimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if err := runtime.QueryRow("SELECT current_user").Scan(&runtimeRole); err != nil {
		t.Fatal(dbError("identify isolated runtime role", err))
	}
	grant := "GRANT USAGE ON SCHEMA judge TO " + pgx.Identifier{runtimeRole}.Sanitize()
	if _, err := admin.Exec(grant); err != nil {
		t.Fatal(dbError("grant runtime schema usage", err))
	}
	// Version/checksum visibility is read-only. Application table grants are
	// explicit; migration history never receives runtime mutation privileges.
	if _, err := admin.Exec("GRANT SELECT ON judge.schema_migrations,judge.migration_checksums TO " + pgx.Identifier{runtimeRole}.Sanitize()); err != nil {
		t.Fatal(dbError("grant runtime history visibility", err))
	}
	if _, err := Inspect(context.Background(), runtime, files); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		"CREATE TABLE judge.forbidden (id integer)",
		"CREATE TABLE public.forbidden (id integer)",
		"CREATE TEMP TABLE forbidden_temp(id integer)",
		"SELECT * FROM backend.private_source", "UPDATE backend.private_source SET source='x'",
		"SELECT * FROM algorithm.private_analysis", "DELETE FROM algorithm.private_analysis",
		"DELETE FROM judge.migration_checksums", "CREATE ROLE forbidden_runtime_role",
	} {
		if _, err := runtime.Exec(statement); err == nil {
			t.Fatalf("runtime privilege boundary accepted: %s", statement)
		}
	}
}

func TestPostgresConcurrentNativeRunners(t *testing.T) {
	dsn, _, admin := testDatabase(t)
	files, err := Load(fstest.MapFS{"000001_slow.up.sql": {Data: []byte("BEGIN;\nSELECT pg_sleep(0.2);\nCREATE TABLE judge.concurrent_marker(id integer);\nCOMMIT;\n")}})
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			db, err := Open(context.Background(), dsn)
			if err == nil {
				defer db.Close()
				_, err = Apply(context.Background(), db, files, 0)
			}
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := admin.QueryRow("SELECT count(*) FROM judge.migration_checksums").Scan(&count); err != nil || count != 1 {
		t.Fatalf("concurrent ledger count=%d, error=%v", count, dbError("read concurrent ledger", err))
	}
}

func TestPostgresFailureIsDirtyAndAtomic(t *testing.T) {
	dsn, _, admin := testDatabase(t)
	files, err := Load(fstest.MapFS{"000001_fail.up.sql": {Data: []byte("BEGIN;\nCREATE TABLE judge.must_rollback(id integer);\nSELECT 1/0;\nCOMMIT;\n")}})
	if err != nil {
		t.Fatal(err)
	}
	db, err := Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Apply(context.Background(), db, files, 0)
	if err == nil {
		t.Fatal("failed SQL reported success")
	}
	var dirty, absent bool
	if err := admin.QueryRow("SELECT dirty FROM judge.schema_migrations").Scan(&dirty); err != nil || !dirty {
		t.Fatal("failed migration must retain native dirty state")
	}
	if err := admin.QueryRow("SELECT to_regclass('judge.must_rollback') IS NULL").Scan(&absent); err != nil || !absent {
		t.Fatal("failed explicit transaction left business objects behind")
	}
	if _, err := Inspect(context.Background(), admin, files); err == nil {
		t.Fatal("status accepted dirty schema")
	}
	db, err = Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(context.Background(), db, files, 0); err == nil {
		t.Fatal("runner automatically retried/erased dirty state")
	}
}

func TestPostgresBaselineIntegrity(t *testing.T) {
	dsn, _, admin := testDatabase(t)
	files, err := Load(migrations.Files)
	if err != nil {
		t.Fatal(err)
	}
	applyTest(t, dsn, files)
	if _, err := admin.Exec(baselineFixture); err != nil {
		t.Fatal(dbError("insert valid circular baseline fixture", err))
	}
	for name, statement := range map[string]string{
		"published_version_rewrite": "UPDATE judge.problem_versions SET title='changed' WHERE problem_id=1",
		"license_rewrite":           "UPDATE judge.license_evidence SET notice='changed'",
		"source_identity_rewrite":   "UPDATE judge.package_source_identities SET source_sha256=repeat('b',64)",
		"content_identity_rewrite":  "UPDATE judge.package_content_identities SET normalized_sha256=repeat('b',64)",
		"artifact_rewrite":          "UPDATE judge.package_artifacts SET source_metadata='{}'",
		"validation_rewrite":        "UPDATE judge.package_validation_runs SET results='{}'",
		"test_rewrite":              "UPDATE judge.problem_test_cases SET ordinal=2",
		"language_rewrite":          "UPDATE judge.judge_language_configs SET compiler_version='invented'",
		"cross_problem_current":     "UPDATE judge.platform_problems SET latest_version_id='00000000-0000-0000-0000-000000000011' WHERE id=2",
		"rated_without_basis":       "INSERT INTO judge.problem_versions(id,problem_id,version_number,package_artifact_id,title,statement_format,statement_content,difficulty,difficulty_scale,time_limit_ms,wall_limit_ms,memory_limit_bytes,output_limit_bytes,language_ids,judge_mode,checker_config,metadata_hash) VALUES('00000000-0000-0000-0000-000000000012',1,2,'00000000-0000-0000-0000-000000000010','bad','MARKDOWN','text',1000,'PLATFORM_RATING',1000,2000,10000,10000,ARRAY['cpp17'],'BATCH_PASS_FAIL','{}',repeat('a',64))",
		"snapshot_incomplete":       "INSERT INTO judge.catalog_snapshots(id,catalog_version,item_count,page_limit,expires_at) VALUES('00000000-0000-0000-0000-000000000099',1,1,100,now()+interval '30 minutes')",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := admin.Exec(statement); err == nil {
				t.Fatal("invalid immutable/cross-owner state committed")
			}
		})
	}
}

func TestPostgresTaskResultOutboxAndCatalogTransactions(t *testing.T) {
	dsn, _, admin := testDatabase(t)
	files, err := Load(migrations.Files)
	if err != nil {
		t.Fatal(err)
	}
	applyTest(t, dsn, files)
	if _, err := admin.Exec(baselineFixture); err != nil {
		t.Fatal(dbError("insert baseline fixture", err))
	}
	// Publishing must stamp the immutable version and advance the catalog in
	// the same transaction; the database defers circular/publication checks.
	expectRejected(t, admin, "UPDATE judge.platform_problems SET status='PUBLISHED',current_version_id=latest_version_id,public_updated_at=clock_timestamp() WHERE id=1")
	expectRejected(t, admin, "UPDATE judge.problem_versions SET first_published_at=clock_timestamp() WHERE problem_id=1")
	if _, err := admin.Exec(`BEGIN;
UPDATE judge.problem_versions SET first_published_at=clock_timestamp() WHERE problem_id=1;
UPDATE judge.platform_problems SET status='PUBLISHED',current_version_id=latest_version_id,public_updated_at=clock_timestamp() WHERE id=1;
UPDATE judge.catalog_state SET catalog_version=catalog_version+1,updated_at=clock_timestamp();
COMMIT;`); err != nil {
		t.Fatal(dbError("publish qualified fixture", err))
	}
	expectRejected(t, admin, "UPDATE judge.catalog_state SET catalog_version=1")
	expectRejected(t, admin, taskAdmission)
	if _, err := admin.Exec("BEGIN;" + taskAdmission + callbackSnapshot + "COMMIT;"); err != nil {
		t.Fatal(dbError("accept task and first callback atomically", err))
	}
	for _, statement := range []string{
		"UPDATE judge.judge_tasks SET status='COMPLETED',revision=2,finished_at=now(),source_expires_at=now()+interval '24 hours'",
		"UPDATE judge.judge_tasks SET problem_version_id='00000000-0000-0000-0000-000000000012'",
		"UPDATE judge.judge_tasks SET transient_source_key=NULL",
		"UPDATE judge.judge_tasks SET revision=0",
		strings.Replace(taskAdmission, "000000000100", "000000000102", 1),                                                     // duplicate request and submission.
		strings.Replace(strings.Replace(taskAdmission, "000000000100", "000000000103", 1), "000000000101", "000000000104", 1), // duplicate submission, fresh request.
	} {
		expectRejected(t, admin, statement)
	}
	// Final result and case may be inserted before the terminal task update.
	// All deferred checks observe the same final transaction state.
	finish := `BEGIN;
UPDATE judge.judge_tasks SET status='DISPATCHING',revision=2,started_at=now(),lease_owner=gen_random_uuid(),lease_expires_at=now()+interval '180 seconds';` + callbackSnapshot + `
UPDATE judge.judge_tasks SET status='RUNNING',revision=3;` + callbackSnapshot + `
INSERT INTO judge.judge_results(judge_task_id,verdict,time_ms,memory_bytes,passed_test_count,total_test_count,judged_at,result_hash)
VALUES('00000000-0000-0000-0000-000000000100','AC',1,1024,1,1,now(),repeat('a',64));
INSERT INTO judge.judge_case_results(judge_task_id,test_case_id,ordinal,verdict,cpu_time_ms,wall_time_ms,memory_bytes)
VALUES('00000000-0000-0000-0000-000000000100','00000000-0000-0000-0000-000000000020',1,'AC',1,2,1024);
UPDATE judge.judge_tasks SET status='COMPLETED',revision=4,finished_at=now(),source_expires_at=now()+interval '24 hours',lease_owner=NULL,lease_expires_at=NULL;` + callbackSnapshot + `COMMIT;`
	if _, err := admin.Exec(finish); err != nil {
		t.Fatal(dbError("commit complete task/result/case/outbox", err))
	}
	for _, statement := range []string{
		"UPDATE judge.judge_tasks SET status='QUEUED',revision=5,finished_at=NULL,source_expires_at=NULL,started_at=NULL",
		"UPDATE judge.judge_results SET verdict='WA'",
		"DELETE FROM judge.judge_results",
		"UPDATE judge.judge_case_results SET verdict='WA'",
		"UPDATE judge.callback_outbox SET payload_hash=repeat('b',64)",
		"UPDATE judge.judge_tasks SET transient_source_key=NULL", // retention not elapsed.
		"UPDATE judge.package_artifacts SET validation_run_id=NULL",
		"INSERT INTO judge.problem_test_cases SELECT gen_random_uuid(),package_artifact_id,2,visibility,input_object_key,answer_object_key,input_sha256,answer_sha256,input_size_bytes,answer_size_bytes,validation_group,created_at FROM judge.problem_test_cases",
	} {
		expectRejected(t, admin, statement)
	}
	var revision, eventCount int
	if err := admin.QueryRow("SELECT revision,(SELECT count(*) FROM judge.callback_outbox WHERE judge_task_id=t.id) FROM judge.judge_tasks t").Scan(&revision, &eventCount); err != nil || revision != 4 || eventCount != 4 {
		t.Fatal("task revisions and immutable event history were not retained")
	}
	// Cleanup is a private mutation: after the retention window, it clears one
	// key while preserving the public DTO, revision and frozen callback bytes.
	if _, err := admin.Exec(`BEGIN;
INSERT INTO judge.judge_tasks SELECT (jsonb_populate_record(NULL::judge.judge_tasks,to_jsonb(t)||jsonb_build_object('id','00000000-0000-0000-0000-000000000110','request_id','00000000-0000-0000-0000-000000000111','submission_id',2,'created_at','2000-01-01T00:00:00Z','updated_at','2000-01-01T00:00:00Z','started_at','2000-01-01T00:00:00Z','finished_at','2000-01-01T00:00:00Z','source_expires_at','2000-01-02T00:00:00Z'))).* FROM judge.judge_tasks t;
INSERT INTO judge.judge_results SELECT (jsonb_populate_record(NULL::judge.judge_results,to_jsonb(r)||jsonb_build_object('judge_task_id','00000000-0000-0000-0000-000000000110','judged_at','2000-01-01T00:00:00Z'))).* FROM judge.judge_results r;
INSERT INTO judge.judge_case_results SELECT (jsonb_populate_record(NULL::judge.judge_case_results,to_jsonb(c)||jsonb_build_object('judge_task_id','00000000-0000-0000-0000-000000000110'))).* FROM judge.judge_case_results c;` + strings.ReplaceAll(callbackSnapshot, "000000000100", "000000000110") + "COMMIT;"); err != nil {
		t.Fatal(dbError("insert historic retention fixture", err))
	}
	readPublic := func() string {
		var state string
		if err := admin.QueryRow(`SELECT jsonb_build_object('task',to_jsonb(t)-'transient_source_key','callback',o.payload,'hash',o.payload_hash)::text
FROM judge.judge_tasks t JOIN judge.callback_outbox o ON o.judge_task_id=t.id AND o.revision=t.revision WHERE t.id='00000000-0000-0000-0000-000000000110'`).Scan(&state); err != nil {
			t.Fatal(dbError("read retained public/callback fixture", err))
		}
		return state
	}
	beforeCleanup := readPublic()
	if _, err := admin.Exec("UPDATE judge.judge_tasks SET transient_source_key=NULL WHERE id='00000000-0000-0000-0000-000000000110'"); err != nil {
		t.Fatal(dbError("clean expired private source registration", err))
	}
	if readPublic() != beforeCleanup {
		t.Fatal("private source cleanup changed public task or frozen callback")
	}
	expectRejected(t, admin, "UPDATE judge.judge_tasks SET transient_source_key=NULL WHERE id='00000000-0000-0000-0000-000000000110'")
	expectRejected(t, admin, "UPDATE judge.judge_tasks SET updated_at=clock_timestamp() WHERE id='00000000-0000-0000-0000-000000000110'")
}

func TestPostgresRecoveryReservationsAreBoundedAndFenced(t *testing.T) {
	dsn, _, admin := testDatabase(t)
	files, err := Load(migrations.Files)
	if err != nil {
		t.Fatal(err)
	}
	applyTest(t, dsn, files)
	if _, err := admin.Exec(baselineFixture + "BEGIN;" + taskAdmission + callbackSnapshot + "COMMIT;"); err != nil {
		t.Fatal(dbError("insert recovery fixture", err))
	}
	if _, err := admin.Exec(`BEGIN;UPDATE judge.judge_tasks SET status='DISPATCHING',revision=2,started_at='2000-01-01T00:00:00Z',lease_owner=gen_random_uuid(),lease_expires_at='2000-01-01T00:03:00Z';` + callbackSnapshot + "COMMIT;"); err != nil {
		t.Fatal(dbError("reserve initial execution", err))
	}
	for recovery := 1; recovery <= 3; recovery++ {
		var staleToken string
		if err := admin.QueryRow("SELECT lease_owner::text FROM judge.judge_tasks").Scan(&staleToken); err != nil {
			t.Fatal(dbError("read recovery fencing fixture", err))
		}
		expectRejected(t, admin, "UPDATE judge.judge_tasks SET status='QUEUED',revision=revision+1,started_at=NULL,lease_owner=NULL,lease_expires_at=NULL")
		reservation := fmt.Sprintf("BEGIN;UPDATE judge.judge_tasks SET status='DISPATCHING',revision=revision+1,lease_owner=gen_random_uuid(),attempt_count=%d,lease_expires_at='2000-01-01T00:03:00Z';", recovery)
		if _, err := admin.Exec(reservation + callbackSnapshot + "COMMIT;"); err != nil {
			t.Fatal(dbError("reserve fenced recovery", err))
		}
		result, err := admin.Exec("UPDATE judge.judge_tasks SET lease_expires_at=now()+interval '180 seconds' WHERE lease_owner=$1::uuid", staleToken)
		if err != nil {
			t.Fatal(dbError("exercise stale-token compare and set", err))
		}
		rows, err := result.RowsAffected()
		if err != nil || rows != 0 {
			t.Fatal("old lease owner changed recovered task")
		}
	}
	expectRejected(t, admin, "UPDATE judge.judge_tasks SET revision=revision+1,lease_owner=gen_random_uuid(),attempt_count=4")
	expectRejected(t, admin, "UPDATE judge.judge_tasks SET updated_at=clock_timestamp()")
	if _, err := admin.Exec(`BEGIN;
INSERT INTO judge.judge_results(judge_task_id,verdict,passed_test_count,total_test_count,judged_at,result_hash)
VALUES('00000000-0000-0000-0000-000000000100','IE',0,1,now(),repeat('a',64));
UPDATE judge.judge_tasks SET status='FAILED',revision=revision+1,error='{"code":"JUDGE_INTERRUPTED","message":"Fixture infrastructure failure","retryable":false}',finished_at=now(),source_expires_at=now()+interval '24 hours',lease_owner=NULL,lease_expires_at=NULL;` + callbackSnapshot + "COMMIT;"); err != nil {
		t.Fatal(dbError("finish exhausted infrastructure task atomically", err))
	}
	var count int
	var started time.Time
	if err := admin.QueryRow("SELECT attempt_count,started_at FROM judge.judge_tasks").Scan(&count, &started); err != nil || count != 3 || started.Year() != 2000 {
		t.Fatal("bounded recovery lost first start or recovery count")
	}
}

func TestPostgresSourceIdentityRegistrationRace(t *testing.T) {
	dsn, _, admin := testDatabase(t)
	files, err := Load(migrations.Files)
	if err != nil {
		t.Fatal(err)
	}
	applyTest(t, dsn, files)
	first, err := admin.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(dbError("begin source registration", err))
	}
	defer first.Rollback()
	statement := `INSERT INTO judge.package_source_identities(id,repository_url,source_revision,package_path,source_sha256)
VALUES(gen_random_uuid(),'https://github.com/oj-lab/problem-packages',repeat('a',40),'problems/race',repeat('%s',64))`
	if _, err := first.Exec(fmt.Sprintf(statement, "a")); err != nil {
		t.Fatal(dbError("register first source", err))
	}
	result := make(chan error, 1)
	go func() {
		_, err := admin.Exec(fmt.Sprintf(statement, "b"))
		result <- err
	}()
	select {
	case <-result:
		t.Fatal("concurrent conflicting source registration did not wait for the unique identity")
	case <-time.After(100 * time.Millisecond):
	}
	if err := first.Commit(); err != nil {
		t.Fatal(dbError("commit first source registration", err))
	}
	if err := <-result; err == nil {
		t.Fatal("conflicting original source bytes both committed")
	}
}

func TestPostgresValidationSelectionAndMemberRegistrationRace(t *testing.T) {
	dsn, _, admin := testDatabase(t)
	files, err := Load(migrations.Files)
	if err != nil {
		t.Fatal(err)
	}
	applyTest(t, dsn, files)
	if _, err := admin.Exec(baselineFixture); err != nil {
		t.Fatal(dbError("insert baseline fixture", err))
	}
	for _, resultExpression := range []string{
		"results-'validators'", "jsonb_set(results,'{validators,passed}','\"true\"')",
		"jsonb_set(results,'{validators,passed}','false')", "jsonb_set(results,'{validators,evidence}','[]')",
		"jsonb_set(results,'{validators,evidence,0,summary}','\" \"')",
	} {
		statement := `INSERT INTO judge.package_validation_runs SELECT (jsonb_populate_record(NULL::judge.package_validation_runs,
to_jsonb(r)||jsonb_build_object('id',gen_random_uuid(),'results',` + resultExpression + `))).* FROM judge.package_validation_runs r`
		expectRejected(t, admin, statement)
	}
	// Register an independent artifact-specific fixture run for new evidence.
	// The byte identity stays shared, but the run cannot be reparented/borrowed.
	var rawEvidence string
	if err := admin.QueryRow("SELECT jsonb_build_object('licenseEvidenceId','00000000-0000-0000-0000-000000000034','validationContext',validation_context)::text FROM judge.package_artifacts").Scan(&rawEvidence); err != nil {
		t.Fatal(dbError("read immutable evidence identity fixture", err))
	}
	evidenceHash, err := canonical.HashJSON([]byte(rawEvidence))
	if err != nil {
		t.Fatal("cannot canonicalize evidence identity fixture")
	}
	if _, err := admin.Exec(fmt.Sprintf(`BEGIN;
INSERT INTO judge.license_evidence SELECT (jsonb_populate_record(NULL::judge.license_evidence,to_jsonb(l)||jsonb_build_object('id','00000000-0000-0000-0000-000000000034','previous_evidence_id',l.id,'notice','Fixture reapproval evidence'))).* FROM judge.license_evidence l;
INSERT INTO judge.package_artifacts SELECT (jsonb_populate_record(NULL::judge.package_artifacts,to_jsonb(a)||jsonb_build_object('id','00000000-0000-0000-0000-000000000030','validation_run_id',NULL,'license_evidence_id','00000000-0000-0000-0000-000000000034','evidence_set_hash','%s'))).* FROM judge.package_artifacts a;
INSERT INTO judge.problem_test_cases SELECT (jsonb_populate_record(NULL::judge.problem_test_cases,to_jsonb(c)||jsonb_build_object('id','00000000-0000-0000-0000-000000000031','package_artifact_id','00000000-0000-0000-0000-000000000030'))).* FROM judge.problem_test_cases c;
INSERT INTO judge.reference_solutions SELECT (jsonb_populate_record(NULL::judge.reference_solutions,to_jsonb(r)||jsonb_build_object('id','00000000-0000-0000-0000-000000000032','package_artifact_id','00000000-0000-0000-0000-000000000030'))).* FROM judge.reference_solutions r;
INSERT INTO judge.package_validation_runs SELECT (jsonb_populate_record(NULL::judge.package_validation_runs,to_jsonb(r)||jsonb_build_object('id','00000000-0000-0000-0000-000000000033','package_artifact_id','00000000-0000-0000-0000-000000000030'))).* FROM judge.package_validation_runs r;
COMMIT;`, evidenceHash)); err != nil {
		t.Fatal(dbError("register independent evidence variant qualification", err))
	}
	expectRejected(t, admin, "UPDATE judge.package_artifacts SET validation_run_id='00000000-0000-0000-0000-000000000004' WHERE id='00000000-0000-0000-0000-000000000030'")
	selection, err := admin.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(dbError("begin validation selection", err))
	}
	defer selection.Rollback()
	if _, err := selection.Exec("UPDATE judge.package_artifacts SET validation_run_id='00000000-0000-0000-0000-000000000033' WHERE id='00000000-0000-0000-0000-000000000030'"); err != nil {
		t.Fatal(dbError("select qualifying run", err))
	}
	statements := []string{
		`INSERT INTO judge.problem_test_cases SELECT (jsonb_populate_record(NULL::judge.problem_test_cases,to_jsonb(c)||jsonb_build_object('id',gen_random_uuid(),'ordinal',2))).* FROM judge.problem_test_cases c WHERE package_artifact_id='00000000-0000-0000-0000-000000000030'`,
		`INSERT INTO judge.reference_solutions SELECT (jsonb_populate_record(NULL::judge.reference_solutions,to_jsonb(r)||jsonb_build_object('id',gen_random_uuid(),'upstream_path','submissions/accepted/new.cpp'))).* FROM judge.reference_solutions r WHERE package_artifact_id='00000000-0000-0000-0000-000000000030'`,
	}
	results := make(chan error, 2)
	for _, statement := range statements {
		go func(statement string) {
			worker, err := Open(context.Background(), dsn)
			if err == nil {
				defer worker.Close()
				_, err = worker.Exec(statement)
			}
			results <- err
		}(statement)
	}
	select {
	case <-results:
		t.Fatal("member registration did not serialize with qualification selection")
	case <-time.After(100 * time.Millisecond):
	}
	if err := selection.Commit(); err != nil {
		t.Fatal(dbError("commit selected qualification", err))
	}
	for range 2 {
		if err := <-results; err == nil {
			t.Fatal("member changed after concurrent qualification committed")
		}
	}
	expectRejected(t, admin, "UPDATE judge.package_artifacts SET validation_run_id=NULL WHERE id='00000000-0000-0000-0000-000000000030'")
}

func TestPostgresHistoryDeletionAndForwardCeilingFailClosed(t *testing.T) {
	dsn, _, admin := testDatabase(t)
	files, err := Load(fstest.MapFS{
		"000001_initial.up.sql": {Data: []byte("BEGIN;CREATE TABLE judge.history(id integer);COMMIT;")},
		"000002_expand.up.sql":  {Data: []byte("BEGIN;ALTER TABLE judge.history ADD COLUMN retained text;COMMIT;")},
	})
	if err != nil {
		t.Fatal(err)
	}
	db, err := Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(context.Background(), db, files, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec("INSERT INTO judge.history VALUES(1)"); err != nil {
		t.Fatal(dbError("insert previous-level retained fixture", err))
	}
	applyTest(t, dsn, files)
	var retainedID int
	if err := admin.QueryRow("SELECT id FROM judge.history").Scan(&retainedID); err != nil || retainedID != 1 {
		t.Fatal("forward expansion did not preserve previous-level records")
	}
	db, err = Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(context.Background(), db, files, 1); err == nil {
		t.Fatal("runner lowered a shared version")
	}
	if _, err := admin.Exec("DELETE FROM judge.migration_checksums WHERE version=1"); err != nil {
		t.Fatal(dbError("simulate missing shared checksum", err))
	}
	if _, err := Inspect(context.Background(), admin, files); err == nil {
		t.Fatal("missing shared migration history accepted")
	}
}

func expectRejected(t *testing.T, db *sql.DB, statement string) {
	t.Helper()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(dbError("begin invariant check", err))
	}
	defer tx.Rollback()
	_, err = tx.Exec(statement)
	if err == nil {
		err = tx.Commit()
	}
	if err == nil {
		t.Fatalf("invalid state committed: %s", statement)
	}
}

const taskAdmission = `INSERT INTO judge.judge_tasks(id,request_id,request_hash,submission_id,problem_id,problem_version_id,source_owner,source_sha256,transient_source_key,language_id,language_config_version,sandbox_version,worker_image_digest,execution_limits,status)
VALUES('00000000-0000-0000-0000-000000000100','00000000-0000-0000-0000-000000000101',repeat('a',64),1,1,'00000000-0000-0000-0000-000000000011','backend',repeat('a',64),'private/transient','cpp17','fixture-1','pinned-fixture','sha256:'||repeat('a',64),'{}','QUEUED');`

const callbackSnapshot = `WITH event AS(SELECT gen_random_uuid() id)
INSERT INTO judge.callback_outbox(event_id,judge_task_id,revision,event_type,request_id,payload,payload_hash,status,next_attempt_at)
SELECT e.id,t.id,t.revision,'JUDGE_TASK_UPDATED',t.request_id,
jsonb_build_object('eventId',e.id,'eventType','JUDGE_TASK_UPDATED','requestId',t.request_id,'aggregateId',t.id,'revision',t.revision,
'payload',jsonb_build_object('judgeTaskId',t.id,'submissionId',t.submission_id::text,'requestId',t.request_id,'revision',t.revision,'status',t.status)),repeat('a',64),'PENDING',now()
FROM judge.judge_tasks t CROSS JOIN event e WHERE t.id='00000000-0000-0000-0000-000000000100';`

// This raw SQL fixture exercises relational constraints. Placeholder archive,
// manifest and result hashes are not real package/runtime qualification claims;
// storage and canonical DTO/hash validation are separate owner-layer checks.
const baselineFixture = `BEGIN;
INSERT INTO judge.platform_problems(source,repository_url,package_path,status) VALUES
 ('OJ_LAB','https://github.com/oj-lab/problem-packages','problems/alpha','DRAFT'),
 ('OJ_LAB','https://github.com/oj-lab/problem-packages','problems/beta','DRAFT');
INSERT INTO judge.license_evidence(id,repository_url,source_revision,package_path,status,license_scope,spdx_id,notice,source_url,license_files,evidence,reviewed_by,reviewed_at)
 VALUES('00000000-0000-0000-0000-000000000001','https://github.com/oj-lab/problem-packages',repeat('a',40),'problems/alpha','VERIFIED','PACKAGE','MIT','fixture license','https://github.com/oj-lab/problem-packages/blob/fixture/LICENSE','[{"path":"LICENSE","sha256":"fixture","spdxId":"MIT"}]','{"adminReview":true}','admin:fixture',now());
INSERT INTO judge.package_source_identities(id,repository_url,source_revision,package_path,source_sha256)
 VALUES('00000000-0000-0000-0000-000000000002','https://github.com/oj-lab/problem-packages',repeat('a',40),'problems/alpha',repeat('a',64));
INSERT INTO judge.package_content_identities(id,source_identity_id,adapter_version,source_format,manifest_version,normalized_sha256,manifest_sha256,manifest)
 VALUES('00000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000002','ojlab-kattis-v0.2.1','oj-lab-v1','0.2.0',repeat('a',64),repeat('a',64),'{"testCount":1}');
INSERT INTO judge.package_artifacts(id,problem_id,content_identity_id,source,repository_url,source_revision,package_path,source_format,adapter_version,manifest_version,source_archive_key,source_sha256,normalized_archive_key,normalized_sha256,manifest,source_metadata,license_evidence_id,validation_run_id,validation_context,evidence_set_hash)
 VALUES('00000000-0000-0000-0000-000000000010',1,'00000000-0000-0000-0000-000000000003','OJ_LAB','https://github.com/oj-lab/problem-packages',repeat('a',40),'problems/alpha','oj-lab-v1','ojlab-kattis-v0.2.1','0.2.0','private/source',repeat('a',64),'private/normalized',repeat('a',64),'{"testCount":1}','{"upstream":true}','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000004',jsonb_build_object('problemtoolsVersion','v1.20260907','adapterVersion','ojlab-kattis-v0.2.1','toolchainVersion','gcc-fixture','imageDigest','sha256:'||repeat('a',64),'configSha256',repeat('a',64),'sourceSha256',repeat('a',64),'normalizedSha256',repeat('a',64)),repeat('a',64));
INSERT INTO judge.package_validation_runs(id,package_artifact_id,status,problemtools_version,adapter_version,toolchain_version,image_digest,config_sha256,source_sha256,normalized_sha256,results,errors,adaptations,started_at,finished_at)
 VALUES('00000000-0000-0000-0000-000000000004','00000000-0000-0000-0000-000000000010','PASSED','v1.20260907','ojlab-kattis-v0.2.1','gcc-fixture','sha256:'||repeat('a',64),repeat('a',64),repeat('a',64),repeat('a',64),
 (SELECT jsonb_object_agg(name,jsonb_build_object('passed',true,'evidence',jsonb_build_array(jsonb_build_object('check','FIXTURE_VALIDATION','subjectSha256',repeat('a',64),'logObjectKey',NULL,'summary','Fixture checkpoint passed')))) FROM unnest(ARRAY['structure','statement','testData','validators','referenceSolutions']) name),'[]','[]',now(),now());
INSERT INTO judge.problem_versions(id,problem_id,version_number,package_artifact_id,title,statement_format,statement_content,difficulty_scale,time_limit_ms,wall_limit_ms,memory_limit_bytes,output_limit_bytes,language_ids,judge_mode,checker_config,metadata_hash)
 VALUES('00000000-0000-0000-0000-000000000011',1,1,'00000000-0000-0000-0000-000000000010','Alpha','MARKDOWN','fixture statement','UNRATED',1000,2000,10000,10000,ARRAY['cpp17'],'BATCH_PASS_FAIL','{}',repeat('a',64));
INSERT INTO judge.problem_test_cases(id,package_artifact_id,ordinal,visibility,input_object_key,answer_object_key,input_sha256,answer_sha256,input_size_bytes,answer_size_bytes)
 VALUES('00000000-0000-0000-0000-000000000020','00000000-0000-0000-0000-000000000010',1,'SECRET','private/input','private/answer',repeat('a',64),repeat('a',64),1,1);
INSERT INTO judge.reference_solutions(id,package_artifact_id,role,language_id,source_object_key,source_sha256,upstream_path)
 VALUES('00000000-0000-0000-0000-000000000021','00000000-0000-0000-0000-000000000010','ACCEPTED','cpp17','private/reference',repeat('a',64),'submissions/accepted/main.cpp');
INSERT INTO judge.judge_language_configs(language_id,config_version,display_name,language_family,compiler_version,source_filename,compile_template,run_template,compile_limits,toolchain_digest,analysis_supported,is_active)
 VALUES('cpp17','fixture-1','C++17','C++','gcc-fixture','main.cpp','{}','{}','{}','sha256:'||repeat('a',64),false,false);
UPDATE judge.platform_problems SET latest_version_id='00000000-0000-0000-0000-000000000011' WHERE id=1;
COMMIT;`
