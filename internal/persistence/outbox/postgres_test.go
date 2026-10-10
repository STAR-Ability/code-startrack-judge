package outbox

import (
	"context"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/callbacks"
	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/persistence/migrate"
	"github.com/STAR-Ability/code-startrack-judge/migrations"
	"github.com/jackc/pgx/v5"
)

//go:embed testdata/baseline.sql
var fixtureFiles embed.FS

type databaseFixture struct {
	admin, worker, operator            *sql.DB
	repository, operatorRepository     *Repository
	submission                         int64
	adminDSN, operatorRole, workerRole string
}

func database(t *testing.T) *databaseFixture {
	t.Helper()
	dsn := os.Getenv("JUDGE_TEST_ADMIN_DATABASE_URL")
	if path := os.Getenv("JUDGE_TEST_ADMIN_DSN_FILE"); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("cannot read private test admin DSN file")
		}
		dsn = strings.TrimSpace(string(raw))
	}
	if dsn == "" {
		t.Skip("PostgreSQL integration requires JUDGE_TEST_ADMIN_DSN_FILE or JUDGE_TEST_ADMIN_DATABASE_URL")
	}
	ctx := context.Background()
	admin, err := migrate.Open(ctx, dsn)
	if err != nil {
		t.Fatal("cannot connect test administrator")
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		t.Fatal("cannot generate test identity")
	}
	suffix := hex.EncodeToString(random)
	name, workerRole, operatorRole, migrationRole := "judge_outbox_"+suffix, "judge_send_"+suffix, "judge_replay_"+suffix, "judge_migrate_"+suffix
	password := suffix + suffix
	for _, role := range []string{workerRole, operatorRole, migrationRole} {
		if _, err := admin.ExecContext(ctx, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"'"); err != nil {
			t.Fatal("cannot create isolated role")
		}
	}
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal("cannot create isolated database")
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("invalid private admin DSN")
	}
	u.Path = "/" + name
	isolated, err := migrate.Open(ctx, u.String())
	if err != nil {
		t.Fatal("cannot connect isolated database")
	}
	f := &databaseFixture{admin: isolated, adminDSN: u.String(), operatorRole: operatorRole, workerRole: workerRole}
	t.Cleanup(func() {
		if f.worker != nil {
			_ = f.worker.Close()
		}
		if f.operator != nil {
			_ = f.operator.Close()
		}
		_ = isolated.Close()
		_, _ = admin.ExecContext(ctx, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
		for _, role := range []string{workerRole, operatorRole, migrationRole} {
			_, _ = admin.ExecContext(ctx, "DROP ROLE "+pgx.Identifier{role}.Sanitize())
		}
		_ = admin.Close()
	})
	for _, statement := range []string{"CREATE SCHEMA judge AUTHORIZATION " + pgx.Identifier{migrationRole}.Sanitize(), "REVOKE ALL ON DATABASE " + pgx.Identifier{name}.Sanitize() + " FROM PUBLIC", "REVOKE ALL ON SCHEMA public FROM PUBLIC", "GRANT CONNECT ON DATABASE " + pgx.Identifier{name}.Sanitize() + " TO " + pgx.Identifier{migrationRole}.Sanitize()} {
		if _, err := isolated.ExecContext(ctx, statement); err != nil {
			t.Fatal("cannot establish isolated schema boundary")
		}
	}
	files, err := migrate.Load(migrations.Files)
	if err != nil {
		t.Fatal(err)
	}
	migrationURL := *u
	migrationURL.User = url.UserPassword(migrationRole, password)
	migrationDB, err := migrate.Open(ctx, migrationURL.String())
	if err != nil {
		t.Fatal("cannot connect scoped migration owner")
	}
	if _, err := migrate.Apply(ctx, migrationDB, files, 0); err != nil {
		_ = migrationDB.Close()
		t.Fatal(err)
	}
	_ = migrationDB.Close()
	fixture, err := fixtureFiles.ReadFile("testdata/baseline.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := isolated.ExecContext(ctx, string(fixture)); err != nil {
		t.Fatal("cannot load relational fixture")
	}
	for _, role := range []string{workerRole, operatorRole} {
		q := pgx.Identifier{role}.Sanitize()
		for _, statement := range []string{
			"GRANT CONNECT ON DATABASE " + pgx.Identifier{name}.Sanitize() + " TO " + q,
			"GRANT USAGE ON SCHEMA judge TO " + q,
			"GRANT SELECT ON judge.callback_outbox,judge.callback_redelivery_requests,judge.callback_redelivery_outcomes TO " + q,
			"GRANT UPDATE(status,attempt_count,next_attempt_at,lease_owner,lease_expires_at,last_error_code,updated_at,delivered_at) ON judge.callback_outbox TO " + q,
			"GRANT INSERT ON judge.callback_redelivery_outcomes TO " + q,
		} {
			if _, err := isolated.ExecContext(ctx, statement); err != nil {
				t.Fatal("cannot grant scoped callback privileges")
			}
		}
	}
	if _, err := isolated.ExecContext(ctx, "GRANT INSERT ON judge.callback_redelivery_requests TO "+pgx.Identifier{operatorRole}.Sanitize()); err != nil {
		t.Fatal("cannot grant trusted replay privilege")
	}
	u.User = url.UserPassword(workerRole, password)
	f.worker, err = migrate.Open(ctx, u.String())
	if err != nil {
		t.Fatal("cannot connect isolated worker")
	}
	u.User = url.UserPassword(operatorRole, password)
	f.operator, err = migrate.Open(ctx, u.String())
	if err != nil {
		t.Fatal("cannot connect isolated operator")
	}
	f.repository, _ = New(f.worker)
	f.operatorRepository, _ = New(f.operator)
	return f
}

func (f *databaseFixture) event(t *testing.T, age time.Duration) contract.UUID {
	t.Helper()
	ctx := context.Background()
	taskID, _ := contract.NewUUID()
	requestID, _ := contract.NewUUID()
	eventID, _ := contract.NewUUID()
	// The database owns delivery deadlines. A host/VM clock skew must not make
	// a newly seeded due event appear to originate in the database's future.
	var databaseNow time.Time
	if err := f.admin.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&databaseNow); err != nil {
		t.Fatal("cannot read fixture database clock")
	}
	created := databaseNow.UTC().Add(-age).Truncate(time.Microsecond)
	f.submission++
	task := contract.JudgeTask{TaskBase: contract.TaskBase{RequestID: requestID, Revision: 1, CreatedAt: contract.UTC(created), UpdatedAt: contract.UTC(created)}, JudgeTaskID: taskID, SubmissionID: contract.ID(strconv.FormatInt(f.submission, 10)), Status: contract.JudgeQueued}
	event := contract.CallbackEvent[contract.JudgeTask]{EventID: eventID, EventType: "JUDGE_TASK_UPDATED", OccurredAt: contract.UTC(created), RequestID: requestID, AggregateID: taskID, Revision: 1, Payload: task}
	raw, _ := json.Marshal(event)
	body, err := canonical.Canonicalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.admin.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal("cannot begin admission fixture")
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO judge.judge_tasks(id,request_id,request_hash,submission_id,problem_id,problem_version_id,source_owner,source_sha256,transient_source_key,language_id,language_config_version,sandbox_version,worker_image_digest,execution_limits,status,created_at,updated_at)
VALUES($1,$2,repeat('a',64),$3,1,'00000000-0000-0000-0000-000000000011','backend',repeat('a',64),'private/transient','cpp17','fixture-1','pinned-fixture','sha256:'||repeat('a',64),'{}','QUEUED',$4,$4)`, string(taskID), string(requestID), f.submission, created)
	if err != nil {
		t.Fatal("cannot insert task fixture")
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO judge.callback_outbox(event_id,judge_task_id,revision,event_type,request_id,payload,payload_hash,status,next_attempt_at,created_at,updated_at)
VALUES($1,$2,1,'JUDGE_TASK_UPDATED',$3,$4,$5,'PENDING',$6,$6,$6)`, string(eventID), string(taskID), string(requestID), string(body), canonical.HashBytes(body), created)
	if err != nil {
		t.Fatal("cannot insert callback fixture")
	}
	if tx.Commit() != nil {
		t.Fatal("cannot commit atomic task/event fixture")
	}
	return eventID
}

func assertStatus(t *testing.T, f *databaseFixture, event contract.UUID, want string) {
	t.Helper()
	var status string
	if f.admin.QueryRow("SELECT status FROM judge.callback_outbox WHERE event_id=$1", string(event)).Scan(&status) != nil || status != want {
		t.Fatalf("status=%s, want=%s", status, want)
	}
}

func TestPostgresClaimsFencesRestartAndNoTaskMutation(t *testing.T) {
	f := database(t)
	ctx := context.Background()
	event := f.event(t, 0)
	var before string
	if f.admin.QueryRow("SELECT jsonb_agg(to_jsonb(t))::text FROM judge.judge_tasks t").Scan(&before) != nil {
		t.Fatal("cannot freeze task facts")
	}
	var wg sync.WaitGroup
	claims := make(chan *callbacks.Delivery, 12)
	failures := make(chan error, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, err := f.repository.Claim(ctx)
			if err != nil {
				failures <- err
			}
			if d != nil {
				claims <- d
			}
		}()
	}
	wg.Wait()
	close(claims)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	var old *callbacks.Delivery
	count := 0
	for d := range claims {
		old = d
		count++
	}
	if count != 1 {
		t.Fatalf("claims=%d", count)
	}
	if old.EventID != event || old.AttemptCount != 1 || canonical.HashBytes(old.CanonicalJSON) != old.PayloadHash {
		t.Fatal("claim changed event identity")
	}
	if _, err := f.admin.Exec("UPDATE judge.callback_outbox SET lease_expires_at=statement_timestamp()-interval '1 second' WHERE event_id=$1", string(event)); err != nil {
		t.Fatal("cannot expire fixture lease")
	}
	if err := f.repository.Complete(ctx, old, callbacks.Outcome{Accepted: true}); !errors.Is(err, callbacks.ErrLeaseLost) {
		t.Fatal("expired token finalized event before replacement")
	}
	restarted, _ := New(f.worker)
	fresh, err := restarted.Claim(ctx)
	if err != nil || fresh == nil {
		t.Fatal("restart did not reclaim lease")
	}
	if fresh.LeaseToken == old.LeaseToken || fresh.AttemptCount != 2 || string(fresh.CanonicalJSON) != string(old.CanonicalJSON) || fresh.PayloadHash != old.PayloadHash {
		t.Fatal("restart changed snapshot or reused fence")
	}
	if err := f.repository.Complete(ctx, old, callbacks.Outcome{Accepted: true}); !errors.Is(err, callbacks.ErrLeaseLost) {
		t.Fatal("stale dispatcher finalized replacement")
	}
	if err := restarted.Complete(ctx, fresh, callbacks.Outcome{Accepted: true, Duplicate: true}); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, f, event, "DELIVERED")
	if err := restarted.Complete(ctx, fresh, callbacks.Outcome{Accepted: true}); !errors.Is(err, callbacks.ErrLeaseLost) {
		t.Fatal("delivered event changed")
	}
	var after string
	if f.admin.QueryRow("SELECT jsonb_agg(to_jsonb(t))::text FROM judge.judge_tasks t").Scan(&after) != nil || after != before {
		t.Fatal("delivery mutated judge facts")
	}
}

func TestPostgresFailuresBackoffAndOriginalDeadline(t *testing.T) {
	f := database(t)
	ctx := context.Background()
	event := f.event(t, 0)
	for i, code := range []callbacks.Code{callbacks.UnknownTask, callbacks.Conflict, callbacks.Unauthorized, callbacks.Unavailable, callbacks.InvalidACK, callbacks.Rejected, callbacks.InvalidArgument} {
		d, err := f.repository.Claim(ctx)
		if err != nil || d == nil {
			t.Fatal("due event not claimed")
		}
		if err := f.repository.Complete(ctx, d, callbacks.Outcome{ErrorCode: code}); err != nil {
			t.Fatal(err)
		}
		var delay float64
		var stored string
		if f.admin.QueryRow("SELECT extract(epoch FROM next_attempt_at-updated_at),last_error_code FROM judge.callback_outbox WHERE event_id=$1", string(event)).Scan(&delay, &stored) != nil || delay < callbacks.Backoff(i+1).Seconds()-0.01 || delay > callbacks.Backoff(i+1).Seconds()+0.01 || stored != string(code) {
			t.Fatalf("attempt%d delay=%f code=%s", i+1, delay, stored)
		}
		assertStatus(t, f, event, "PENDING")
		if got, err := f.repository.Claim(ctx); err != nil || got != nil {
			t.Fatal("retry before next_attempt_at")
		}
		if _, err := f.admin.Exec("UPDATE judge.callback_outbox SET next_attempt_at=statement_timestamp() WHERE event_id=$1", string(event)); err != nil {
			t.Fatal("cannot advance fixture due time")
		}
	}
	// A reservation begins within the original window and a failed response
	// arrives after it. The deadline is not extended by that later response.
	if _, err := f.admin.Exec("UPDATE judge.callback_outbox SET status='DEAD_LETTER' WHERE event_id=$1", string(event)); err != nil {
		t.Fatal("cannot park earlier fixture")
	}
	near := f.event(t, 24*time.Hour-300*time.Millisecond)
	d, err := f.repository.Claim(ctx)
	if err != nil || d == nil || d.EventID != near {
		t.Fatal("near-deadline reservation missing")
	}
	time.Sleep(350 * time.Millisecond)
	if f.repository.Complete(ctx, d, callbacks.Outcome{ErrorCode: callbacks.UnknownTask}) != nil {
		t.Fatal("failed deadline response not retained")
	}
	assertStatus(t, f, near, "DEAD_LETTER")
	expired := f.event(t, 25*time.Hour)
	if d, err := f.repository.Claim(ctx); err != nil || d != nil {
		t.Fatal("expired original window sent")
	}
	assertStatus(t, f, expired, "DEAD_LETTER")
	rows, err := f.repository.ListDeadLetters(ctx, 100, nil)
	if err != nil || len(rows) != 3 {
		t.Fatal("dead letters not visible")
	}
	for _, row := range rows {
		if row.EventID == expired && row.AttemptCount != 0 {
			t.Fatal("sweep fabricated delivery attempt")
		}
	}
}

func TestPostgresCompletionCannotCrossExpiryWaitingForRowLock(t *testing.T) {
	f := database(t)
	ctx := context.Background()
	event := f.event(t, 0)
	d, err := f.repository.Claim(ctx)
	if err != nil || d == nil {
		t.Fatal("cannot reserve event")
	}
	if _, err := f.admin.Exec("UPDATE judge.callback_outbox SET lease_expires_at=clock_timestamp()+interval '400 milliseconds' WHERE event_id=$1", string(event)); err != nil {
		t.Fatal("cannot shorten test lease")
	}
	lock, err := f.admin.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal("cannot begin holding transaction")
	}
	defer lock.Rollback()
	if _, err := lock.Exec("SELECT event_id FROM judge.callback_outbox WHERE event_id=$1 FOR UPDATE", string(event)); err != nil {
		t.Fatal("cannot hold outbox row")
	}
	finished := make(chan error, 1)
	go func() { finished <- f.repository.Complete(ctx, d, callbacks.Outcome{Accepted: true}) }()
	// Observe an actual worker-side lock wait before expiring/releasing the row;
	// a merely delayed goroutine is not evidence for this fencing invariant.
	blocked := false
	for end := time.Now().Add(time.Second); time.Now().Before(end); {
		if f.admin.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=$1 AND wait_event_type='Lock')`, f.workerRole).Scan(&blocked) != nil {
			t.Fatal("cannot inspect bounded lock wait")
		}
		if blocked {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !blocked {
		t.Fatal("completion never blocked on held row")
	}
	time.Sleep(450 * time.Millisecond)
	if lock.Commit() != nil {
		t.Fatal("cannot release held row")
	}
	if err := <-finished; !errors.Is(err, callbacks.ErrLeaseLost) {
		t.Fatal("completion used time from before row-lock wait")
	}
	assertStatus(t, f, event, "SENDING")
	if d2, err := f.repository.Claim(ctx); err != nil || d2 == nil || d2.LeaseToken == d.LeaseToken {
		t.Fatal("expired reservation was not recoverable")
	}
}

func TestPostgresManualReplayAuditAndPrivileges(t *testing.T) {
	f := database(t)
	ctx := context.Background()
	event := f.event(t, 25*time.Hour)
	if _, err := f.repository.Claim(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.repository.ClaimReplay(ctx, event, "operator:invalid", MappingReconciled); !errors.Is(err, callbacks.ErrInvalid) {
		t.Fatal("unbounded operator accepted")
	}
	if _, _, err := f.repository.ClaimReplay(ctx, event, "alice", MappingReconciled); !errors.Is(err, callbacks.ErrPersistence) {
		t.Fatal("runtime authorized manual replay")
	}
	assertStatus(t, f, event, "DEAD_LETTER")
	d, replay, err := f.operatorRepository.ClaimReplay(ctx, event, "alice@example.org", MappingReconciled)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.operatorRepository.ClaimReplay(ctx, event, "bob", MappingReconciled); !errors.Is(err, callbacks.ErrInvalid) {
		t.Fatal("concurrent replay reused event")
	}
	if err := f.operatorRepository.Complete(ctx, d, callbacks.Outcome{ErrorCode: callbacks.Conflict}); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, f, event, "DEAD_LETTER")
	var status string
	if f.admin.QueryRow("SELECT status FROM judge.callback_redelivery_outcomes WHERE replay_id=$1", string(replay)).Scan(&status) != nil || status != "FAILED" {
		t.Fatal("failed replay evidence missing")
	}
	interrupted, replay2, err := f.operatorRepository.ClaimReplay(ctx, event, "alice", AuthRestored)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec("UPDATE judge.callback_outbox SET lease_expires_at=statement_timestamp()-interval '1 second' WHERE event_id=$1", string(event)); err != nil {
		t.Fatal("cannot expire replay lease")
	}
	if _, err := f.repository.Claim(ctx); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, f, event, "DEAD_LETTER")
	if f.admin.QueryRow("SELECT status FROM judge.callback_redelivery_outcomes WHERE replay_id=$1", string(replay2)).Scan(&status) != nil || status != "INTERRUPTED" {
		t.Fatal("crashed replay evidence missing")
	}
	if err := f.operatorRepository.Complete(ctx, interrupted, callbacks.Outcome{Accepted: true}); !errors.Is(err, callbacks.ErrLeaseLost) {
		t.Fatal("expired replay finalized")
	}
	final, replay3, err := f.operatorRepository.ClaimReplay(ctx, event, "alice", ConflictResolved)
	if err != nil {
		t.Fatal(err)
	}
	if final.PayloadHash != d.PayloadHash || string(final.CanonicalJSON) != string(d.CanonicalJSON) || final.EventID != d.EventID {
		t.Fatal("manual replay changed original bytes")
	}
	if err := f.operatorRepository.Complete(ctx, final, callbacks.Outcome{Accepted: true, Duplicate: true}); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, f, event, "DELIVERED")
	if f.admin.QueryRow("SELECT status FROM judge.callback_redelivery_outcomes WHERE replay_id=$1", string(replay3)).Scan(&status) != nil || status != "DELIVERED" {
		t.Fatal("successful replay audit missing")
	}
	for _, statement := range []string{
		"UPDATE judge.judge_tasks SET revision=revision+1", "UPDATE judge.callback_outbox SET payload_hash=repeat('b',64)",
		"UPDATE judge.callback_redelivery_requests SET operator_ref='changed'", "DELETE FROM judge.callback_redelivery_outcomes",
		"UPDATE judge.migration_checksums SET sha256=repeat('b',64)", "CREATE TABLE judge.forbidden(id integer)", "CREATE TEMP TABLE forbidden(id integer)",
	} {
		if _, err := f.operator.Exec(statement); err == nil {
			t.Fatalf("operator privilege accepted %s", statement)
		}
	}
	for _, statement := range []string{"UPDATE judge.callback_redelivery_requests SET operator_ref='changed'", "DELETE FROM judge.callback_redelivery_outcomes"} {
		if _, err := f.admin.Exec(statement); err == nil {
			t.Fatal("audit history mutable even as owner")
		}
	}
}

func TestPostgresOperatorProvisioningScript(t *testing.T) {
	// Hosted Linux CI may use its installed psql. Local Mac qualification can
	// explicitly select the already pinned PostgreSQL container, without any
	// rendered Compose settings or credentials in command-line arguments.
	psqlPath, psqlErr := exec.LookPath("psql")
	container := os.Getenv("JUDGE_TEST_PSQL_DOCKER_CONTAINER")
	if psqlErr != nil && container == "" {
		t.Skip("operator script qualification requires psql or explicit JUDGE_TEST_PSQL_DOCKER_CONTAINER")
	}
	f := database(t)
	script, err := os.ReadFile("../../../scripts/grant-outbox-operator.sql")
	if err != nil {
		t.Fatal("cannot read shipped operator script")
	}
	script = []byte(strings.ReplaceAll(string(script), "judge_outbox_operator", f.operatorRole))
	u, err := url.Parse(f.adminDSN)
	if err != nil {
		t.Fatal("invalid test administrator URL")
	}
	password, _ := u.User.Password()
	canary := "outbox-script-canary-password-67c4d18d5d7fa0b9"
	run := func(body []byte, expectSuccess bool) {
		t.Helper()
		var cmd *exec.Cmd
		if container != "" {
			args := []string{}
			if dockerContext := os.Getenv("JUDGE_TEST_PSQL_DOCKER_CONTEXT"); dockerContext != "" {
				args = append(args, "--context", dockerContext)
			}
			args = append(args, "exec", "-i", "--env", "PGPASSWORD", "--env", "JUDGE_OUTBOX_OPERATOR_PASSWORD", container, "psql", "--no-psqlrc", "--quiet", "--username", u.User.Username(), "--dbname", strings.TrimPrefix(u.Path, "/"))
			cmd = exec.Command("docker", args...)
		} else {
			cmd = exec.Command(psqlPath, "--no-psqlrc", "--quiet")
		}
		cmd.Env = append(os.Environ(), "PGPASSWORD="+password, "JUDGE_OUTBOX_OPERATOR_PASSWORD="+canary, "PGHOST="+u.Hostname(), "PGPORT="+u.Port(), "PGDATABASE="+strings.TrimPrefix(u.Path, "/"), "PGUSER="+u.User.Username())
		// The container's private server uses its local socket, not the host's
		// published development port. PGHOST/PGPORT are omitted from docker exec.
		cmd.Stdin = strings.NewReader(string(body))
		output, err := cmd.CombinedOutput()
		if strings.Contains(string(output), canary) || strings.Contains(string(output), password) {
			t.Fatal("operator script printed a credential")
		}
		if (err == nil) != expectSuccess {
			category := "unknown"
			for _, candidate := range []string{"syntax error", "permission denied", "unsafe attributes", "Unsafe PUBLIC", "authentication failed", "Connection refused", "No such file", "does not exist", "unrecognized configuration", "cannot be executed"} {
				if strings.Contains(string(output), candidate) {
					category = candidate
					break
				}
			}
			t.Fatalf("operator script success/rejection mismatch: category=%s successExpected=%v", category, expectSuccess)
		}
	}
	run(script, true)
	run(script, true)
	role := pgx.Identifier{f.operatorRole}.Sanitize()
	worker := pgx.Identifier{f.workerRole}.Sanitize()
	for _, tc := range []struct{ introduce, restore string }{
		{"ALTER ROLE " + role + " INHERIT", "ALTER ROLE " + role + " NOINHERIT"},
		{"GRANT " + worker + " TO " + role, "REVOKE " + worker + " FROM " + role},
		{"GRANT SELECT ON judge.judge_tasks TO " + role, "REVOKE SELECT ON judge.judge_tasks FROM " + role},
		{"GRANT UPDATE(payload) ON judge.callback_outbox TO " + role, "REVOKE UPDATE(payload) ON judge.callback_outbox FROM " + role},
		{"GRANT INSERT ON judge.migration_checksums TO " + role, "REVOKE INSERT ON judge.migration_checksums FROM " + role},
	} {
		if _, err := f.admin.Exec(tc.introduce); err != nil {
			t.Fatal("cannot introduce unsafe fixture privilege")
		}
		run(script, false)
		if _, err := f.admin.Exec(tc.restore); err != nil {
			t.Fatal("cannot restore scoped fixture privilege")
		}
	}
	run(script, true)
}
