package tasks

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/admission"
	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
	"github.com/STAR-Ability/code-startrack-judge/internal/storage"
	taskdomain "github.com/STAR-Ability/code-startrack-judge/internal/tasks"
	"github.com/STAR-Ability/code-startrack-judge/internal/testutil/judgetask"
	"github.com/STAR-Ability/code-startrack-judge/internal/testutil/postgres"
)

type fixture struct {
	database   postgres.Database
	repository *Repository
	registry   *storage.Registry
}

func prepare(t *testing.T, count int) fixture {
	t.Helper()
	db := postgres.New(t)
	judgetask.Seed(t, db.Admin, count)
	root := t.TempDir()
	if os.Chmod(root, 0700) != nil {
		t.Fatal("cannot prepare private test store")
	}
	store, err := storage.New(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	registry, err := storage.NewRegistry(db.Runtime, store)
	if err != nil {
		t.Fatal(err)
	}
	repo, err := New(db.Runtime, registry)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{db, repo, registry}
}
func (f fixture) input(t *testing.T, submission string) admission.CreateInput {
	t.Helper()
	ctx := context.Background()
	request, _ := contract.NewUUID()
	task, _ := contract.NewUUID()
	source := "int main() { return 0; }\n"
	sourceHash, err := canonical.HashSource(source)
	if err != nil {
		t.Fatal(err)
	}
	version := contract.UUID("00000000-0000-0000-0000-000000000011")
	body := contract.JudgeTaskRequest{RequestID: request, SubmissionID: contract.ID(submission), ProblemRef: contract.ProblemRef{Source: contract.SourcePlatform, Platform: contract.PlatformStartrack, ProblemID: "1", ProblemVersionID: &version}, LanguageID: "cpp17", SourceCode: source, SourceSHA256: sourceHash}
	raw, _ := json.Marshal(body)
	hash, err := canonical.RequestHash("JUDGE", nil, raw)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := f.registry.Stage(ctx, task, []byte(source), body.SourceSHA256)
	if err != nil {
		t.Fatal(err)
	}
	return admission.CreateInput{Request: body, RequestHash: hash, Source: stage, Runtime: judgetask.Identity()}
}
func (f fixture) accept(t *testing.T, submission string) contract.JudgeTask {
	t.Helper()
	a, created, err := f.repository.Create(context.Background(), f.input(t, submission))
	if err != nil || !created {
		t.Fatalf("admission failed: %v", err)
	}
	return a.Task
}
func (f fixture) claim(t *testing.T) *taskdomain.Lease {
	t.Helper()
	lease, err := f.repository.Claim(context.Background())
	if err != nil || lease == nil {
		t.Fatalf("claim failed: %v", err)
	}
	return lease
}
func mustExec(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatal("synthetic fixture transaction failed")
	}
}
func countRows(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var count int
	if db.QueryRow(query, args...).Scan(&count) != nil {
		t.Fatal("cannot inspect isolated facts")
	}
	return count
}
func checkEvents(t *testing.T, f fixture, id contract.UUID, want int) {
	t.Helper()
	rows, err := f.database.Runtime.Query(`SELECT revision,payload::text,payload_hash FROM judge.callback_outbox WHERE judge_task_id=$1 ORDER BY revision`, string(id))
	if err != nil {
		t.Fatal("cannot inspect callback facts")
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		n++
		var revision int
		var raw, hash string
		if rows.Scan(&revision, &raw, &hash) != nil {
			t.Fatal("cannot decode callback facts")
		}
		var event contract.CallbackEvent[contract.JudgeTask]
		if json.Unmarshal([]byte(raw), &event) != nil || event.Validate() != nil || revision != n {
			t.Fatal("incorrect complete callback snapshot")
		}
		got, err := canonical.HashJSON([]byte(raw))
		if err != nil || got != hash {
			t.Fatal("callback bytes/hash drifted")
		}
	}
	if rows.Err() != nil || n != want {
		t.Fatalf("callback facts=%d want=%d", n, want)
	}
}
func outcome(l *taskdomain.Lease, verdicts ...contract.JudgeVerdict) judgeruntime.Outcome {
	out := judgeruntime.Outcome{Result: contract.JudgeResult{Verdict: contract.VerdictAC, PassedTestCount: 999, TotalTestCount: 999}}
	for i, verdict := range verdicts {
		out.Cases = append(out.Cases, judgeruntime.CaseResult{TestCaseID: l.Cases[i].TestCaseID, Ordinal: i + 1, Verdict: verdict, CPUTimeNS: uint64(i+1)*1000000 + 1, WallTimeNS: uint64(i+1) * 2000000, MemoryBytes: uint64((i + 1) * 100)})
	}
	return out
}

func TestPostgresAdmissionRaceReplayAndSourcePin(t *testing.T) {
	f := prepare(t, 2)
	in := f.input(t, "100")
	var group sync.WaitGroup
	results := make(chan bool, 12)
	failures := make(chan error, 12)
	for range 12 {
		group.Add(1)
		go func() {
			defer group.Done()
			a, created, err := f.repository.Create(context.Background(), in)
			if err == nil && a.Task.JudgeTaskID != in.Source.TaskID {
				err = taskdomain.ErrInvalid
			}
			results <- created
			failures <- err
		}()
	}
	group.Wait()
	close(results)
	close(failures)
	created := 0
	for value := range results {
		if value {
			created++
		}
	}
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	if created != 1 {
		t.Fatalf("concurrent admissions created=%d", created)
	}
	if countRows(t, f.database.Runtime, `SELECT count(*) FROM judge.private_object_references WHERE owner_type='TASK' AND owner_id=$1`, string(in.Source.TaskID)) != 1 || countRows(t, f.database.Runtime, `SELECT count(*) FROM judge.private_object_stages WHERE id=$1`, string(in.Source.RegistrationID)) != 0 {
		t.Fatal("source pin was not consumed with task")
	}
	checkEvents(t, f, in.Source.TaskID, 1)
	mustExec(t, f.database.Admin, `BEGIN;UPDATE judge.platform_problems SET status='WITHDRAWN',withdrawn_at=now(),withdrawal_reason='fixture',public_updated_at=clock_timestamp() WHERE id=1;UPDATE judge.catalog_state SET catalog_version=catalog_version+1;COMMIT`)
	in.Runtime = admission.RuntimeIdentity{}
	a, createdAgain, err := f.repository.Create(context.Background(), in)
	if err != nil || createdAgain || a.Task.JudgeTaskID != in.Source.TaskID {
		t.Fatal("accepted replay did not bypass changed eligibility")
	}
	rejected := f.input(t, "101")
	if _, _, err := f.repository.Create(context.Background(), rejected); err == nil {
		t.Fatal("withdrew problem accepted a new task")
	}
	if countRows(t, f.database.Runtime, `SELECT count(*) FROM judge.judge_tasks WHERE request_id=$1`, string(rejected.Request.RequestID)) != 0 {
		t.Fatal("deterministic rejection reserved identity")
	}
	if err := f.registry.Abandon(context.Background(), in.Source); err != nil {
		t.Fatal(err)
	}
	if countRows(t, f.database.Runtime, `SELECT count(*) FROM judge.private_object_references WHERE owner_id=$1`, string(in.Source.TaskID)) != 1 {
		t.Fatal("replay abandonment unpinned accepted source")
	}
	duplicate := f.input(t, "100")
	if _, _, err := f.repository.Create(context.Background(), duplicate); err == nil {
		t.Fatal("second request reused submission")
	}
}

func TestPostgresOrderedTerminalTransactionAndHeartbeat(t *testing.T) {
	f := prepare(t, 3)
	task := f.accept(t, "100")
	lease := f.claim(t)
	if lease.AttemptCount != 0 || lease.Task.Status != contract.JudgeDispatching || lease.Task.Revision != 2 {
		t.Fatal("initial reservation is incorrect")
	}
	if f.repository.Heartbeat(context.Background(), lease) != nil {
		t.Fatal("heartbeat failed")
	}
	after, _, err := f.repository.Get(context.Background(), task.JudgeTaskID)
	if err != nil || after.UpdatedAt != lease.Task.UpdatedAt || after.Revision != 2 {
		t.Fatal("heartbeat changed public state")
	}
	checkEvents(t, f, task.JudgeTaskID, 2)
	if f.repository.Running(context.Background(), lease) != nil {
		t.Fatal("ack failed")
	}
	checkEvents(t, f, task.JudgeTaskID, 3)
	wrong := outcome(lease, contract.VerdictAC)
	wrong.Cases[0].TestCaseID = lease.Cases[1].TestCaseID
	if _, err = f.repository.Complete(context.Background(), lease, wrong); !errors.Is(err, taskdomain.ErrInvalid) {
		t.Fatal("invalid case did not rollback")
	}
	after, _, _ = f.repository.Get(context.Background(), task.JudgeTaskID)
	if after.Status != contract.JudgeRunning || after.Revision != 3 {
		t.Fatal("invalid finalization changed task")
	}
	final, err := f.repository.Complete(context.Background(), lease, outcome(lease, contract.VerdictAC, contract.VerdictTLE))
	if err != nil {
		t.Fatal(err)
	}
	if final.Status != contract.JudgeCompleted || final.Result.Verdict != contract.VerdictTLE || final.Result.PassedTestCount != 1 || final.Result.TotalTestCount != 3 || *final.Result.TimeMs != 3 || *final.Result.MemoryBytes != 200 || final.Result.Score != nil {
		t.Fatal("terminal aggregate trusted adapter rather than facts")
	}
	checkEvents(t, f, task.JudgeTaskID, 4)
	if countRows(t, f.database.Runtime, `SELECT count(*) FROM judge.judge_case_results WHERE judge_task_id=$1`, string(task.JudgeTaskID)) != 3 {
		t.Fatal("final cases missing")
	}
	var raw, hash string
	if f.database.Runtime.QueryRow(`SELECT result_hash,row_to_json(r)::text FROM judge.judge_results r WHERE judge_task_id=$1`, string(task.JudgeTaskID)).Scan(&hash, &raw) != nil {
		t.Fatal("result hash unavailable")
	}
	encoded, _ := json.Marshal(final.Result)
	expectedHash, _ := canonical.HashJSON(encoded)
	if hash != expectedHash {
		t.Fatal("complete public result hash differs")
	}
	if _, err = f.repository.Complete(context.Background(), lease, outcome(lease, contract.VerdictAC, contract.VerdictAC, contract.VerdictAC)); err != taskdomain.ErrLeaseLost {
		t.Fatal("terminal task revived")
	}
	if _, err = f.database.Runtime.Exec(`UPDATE judge.judge_results SET passed_test_count=0 WHERE judge_task_id=$1`, string(task.JudgeTaskID)); err == nil {
		t.Fatal("original result was mutable")
	}
}

func TestPostgresFencedRecoveryInitialPlusThree(t *testing.T) {
	f := prepare(t, 1)
	task := f.accept(t, "100")
	lease := f.claim(t)
	first := lease.Token
	var started time.Time
	if f.database.Runtime.QueryRow(`SELECT started_at FROM judge.judge_tasks WHERE id=$1`, string(task.JudgeTaskID)).Scan(&started) != nil {
		t.Fatal("first start unavailable")
	}
	for recovery := 1; recovery <= 3; recovery++ {
		mustExec(t, f.database.Admin, `UPDATE judge.judge_tasks SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, string(task.JudgeTaskID))
		if err := f.repository.Heartbeat(context.Background(), lease); err != taskdomain.ErrLeaseLost {
			t.Fatal("expired heartbeat resurrected fence")
		}
		if _, err := f.repository.Fail(context.Background(), lease, "STALE_WORKER"); err != taskdomain.ErrLeaseLost {
			t.Fatal("expired owner committed before replacement")
		}
		previous := lease
		lease = f.claim(t)
		if lease.AttemptCount != recovery || lease.Token == previous.Token || lease.Token == first || lease.Task.Status != contract.JudgeDispatching {
			t.Fatal("fresh recovery reservation is incorrect")
		}
		if f.repository.Running(context.Background(), previous) != taskdomain.ErrLeaseLost {
			t.Fatal("old worker acknowledged after new fence")
		}
		var retained time.Time
		_ = f.database.Runtime.QueryRow(`SELECT started_at FROM judge.judge_tasks WHERE id=$1`, string(task.JudgeTaskID)).Scan(&retained)
		if retained != started {
			t.Fatal("recovery overwrote first start")
		}
	}
	mustExec(t, f.database.Admin, `UPDATE judge.judge_tasks SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, string(task.JudgeTaskID))
	next, err := f.repository.Claim(context.Background())
	if err != nil || next != nil {
		t.Fatalf("exhaustion did not finalize: %v", err)
	}
	final, found, err := f.repository.Get(context.Background(), task.JudgeTaskID)
	if err != nil || !found || final.Status != contract.JudgeFailed || final.Result.Verdict != contract.VerdictIE || final.Error.Code != "JUDGE_INTERRUPTED" || final.Error.Retryable || final.Revision != 6 {
		t.Fatal("exhausted task lacks immutable failed IE")
	}
	checkEvents(t, f, task.JudgeTaskID, 6)
}

func TestPostgresOriginalCaseTransactionAndLateAppend(t *testing.T) {
	f := prepare(t, 1)
	f.accept(t, "100")
	lease := f.claim(t)
	if f.repository.Running(context.Background(), lease) != nil {
		t.Fatal("ack failed")
	}
	final, err := taskdomain.Reduce(lease.Cases, judgeruntime.Outcome{Result: contract.JudgeResult{Verdict: contract.VerdictCE}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	final.Cases = nil
	tx, err := f.database.Runtime.Begin()
	if err != nil {
		t.Fatal("cannot begin isolated finalization")
	}
	defer tx.Rollback()
	if _, err = writeFinal(context.Background(), tx, lease.Task.JudgeTaskID, lease.Token, final, false); err != nil || tx.Commit() != nil {
		t.Fatal("valid CE-only finalization failed")
	}
	if _, err = f.database.Runtime.Exec(`INSERT INTO judge.judge_case_results(judge_task_id,test_case_id,ordinal,verdict) VALUES($1,$2,1,'SKIPPED')`, string(lease.Task.JudgeTaskID), string(lease.Cases[0].TestCaseID)); err == nil {
		t.Fatal("late SKIPPED case appended to committed CE result")
	}
	f.accept(t, "101")
	lease = f.claim(t)
	if f.repository.Running(context.Background(), lease) != nil {
		t.Fatal("ack failed")
	}
	final, err = taskdomain.Reduce(lease.Cases, outcome(lease, contract.VerdictAC), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tx, err = f.database.Runtime.Begin()
	if err != nil {
		t.Fatal("cannot begin isolated finalization")
	}
	defer tx.Rollback()
	c := final.Cases[0]
	if _, err = tx.Exec(`INSERT INTO judge.judge_case_results(judge_task_id,test_case_id,ordinal,verdict,cpu_time_ms,wall_time_ms,memory_bytes) VALUES($1,$2,1,'AC',$3,$4,$5)`, string(lease.Task.JudgeTaskID), string(c.TestCaseID), int64(*c.CPUTimeMS), int64(*c.WallTimeMS), int64(*c.MemoryBytes)); err != nil {
		t.Fatal("case before result insertion failed")
	}
	final.Cases = nil
	if _, err = writeFinal(context.Background(), tx, lease.Task.JudgeTaskID, lease.Token, final, false); err != nil || tx.Commit() != nil {
		t.Fatal("deferred same-transaction case/result failed")
	}
}

func TestPostgresLargeCaseBatch(t *testing.T) {
	f := prepare(t, 4096)
	f.accept(t, "100")
	lease := f.claim(t)
	if f.repository.Running(context.Background(), lease) != nil {
		t.Fatal("ack failed")
	}
	verdicts := make([]contract.JudgeVerdict, 4096)
	for i := range verdicts {
		verdicts[i] = contract.VerdictAC
	}
	start := time.Now()
	final, err := f.repository.Complete(context.Background(), lease, outcome(lease, verdicts...))
	elapsed := time.Since(start)
	if err != nil || final.Result.PassedTestCount != 4096 || countRows(t, f.database.Runtime, `SELECT count(*) FROM judge.judge_case_results WHERE judge_task_id=$1`, string(lease.Task.JudgeTaskID)) != 4096 {
		t.Fatalf("large frozen case batch failed: %v", err)
	}
	t.Logf("4096 cases atomically committed in %s", elapsed.Round(time.Millisecond))
	checkEvents(t, f, lease.Task.JudgeTaskID, 4)
}

func TestPostgresDeadlineCheckedAfterRowLockWait(t *testing.T) {
	for _, operation := range []string{"heartbeat", "running", "complete"} {
		t.Run(operation, func(t *testing.T) {
			f := prepare(t, 1)
			f.accept(t, "100")
			lease := f.claim(t)
			if operation == "complete" && f.repository.Running(context.Background(), lease) != nil {
				t.Fatal("ack failed")
			}
			mustExec(t, f.database.Admin, `UPDATE judge.judge_tasks SET lease_expires_at=clock_timestamp()+interval '250 milliseconds' WHERE id=$1`, string(lease.Task.JudgeTaskID))
			blocker, err := f.database.Admin.Begin()
			if err != nil {
				t.Fatal("cannot reserve row lock")
			}
			defer blocker.Rollback()
			var locked string
			if blocker.QueryRow(`SELECT id::text FROM judge.judge_tasks WHERE id=$1 FOR UPDATE`, string(lease.Task.JudgeTaskID)).Scan(&locked) != nil {
				t.Fatal("cannot hold task row lock")
			}
			result := make(chan error, 1)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			go func() {
				switch operation {
				case "heartbeat":
					result <- f.repository.Heartbeat(ctx, lease)
				case "running":
					result <- f.repository.Running(ctx, lease)
				case "complete":
					_, err := f.repository.Complete(ctx, lease, outcome(lease, contract.VerdictAC))
					result <- err
				}
			}()
			// The lock holder deliberately makes no row update: READ COMMITTED
			// must not depend on a changed tuple to re-evaluate database time.
			time.Sleep(350 * time.Millisecond)
			_ = blocker.Rollback()
			if err := <-result; err != taskdomain.ErrLeaseLost {
				t.Fatalf("expired %s accepted after lock wait: %v", operation, err)
			}
			if countRows(t, f.database.Runtime, `SELECT count(*) FROM judge.judge_results WHERE judge_task_id=$1`, string(lease.Task.JudgeTaskID)) != 0 {
				t.Fatal("expired owner persisted result")
			}
		})
	}
}

func TestPostgresSourcePinFailureRollsBackAdmission(t *testing.T) {
	f := prepare(t, 1)
	in := f.input(t, "100")
	mustExec(t, f.database.Admin, `DELETE FROM judge.private_object_stages WHERE id=$1`, string(in.Source.RegistrationID))
	if _, _, err := f.repository.Create(context.Background(), in); err != taskdomain.ErrPersistence {
		t.Fatal("missing source pin did not fail admission")
	}
	if countRows(t, f.database.Runtime, `SELECT count(*) FROM judge.judge_tasks WHERE request_id=$1`, string(in.Request.RequestID)) != 0 || countRows(t, f.database.Runtime, `SELECT count(*) FROM judge.callback_outbox WHERE request_id=$1`, string(in.Request.RequestID)) != 0 || countRows(t, f.database.Runtime, `SELECT count(*) FROM judge.private_object_references WHERE owner_id=$1`, string(in.Source.TaskID)) != 0 {
		t.Fatal("partial admission survived source pin failure")
	}
}

func TestPostgresRuntimeRegistrationRetainsIdentity(t *testing.T) {
	f := prepare(t, 1)
	identity := judgetask.Identity()
	for range 2 {
		if f.repository.RegisterRuntime(context.Background(), identity, false) != nil {
			t.Fatal("exact runtime initialization failed")
		}
	}
	ready, err := f.repository.RuntimeReady(context.Background(), identity, false)
	if err != nil || !ready {
		t.Fatal("registered runtime was not ready")
	}
	if f.repository.RegisterRuntime(context.Background(), identity, true) != taskdomain.ErrInvalid {
		t.Fatal("configuration version rewrote analysis capability")
	}
	ready, err = f.repository.RuntimeReady(context.Background(), identity, true)
	if err != nil || ready {
		t.Fatal("mismatched runtime configuration remained ready")
	}
	mustExec(t, f.database.Admin, `UPDATE judge.judge_language_configs SET is_active=false WHERE language_id='cpp17'`)
	ready, err = f.repository.RuntimeReady(context.Background(), identity, false)
	if err != nil || ready {
		t.Fatal("read-only health activated inactive runtime")
	}
	if countRows(t, f.database.Runtime, `SELECT count(*) FROM judge.judge_language_configs WHERE language_id='cpp17'`) != 1 {
		t.Fatal("repeat initialization duplicated configuration history")
	}
}
