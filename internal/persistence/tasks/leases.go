package tasks

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
	taskdomain "github.com/STAR-Ability/code-startrack-judge/internal/tasks"
)

// Claim reserves exactly one initial or counted recovery attempt. No runtime
// call or private blob read occurs inside the SKIP LOCKED transaction.
func (r *Repository) Claim(ctx context.Context) (*taskdomain.Lease, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, taskdomain.ErrPersistence
	}
	defer tx.Rollback()
	var id string
	var count int
	var status string
	err = tx.QueryRowContext(ctx, `SELECT id::text,attempt_count,status FROM judge.judge_tasks
 WHERE status='QUEUED' OR (status IN ('DISPATCHING','RUNNING') AND lease_expires_at<=clock_timestamp())
 ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(&id, &count, &status)
	if errors.Is(err, sql.ErrNoRows) {
		if tx.Commit() != nil {
			return nil, taskdomain.ErrPersistence
		}
		return nil, nil
	}
	if err != nil {
		return nil, taskdomain.ErrPersistence
	}
	if status != "QUEUED" && count == 3 {
		expected, err := caseDefinitions(ctx, tx, contract.UUID(id))
		if err != nil {
			return nil, err
		}
		var now time.Time
		if tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now) != nil {
			return nil, taskdomain.ErrPersistence
		}
		final, err := taskdomain.Reduce(expected, failureOutcome("JUDGE_INTERRUPTED"), now)
		if err != nil {
			return nil, err
		}
		if _, err = writeFinal(ctx, tx, contract.UUID(id), "", final, true); err != nil {
			return nil, err
		}
		if tx.Commit() != nil {
			return nil, taskdomain.ErrPersistence
		}
		return nil, nil
	}
	token, err := contract.NewUUID()
	if err != nil {
		return nil, taskdomain.ErrPersistence
	}
	_, err = tx.ExecContext(ctx, `UPDATE judge.judge_tasks SET status='DISPATCHING',revision=revision+1,
 started_at=coalesce(started_at,clock_timestamp()),updated_at=clock_timestamp(),lease_owner=$2,
 lease_expires_at=clock_timestamp()+interval '180 seconds',attempt_count=attempt_count+CASE WHEN status='QUEUED' THEN 0 ELSE 1 END WHERE id=$1`, id, string(token))
	if err != nil {
		return nil, taskdomain.ErrPersistence
	}
	a, found, err := readTask(ctx, tx, "WHERE t.id=$1", id)
	if err != nil || !found {
		return nil, taskdomain.ErrPersistence
	}
	if appendEvent(ctx, tx, a.Task) != nil || tx.Commit() != nil {
		return nil, taskdomain.ErrPersistence
	}
	return r.loadLease(ctx, contract.UUID(id), token)
}

type caseQuerier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func caseDefinitions(ctx context.Context, q caseQuerier, id contract.UUID) ([]judgeruntime.Case, error) {
	rows, err := q.QueryContext(ctx, `SELECT tc.id::text,tc.ordinal,tc.input_sha256,tc.input_size_bytes,tc.answer_sha256,tc.answer_size_bytes
 FROM judge.judge_tasks t JOIN judge.problem_versions v ON v.id=t.problem_version_id
 JOIN judge.problem_test_cases tc ON tc.package_artifact_id=v.package_artifact_id WHERE t.id=$1 ORDER BY tc.ordinal`, string(id))
	if err != nil {
		return nil, taskdomain.ErrPersistence
	}
	defer rows.Close()
	cases := make([]judgeruntime.Case, 0)
	for rows.Next() {
		var c judgeruntime.Case
		if rows.Scan(&c.TestCaseID, &c.Ordinal, &c.Input.SHA256, &c.Input.SizeBytes, &c.Answer.SHA256, &c.Answer.SizeBytes) != nil {
			return nil, taskdomain.ErrPersistence
		}
		cases = append(cases, c)
	}
	if rows.Err() != nil || len(cases) < 1 || len(cases) > 65536 {
		return nil, taskdomain.ErrPersistence
	}
	return cases, nil
}
func (r *Repository) loadLease(ctx context.Context, id, token contract.UUID) (*taskdomain.Lease, error) {
	a, found, err := readTask(ctx, r.db, "WHERE t.id=$1", string(id))
	if err != nil || !found {
		return nil, taskdomain.ErrPersistence
	}
	l := &taskdomain.Lease{Task: a.Task, Token: token}
	var frozenJSON string
	err = r.db.QueryRowContext(ctx, `SELECT attempt_count,lease_expires_at,transient_source_key,source_sha256,execution_limits::text FROM judge.judge_tasks
 WHERE id=$1 AND lease_owner=$2 AND status='DISPATCHING' AND lease_expires_at>clock_timestamp()`, string(id), string(token)).Scan(&l.AttemptCount, &l.ExpiresAt, &l.SourceKey, &l.SourceSHA256, &frozenJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, taskdomain.ErrLeaseLost
	}
	if err != nil || json.Unmarshal([]byte(frozenJSON), &l.Frozen) != nil {
		return nil, taskdomain.ErrPersistence
	}
	l.Cases, err = caseDefinitions(ctx, r.db, id)
	if err != nil {
		return nil, err
	}
	for i := range l.Cases {
		l.Cases[i].Checker = l.Frozen.Checker
	}
	return l, nil
}
func validLease(l *taskdomain.Lease) bool {
	return l != nil && l.Task.JudgeTaskID.Validate() == nil && l.Token.Validate() == nil
}
func (r *Repository) Running(ctx context.Context, l *taskdomain.Lease) error {
	if !validLease(l) {
		return taskdomain.ErrInvalid
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return taskdomain.ErrPersistence
	}
	defer tx.Rollback()
	if err := lockTask(ctx, tx, l.Task.JudgeTaskID); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE judge.judge_tasks SET status='RUNNING',revision=revision+1,updated_at=clock_timestamp()
 WHERE id=$1 AND lease_owner=$2 AND status='DISPATCHING' AND lease_expires_at>clock_timestamp()`, string(l.Task.JudgeTaskID), string(l.Token))
	if err != nil {
		return taskdomain.ErrPersistence
	}
	n, err := result.RowsAffected()
	if err != nil {
		return taskdomain.ErrPersistence
	}
	if n != 1 {
		return taskdomain.ErrLeaseLost
	}
	a, found, err := readTask(ctx, tx, "WHERE t.id=$1", string(l.Task.JudgeTaskID))
	if err != nil || !found {
		return taskdomain.ErrPersistence
	}
	if appendEvent(ctx, tx, a.Task) != nil || tx.Commit() != nil {
		return taskdomain.ErrPersistence
	}
	return nil
}
func (r *Repository) Heartbeat(ctx context.Context, l *taskdomain.Lease) error {
	if !validLease(l) {
		return taskdomain.ErrInvalid
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return taskdomain.ErrPersistence
	}
	defer tx.Rollback()
	if err := lockTask(ctx, tx, l.Task.JudgeTaskID); err != nil {
		return err
	}
	var expiry time.Time
	err = tx.QueryRowContext(ctx, `UPDATE judge.judge_tasks SET lease_expires_at=clock_timestamp()+interval '180 seconds'
 WHERE id=$1 AND lease_owner=$2 AND status IN ('DISPATCHING','RUNNING') AND lease_expires_at>clock_timestamp() RETURNING lease_expires_at`, string(l.Task.JudgeTaskID), string(l.Token)).Scan(&expiry)
	if errors.Is(err, sql.ErrNoRows) {
		return taskdomain.ErrLeaseLost
	}
	if err != nil {
		return taskdomain.ErrPersistence
	}
	if tx.Commit() != nil {
		return taskdomain.ErrPersistence
	}
	return nil
}

// Acquire the row lock before evaluating the volatile deadline. A contender
// waiting behind a transaction that only locks (without updating) must still
// reject an expiry that occurs during that wait.
func lockTask(ctx context.Context, tx *sql.Tx, id contract.UUID) error {
	var locked string
	err := tx.QueryRowContext(ctx, `SELECT id::text FROM judge.judge_tasks WHERE id=$1 FOR UPDATE`, string(id)).Scan(&locked)
	if errors.Is(err, sql.ErrNoRows) {
		return taskdomain.ErrLeaseLost
	}
	if err != nil {
		return taskdomain.ErrPersistence
	}
	return nil
}

func failureOutcome(code string) judgeruntime.Outcome {
	return judgeruntime.Outcome{Result: contract.JudgeResult{Verdict: contract.VerdictIE, DiagnosticCode: &code}, Error: &contract.TaskError{Code: code, Message: "Controlled execution failed", Retryable: false}}
}
func (r *Repository) Fail(ctx context.Context, l *taskdomain.Lease, code string) (contract.JudgeTask, error) {
	return r.complete(ctx, l, failureOutcome(code), false)
}
func (r *Repository) Complete(ctx context.Context, l *taskdomain.Lease, out judgeruntime.Outcome) (contract.JudgeTask, error) {
	return r.complete(ctx, l, out, true)
}
func (r *Repository) complete(ctx context.Context, l *taskdomain.Lease, out judgeruntime.Outcome, requireRunning bool) (contract.JudgeTask, error) {
	if !validLease(l) {
		return contract.JudgeTask{}, taskdomain.ErrInvalid
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return contract.JudgeTask{}, taskdomain.ErrPersistence
	}
	defer tx.Rollback()
	var status string
	err = tx.QueryRowContext(ctx, `SELECT status FROM judge.judge_tasks WHERE id=$1 AND lease_owner=$2 AND lease_expires_at>clock_timestamp()
 AND status IN ('DISPATCHING','RUNNING') FOR UPDATE`, string(l.Task.JudgeTaskID), string(l.Token)).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return contract.JudgeTask{}, taskdomain.ErrLeaseLost
	}
	if err != nil {
		return contract.JudgeTask{}, taskdomain.ErrPersistence
	}
	if requireRunning && status != "RUNNING" {
		return contract.JudgeTask{}, taskdomain.ErrInvalid
	}
	expected, err := caseDefinitions(ctx, tx, l.Task.JudgeTaskID)
	if err != nil {
		return contract.JudgeTask{}, err
	}
	var now time.Time
	if tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now) != nil {
		return contract.JudgeTask{}, taskdomain.ErrPersistence
	}
	final, err := taskdomain.Reduce(expected, out, now)
	if err != nil {
		return contract.JudgeTask{}, err
	}
	task, err := writeFinal(ctx, tx, l.Task.JudgeTaskID, l.Token, final, false)
	if err != nil {
		return contract.JudgeTask{}, err
	}
	if tx.Commit() != nil {
		return contract.JudgeTask{}, taskdomain.ErrPersistence
	}
	return task, nil
}

func writeFinal(ctx context.Context, tx *sql.Tx, id, token contract.UUID, f taskdomain.Final, exhausted bool) (contract.JudgeTask, error) {
	status := "COMPLETED"
	var errorJSON any
	if f.Error != nil {
		status = "FAILED"
		raw, err := json.Marshal(f.Error)
		if err != nil {
			return contract.JudgeTask{}, taskdomain.ErrPersistence
		}
		errorJSON = string(raw)
	}
	// The final update checks database time again after reduction. An expired
	// worker cannot commit even when no replacement worker has claimed yet.
	var tokenArg any = string(token)
	predicate := `lease_owner=$5 AND lease_expires_at>clock_timestamp()`
	if exhausted {
		predicate = `attempt_count=3 AND lease_expires_at<=clock_timestamp() AND $5::uuid IS NULL`
		tokenArg = nil
	}
	result, err := tx.ExecContext(ctx, `UPDATE judge.judge_tasks SET status=$2,revision=revision+1,error=$3,
 lease_owner=NULL,lease_expires_at=NULL,finished_at=$4,updated_at=$4,source_expires_at=$4::timestamptz+interval '24 hours'
 WHERE id=$1 AND status IN ('DISPATCHING','RUNNING') AND `+predicate, string(id), status, errorJSON, string(f.Result.JudgedAt), tokenArg)
	if err != nil {
		return contract.JudgeTask{}, taskdomain.ErrPersistence
	}
	n, err := result.RowsAffected()
	if err != nil {
		return contract.JudgeTask{}, taskdomain.ErrPersistence
	}
	if n != 1 {
		return contract.JudgeTask{}, taskdomain.ErrLeaseLost
	}
	raw, err := json.Marshal(f.Result)
	if err != nil {
		return contract.JudgeTask{}, taskdomain.ErrPersistence
	}
	hash, err := canonical.HashJSON(raw)
	if err != nil {
		return contract.JudgeTask{}, taskdomain.ErrPersistence
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO judge.judge_results(judge_task_id,verdict,time_ms,memory_bytes,passed_test_count,total_test_count,score,compile_log,diagnostic_code,judged_at,result_hash)
 VALUES($1,$2,$3,$4,$5,$6,NULL,$7,$8,$9,$10)`, string(id), string(f.Result.Verdict), safePointer(f.Result.TimeMs), safePointer(f.Result.MemoryBytes), int64(f.Result.PassedTestCount), int64(f.Result.TotalTestCount), f.Result.CompileLog, f.Result.DiagnosticCode, string(f.Result.JudgedAt), hash)
	if err != nil {
		return contract.JudgeTask{}, taskdomain.ErrPersistence
	}
	// A bounded chunk keeps SQL shape fixed while avoiding a roundtrip per case.
	for start := 0; start < len(f.Cases); start += 1024 {
		end := start + 1024
		if end > len(f.Cases) {
			end = len(f.Cases)
		}
		encoded, err := json.Marshal(f.Cases[start:end])
		if err != nil {
			return contract.JudgeTask{}, taskdomain.ErrPersistence
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO judge.judge_case_results(judge_task_id,test_case_id,ordinal,verdict,cpu_time_ms,wall_time_ms,memory_bytes,exit_code,sandbox_status,checker_status)
 SELECT $1,x."TestCaseID",x."Ordinal",x."Verdict",x."CPUTimeMS",x."WallTimeMS",x."MemoryBytes",x."ExitCode",x."SandboxStatus",x."CheckerStatus"
 FROM jsonb_to_recordset($2::jsonb) AS x("TestCaseID" uuid,"Ordinal" integer,"Verdict" text,"CPUTimeMS" bigint,"WallTimeMS" bigint,"MemoryBytes" bigint,"ExitCode" integer,"SandboxStatus" text,"CheckerStatus" text)`, string(id), string(encoded))
		if err != nil {
			return contract.JudgeTask{}, taskdomain.ErrPersistence
		}
	}
	a, found, err := readTask(ctx, tx, "WHERE t.id=$1", string(id))
	if err != nil || !found {
		return contract.JudgeTask{}, taskdomain.ErrPersistence
	}
	if appendEvent(ctx, tx, a.Task) != nil {
		return contract.JudgeTask{}, taskdomain.ErrPersistence
	}
	return a.Task, nil
}
func safePointer(p *contract.SafeInt) any {
	if p == nil {
		return nil
	}
	return int64(*p)
}
