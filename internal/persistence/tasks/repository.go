// Package tasks persists frozen JudgeTask facts and exact callback snapshots.
package tasks

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/admission"
	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/packages"
	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
	taskdomain "github.com/STAR-Ability/code-startrack-judge/internal/tasks"
)

type SourceAttacher interface {
	AttachSource(context.Context, *sql.Tx, admission.StagedSource) error
}
type Repository struct {
	db      *sql.DB
	sources SourceAttacher
}

func New(db *sql.DB, sources SourceAttacher) (*Repository, error) {
	if db == nil || sources == nil {
		return nil, taskdomain.ErrInvalid
	}
	return &Repository{db: db, sources: sources}, nil
}

var _ admission.Repository = (*Repository)(nil)
var _ taskdomain.Repository = (*Repository)(nil)

func reject(code string) error { return &contract.ValidationError{Code: code} }

type scanner interface{ Scan(...any) error }
type querier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

const projection = `SELECT t.id::text,t.request_id::text,t.request_hash,t.submission_id::text,t.status,t.revision,t.error::text,
t.created_at,t.updated_at,t.finished_at,r.verdict,r.time_ms,r.memory_bytes,r.passed_test_count,r.total_test_count,
r.compile_log,r.diagnostic_code,r.judged_at FROM judge.judge_tasks t LEFT JOIN judge.judge_results r ON r.judge_task_id=t.id `

func scanTask(row scanner) (admission.Accepted, error) {
	var a admission.Accepted
	var id, request, status, submission string
	var errorJSON, verdict, compile, diagnostic sql.NullString
	var created, updated time.Time
	var finished, judged sql.NullTime
	var cpu, memory, passed, total sql.NullInt64
	if err := row.Scan(&id, &request, &a.RequestHash, &submission, &status, &a.Task.Revision, &errorJSON, &created, &updated, &finished, &verdict, &cpu, &memory, &passed, &total, &compile, &diagnostic, &judged); err != nil {
		return a, err
	}
	a.Task.JudgeTaskID = contract.UUID(id)
	a.Task.RequestID = contract.UUID(request)
	a.Task.SubmissionID = contract.ID(submission)
	a.Task.Status = contract.JudgeStatus(status)
	a.Task.TaskBase.Status = status
	a.Task.CreatedAt = contract.UTC(created)
	a.Task.UpdatedAt = contract.UTC(updated)
	if finished.Valid {
		instant := contract.UTC(finished.Time)
		a.Task.FinishedAt = &instant
	}
	if errorJSON.Valid {
		if json.Unmarshal([]byte(errorJSON.String), &a.Task.Error) != nil {
			return a, taskdomain.ErrPersistence
		}
	}
	if verdict.Valid {
		result := &contract.JudgeResult{Verdict: contract.JudgeVerdict(verdict.String), PassedTestCount: contract.SafeInt(passed.Int64), TotalTestCount: contract.SafeInt(total.Int64), JudgedAt: contract.UTC(judged.Time)}
		if cpu.Valid {
			value := contract.SafeInt(cpu.Int64)
			result.TimeMs = &value
		}
		if memory.Valid {
			value := contract.SafeInt(memory.Int64)
			result.MemoryBytes = &value
		}
		if compile.Valid {
			result.CompileLog = &compile.String
		}
		if diagnostic.Valid {
			result.DiagnosticCode = &diagnostic.String
		}
		a.Task.Result = result
	}
	if a.Task.Validate() != nil {
		return admission.Accepted{}, taskdomain.ErrPersistence
	}
	return a, nil
}
func readTask(ctx context.Context, q querier, where string, arg any) (admission.Accepted, bool, error) {
	a, err := scanTask(q.QueryRowContext(ctx, projection+where, arg))
	if errors.Is(err, sql.ErrNoRows) {
		return a, false, nil
	}
	if err != nil {
		return admission.Accepted{}, false, taskdomain.ErrPersistence
	}
	return a, true, nil
}
func (r *Repository) FindByRequest(ctx context.Context, id contract.UUID) (admission.Accepted, bool, error) {
	return readTask(ctx, r.db, "WHERE t.request_id=$1", string(id))
}
func (r *Repository) FindBySubmission(ctx context.Context, id contract.ID) (contract.JudgeTask, bool, error) {
	a, found, err := readTask(ctx, r.db, "WHERE t.submission_id=$1", string(id))
	return a.Task, found, err
}
func (r *Repository) Get(ctx context.Context, id contract.UUID) (contract.JudgeTask, bool, error) {
	a, found, err := readTask(ctx, r.db, "WHERE t.id=$1", string(id))
	return a.Task, found, err
}
func (r *Repository) FindRequests(ctx context.Context, ids []contract.UUID) (map[contract.UUID]contract.JudgeTask, error) {
	if len(ids) < 1 || len(ids) > 100 {
		return nil, taskdomain.ErrInvalid
	}
	values := make([]string, len(ids))
	for i, id := range ids {
		if id.Validate() != nil {
			return nil, taskdomain.ErrInvalid
		}
		values[i] = string(id)
	}
	rows, err := r.db.QueryContext(ctx, projection+"WHERE t.request_id=ANY($1::uuid[])", values)
	if err != nil {
		return nil, taskdomain.ErrPersistence
	}
	defer rows.Close()
	result := map[contract.UUID]contract.JudgeTask{}
	for rows.Next() {
		a, err := scanTask(rows)
		if err != nil {
			return nil, taskdomain.ErrPersistence
		}
		result[a.Task.RequestID] = a.Task
	}
	if rows.Err() != nil {
		return nil, taskdomain.ErrPersistence
	}
	return result, nil
}

var shaPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Create serializes both logical idempotency keys before checking mutable
// admission state. No request identity survives a deterministic rejection.
func (r *Repository) Create(ctx context.Context, in admission.CreateInput) (admission.Accepted, bool, error) {
	if in.Request.Validate() != nil || in.Source.TaskID.Validate() != nil || in.Source.RegistrationID.Validate() != nil || in.Source.Key == "" || in.Source.SHA256 != in.Request.SourceSHA256 || in.Source.SizeBytes != int64(len(in.Request.SourceCode)) || !shaPattern.MatchString(in.RequestHash) {
		return admission.Accepted{}, false, taskdomain.ErrInvalid
	}
	raw, err := json.Marshal(in.Request)
	if err != nil {
		return admission.Accepted{}, false, taskdomain.ErrInvalid
	}
	hash, err := canonical.RequestHash("JUDGE", nil, raw)
	if err != nil || hash != in.RequestHash {
		return admission.Accepted{}, false, taskdomain.ErrInvalid
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return admission.Accepted{}, false, taskdomain.ErrPersistence
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('judge-request:'||$1,0))`, string(in.Request.RequestID)); err != nil {
		return admission.Accepted{}, false, taskdomain.ErrPersistence
	}
	a, found, err := readTask(ctx, tx, "WHERE t.request_id=$1", string(in.Request.RequestID))
	if err != nil {
		return a, false, err
	}
	if found {
		if a.RequestHash != hash {
			return a, false, reject("IDEMPOTENCY_CONFLICT")
		}
		if tx.Commit() != nil {
			return a, false, taskdomain.ErrPersistence
		}
		return a, false, nil
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('judge-submission:'||$1,0))`, string(in.Request.SubmissionID)); err != nil {
		return a, false, taskdomain.ErrPersistence
	}
	_, found, err = readTask(ctx, tx, "WHERE t.submission_id=$1", string(in.Request.SubmissionID))
	if err != nil {
		return a, false, err
	}
	if found {
		return a, false, reject("IDEMPOTENCY_CONFLICT")
	}
	var status, current string
	err = tx.QueryRowContext(ctx, `SELECT status,coalesce(current_version_id::text,'') FROM judge.platform_problems WHERE id=$1 FOR SHARE`, string(in.Request.ProblemRef.ProblemID)).Scan(&status, &current)
	if errors.Is(err, sql.ErrNoRows) {
		return a, false, reject("PROBLEM_NOT_FOUND")
	}
	if err != nil {
		return a, false, taskdomain.ErrPersistence
	}
	if status != "PUBLISHED" {
		return a, false, reject("PROBLEM_NOT_SUBMITTABLE")
	}
	if in.Request.ProblemRef.ProblemVersionID != nil && string(*in.Request.ProblemRef.ProblemVersionID) != current {
		return a, false, reject("PROBLEM_VERSION_CONFLICT")
	}
	var frozen taskdomain.Frozen
	var checkerJSON string
	var cpu, wall, memory, output int64
	var languageAllowed bool
	err = tx.QueryRowContext(ctx, `SELECT v.package_artifact_id::text,v.time_limit_ms,v.wall_limit_ms,v.memory_limit_bytes,v.output_limit_bytes,v.checker_config::text,$3=ANY(v.language_ids)
 FROM judge.problem_versions v JOIN judge.package_artifacts a ON a.id=v.package_artifact_id JOIN judge.license_evidence l ON l.id=a.license_evidence_id
 WHERE v.problem_id=$1 AND v.id=$2 AND v.first_published_at IS NOT NULL AND a.validation_run_id IS NOT NULL AND l.status='VERIFIED' FOR SHARE OF v,a,l`, string(in.Request.ProblemRef.ProblemID), current, in.Request.LanguageID).Scan(&frozen.ArtifactID, &cpu, &wall, &memory, &output, &checkerJSON, &languageAllowed)
	if err != nil {
		return a, false, taskdomain.ErrPersistence
	}
	if !languageAllowed {
		return a, false, reject("LANGUAGE_NOT_SUPPORTED")
	}
	var compiler, toolchain string
	var compile, run, compileLimits string
	var active bool
	err = tx.QueryRowContext(ctx, `SELECT compiler_version,toolchain_digest,source_filename,compile_template::text,run_template::text,compile_limits::text,is_active
 FROM judge.judge_language_configs WHERE language_id=$1 AND config_version=$2 FOR SHARE`, in.Request.LanguageID, in.Runtime.LanguageConfigVersion).Scan(&compiler, &toolchain, &frozen.SourceFilename, &compile, &run, &compileLimits, &active)
	if err != nil || !active || compiler != in.Runtime.CompilerVersion || toolchain != in.Runtime.ToolchainDigest || in.Runtime.LanguageID != in.Request.LanguageID {
		return a, false, reject("JUDGE_UNAVAILABLE")
	}
	expectedCompile, expectedRun, expectedLimits := runtimeProfile()
	if frozen.SourceFilename != "main.cpp" || !sameJSON([]byte(compile), expectedCompile) || !sameJSON([]byte(run), expectedRun) || !sameJSON([]byte(compileLimits), expectedLimits) {
		return a, false, reject("JUDGE_UNAVAILABLE")
	}
	frozen.Identity = judgeruntime.FrozenIdentity{LanguageConfigVersion: in.Runtime.LanguageConfigVersion, CompilerVersion: compiler, ToolchainDigest: toolchain, WorkerImageDigest: in.Runtime.WorkerImageDigest, SandboxVersion: in.Runtime.SandboxVersion, CheckerDigest: in.Runtime.CheckerDigest}
	frozen.Limits = judgeruntime.Limits{CPUTimeNS: uint64(cpu) * uint64(time.Millisecond), WallTimeNS: uint64(wall) * uint64(time.Millisecond), MemoryBytes: uint64(memory), OutputBytes: uint64(output), Processes: 32}
	var checker packages.CheckerConfig
	if json.Unmarshal([]byte(checkerJSON), &checker) != nil || checker.Type != "DEFAULT" || checker.Profile != "kattis-default-v1.20260907" || checker.Implementation.RepositoryURL != "https://github.com/Kattis/problemtools" || checker.Implementation.Revision != packages.CheckerRevision || checker.Implementation.SourcePath != "support/default_validator/default_validator.cc" {
		return a, false, reject("JUDGE_UNAVAILABLE")
	}
	frozen.Checker = judgeruntime.CheckerConfig{Implementation: judgeruntime.CheckerImplementation, SourceSHA256: checker.Implementation.SourceSHA256, CaseSensitive: checker.CaseSensitive, SpaceChangeSensitive: checker.SpaceChangeSensitive, FloatAbsoluteTolerance: checker.FloatAbsoluteTolerance, FloatRelativeTolerance: checker.FloatRelativeTolerance}
	if frozen.Identity.Validate() != nil || frozen.Limits.Validate() != nil || frozen.Checker.Validate() != nil {
		return a, false, reject("JUDGE_UNAVAILABLE")
	}
	frozen.CompileTemplate = json.RawMessage(compile)
	frozen.RunTemplate = json.RawMessage(run)
	frozen.CompileLimits = json.RawMessage(compileLimits)
	frozen.SourceSizeBytes = in.Source.SizeBytes
	frozenJSON, err := json.Marshal(frozen)
	if err != nil {
		return a, false, taskdomain.ErrPersistence
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO judge.judge_tasks(id,request_id,request_hash,submission_id,problem_id,problem_version_id,source_owner,source_sha256,transient_source_key,language_id,language_config_version,sandbox_version,worker_image_digest,execution_limits,status)
 VALUES($1,$2,$3,$4,$5,$6,'backend',$7,$8,$9,$10,$11,$12,$13,'QUEUED')`, string(in.Source.TaskID), string(in.Request.RequestID), hash, string(in.Request.SubmissionID), string(in.Request.ProblemRef.ProblemID), current, in.Request.SourceSHA256, in.Source.Key, in.Request.LanguageID, in.Runtime.LanguageConfigVersion, in.Runtime.SandboxVersion, in.Runtime.WorkerImageDigest, string(frozenJSON))
	if err != nil {
		return a, false, taskdomain.ErrPersistence
	}
	if err = r.sources.AttachSource(ctx, tx, in.Source); err != nil {
		return a, false, taskdomain.ErrPersistence
	}
	a, found, err = readTask(ctx, tx, "WHERE t.id=$1", string(in.Source.TaskID))
	if err != nil || !found {
		return a, false, taskdomain.ErrPersistence
	}
	if err = appendEvent(ctx, tx, a.Task); err != nil {
		return a, false, err
	}
	if tx.Commit() != nil {
		return a, false, taskdomain.ErrPersistence
	}
	return a, true, nil
}

func sameJSON(a, b []byte) bool {
	left, err := canonical.HashJSON(a)
	if err != nil {
		return false
	}
	right, err := canonical.HashJSON(b)
	return err == nil && left == right
}

func appendEvent(ctx context.Context, tx *sql.Tx, task contract.JudgeTask) error {
	id, err := contract.NewUUID()
	if err != nil {
		return taskdomain.ErrPersistence
	}
	event := contract.CallbackEvent[contract.JudgeTask]{EventID: id, EventType: "JUDGE_TASK_UPDATED", OccurredAt: task.UpdatedAt, RequestID: task.RequestID, AggregateID: task.JudgeTaskID, Revision: task.Revision, Payload: task}
	if event.Validate() != nil {
		return taskdomain.ErrPersistence
	}
	raw, err := json.Marshal(event)
	if err != nil {
		return taskdomain.ErrPersistence
	}
	hash, err := canonical.HashJSON(raw)
	if err != nil {
		return taskdomain.ErrPersistence
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO judge.callback_outbox(event_id,judge_task_id,revision,event_type,request_id,payload,payload_hash,status,next_attempt_at,created_at,updated_at)
 VALUES($1,$2,$3,'JUDGE_TASK_UPDATED',$4,$5,$6,'PENDING',statement_timestamp(),statement_timestamp(),statement_timestamp())`, string(id), string(task.JudgeTaskID), int64(task.Revision), string(task.RequestID), string(raw), hash)
	if err != nil {
		return taskdomain.ErrPersistence
	}
	return nil
}
