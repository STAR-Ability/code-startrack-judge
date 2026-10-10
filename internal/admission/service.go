// Package admission coordinates durable JudgeTask admission. The repository
// owns publication/configuration locks, uniqueness and task/outbox transactions;
// this service owns request validation, replay ordering and staged source input.
package admission

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/storage"
)

// Accepted holds only the safe task projection and its immutable request hash.
type Accepted struct {
	Task        contract.JudgeTask
	RequestHash string
}

// StagedSource is a durable private registration. Its bytes are already written
// and pinned against GC when Stage returns. The task transaction must consume
// that registration; a bare object write is insufficient for acceptance.
type StagedSource = storage.SourceRegistration

// RuntimeIdentity is supplied by the qualified server runtime, never the caller.
// The repository must lock and verify the corresponding active immutable
// language configuration before freezing its checker/limits/template context.
type RuntimeIdentity struct {
	LanguageID            string
	LanguageConfigVersion string
	CompilerVersion       string
	ToolchainDigest       string
	WorkerImageDigest     string
	SandboxVersion        string
	CheckerDigest         string
}

type CreateInput struct {
	Request     contract.JudgeTaskRequest
	RequestHash string
	Source      StagedSource
	Runtime     RuntimeIdentity
}

func (CreateInput) String() string         { return "judge admission [source and private context redacted]" }
func (input CreateInput) GoString() string { return input.String() }

// Repository methods return a stable coded error for deterministic rejections.
// Create atomically checks current eligibility, consumes the source registration,
// freezes the complete execution context, inserts QUEUED and its initial outbox.
// Concurrent request/submission uniqueness is resolved inside that transaction.
type Repository interface {
	FindByRequest(context.Context, contract.UUID) (Accepted, bool, error)
	FindBySubmission(context.Context, contract.ID) (contract.JudgeTask, bool, error)
	Create(context.Context, CreateInput) (Accepted, bool, error)
	Get(context.Context, contract.UUID) (contract.JudgeTask, bool, error)
	FindRequests(context.Context, []contract.UUID) (map[contract.UUID]contract.JudgeTask, error)
}

type SourceRegistry interface {
	Stage(context.Context, contract.UUID, []byte, string) (StagedSource, error)
	// Abandon marks only an unconsumed candidate registration for checked cleanup.
	// It must never unpin/delete a registration consumed by an accepted task.
	Abandon(context.Context, StagedSource) error
}

type RuntimeProvider func(context.Context) (RuntimeIdentity, bool, error)
type Options struct {
	Repository Repository
	Sources    SourceRegistry
	Runtime    RuntimeProvider
}
type Service struct {
	repository Repository
	sources    SourceRegistry
	runtime    RuntimeProvider
}

func New(options Options) (*Service, error) {
	if options.Repository == nil || options.Sources == nil || options.Runtime == nil {
		return nil, errors.New("admission dependencies are required")
	}
	return &Service{repository: options.Repository, sources: options.Sources, runtime: options.Runtime}, nil
}

// Submit returns created=true only after the required durable transaction. An
// accepted replay is resolved before runtime availability/current publication.
func (s *Service) Submit(ctx context.Context, request contract.JudgeTaskRequest) (contract.JudgeTask, bool, error) {
	if err := contract.ValidateValue(request); err != nil {
		return contract.JudgeTask{}, false, err
	}
	request = normalize(request)
	raw, err := json.Marshal(request)
	if err != nil {
		return contract.JudgeTask{}, false, failure("INTERNAL_ERROR")
	}
	hash, err := canonical.RequestHash("JUDGE", nil, raw)
	if err != nil {
		return contract.JudgeTask{}, false, failure("INTERNAL_ERROR")
	}
	accepted, found, err := s.repository.FindByRequest(ctx, request.RequestID)
	if err != nil {
		return contract.JudgeTask{}, false, repositoryError(err)
	}
	if found {
		return replay(accepted, hash)
	}
	existing, found, err := s.repository.FindBySubmission(ctx, request.SubmissionID)
	if err != nil {
		return contract.JudgeTask{}, false, repositoryError(err)
	}
	if found {
		// Another admission can commit between these two read-committed
		// lookups. Its submission is an accepted replay when it belongs to
		// this request; fetch the recorded hash before deciding compatibility.
		if existing.RequestID == request.RequestID {
			accepted, found, err = s.repository.FindByRequest(ctx, request.RequestID)
			if err != nil {
				return contract.JudgeTask{}, false, repositoryError(err)
			}
			if !found {
				return contract.JudgeTask{}, false, failure("INTERNAL_ERROR")
			}
			return replay(accepted, hash)
		}
		return contract.JudgeTask{}, false, failure("IDEMPOTENCY_CONFLICT")
	}
	identity, ready, err := s.runtime(ctx)
	if err != nil || !ready || !identity.valid() {
		return contract.JudgeTask{}, false, failure("JUDGE_UNAVAILABLE")
	}
	id, err := contract.NewUUID()
	if err != nil {
		return contract.JudgeTask{}, false, failure("INTERNAL_ERROR")
	}
	source, err := s.sources.Stage(ctx, id, []byte(request.SourceCode), request.SourceSHA256)
	if err != nil {
		return contract.JudgeTask{}, false, failure("JUDGE_UNAVAILABLE")
	}
	consumed := false
	defer func() {
		if !consumed {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = s.sources.Abandon(cleanupCtx, source)
		}
	}()
	if source.TaskID != id || source.RegistrationID.Validate() != nil || source.Key == "" || source.SHA256 != request.SourceSHA256 || source.SizeBytes != int64(len(request.SourceCode)) {
		return contract.JudgeTask{}, false, failure("INTERNAL_ERROR")
	}
	accepted, created, err := s.repository.Create(ctx, CreateInput{Request: request, RequestHash: hash, Source: source, Runtime: identity})
	if err != nil {
		return contract.JudgeTask{}, false, repositoryError(err)
	}
	if !created {
		return replay(accepted, hash)
	}
	consumed = true
	if accepted.RequestHash != hash || accepted.Task.JudgeTaskID != id || accepted.Task.RequestID != request.RequestID || accepted.Task.SubmissionID != request.SubmissionID || accepted.Task.Validate() != nil {
		return contract.JudgeTask{}, false, failure("INTERNAL_ERROR")
	}
	return accepted.Task, true, nil
}

func (s *Service) Get(ctx context.Context, id contract.UUID) (contract.JudgeTask, error) {
	if err := id.Validate(); err != nil {
		return contract.JudgeTask{}, err
	}
	id = contract.UUID(strings.ToLower(string(id)))
	task, found, err := s.repository.Get(ctx, id)
	if err != nil {
		return contract.JudgeTask{}, repositoryError(err)
	}
	if !found {
		return contract.JudgeTask{}, failure("TASK_NOT_FOUND")
	}
	if task.Validate() != nil || task.JudgeTaskID != id {
		return contract.JudgeTask{}, failure("INTERNAL_ERROR")
	}
	return task, nil
}

func (s *Service) ByRequest(ctx context.Context, request contract.ByRequestRequest) (contract.ByRequestResponse, error) {
	if err := request.Validate(); err != nil {
		return contract.ByRequestResponse{}, err
	}
	ids := make([]contract.UUID, len(request.RequestIDs))
	for i, id := range request.RequestIDs {
		ids[i] = contract.UUID(strings.ToLower(string(id)))
	}
	// UUID spelling is canonicalized after HTTP header/body equality checking.
	seen := map[contract.UUID]bool{}
	for _, id := range ids {
		if seen[id] {
			return contract.ByRequestResponse{}, contract.Invalid("requestIds")
		}
		seen[id] = true
	}
	tasks, err := s.repository.FindRequests(ctx, ids)
	if err != nil {
		return contract.ByRequestResponse{}, repositoryError(err)
	}
	result := contract.ByRequestResponse{Tasks: make(contract.Array[contract.JudgeTask], 0, len(ids)), MissingRequestIDs: make(contract.Array[contract.UUID], 0, len(ids))}
	for _, id := range ids {
		task, found := tasks[id]
		if !found {
			result.MissingRequestIDs = append(result.MissingRequestIDs, id)
			continue
		}
		if task.Validate() != nil || task.RequestID != id {
			return contract.ByRequestResponse{}, failure("INTERNAL_ERROR")
		}
		result.Tasks = append(result.Tasks, task)
	}
	return result, nil
}

func replay(accepted Accepted, hash string) (contract.JudgeTask, bool, error) {
	if accepted.RequestHash != hash {
		return contract.JudgeTask{}, false, failure("IDEMPOTENCY_CONFLICT")
	}
	if accepted.Task.Validate() != nil {
		return contract.JudgeTask{}, false, failure("INTERNAL_ERROR")
	}
	return accepted.Task, false, nil
}
func normalize(request contract.JudgeTaskRequest) contract.JudgeTaskRequest {
	request.RequestID = contract.UUID(strings.ToLower(string(request.RequestID)))
	if request.ProblemRef.ProblemVersionID != nil {
		version := contract.UUID(strings.ToLower(string(*request.ProblemRef.ProblemVersionID)))
		request.ProblemRef.ProblemVersionID = &version
	}
	return request
}

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var checksumPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (i RuntimeIdentity) valid() bool {
	return i.LanguageID == "cpp17" && i.LanguageConfigVersion != "" && i.CompilerVersion != "" && i.SandboxVersion != "" && digestPattern.MatchString(i.ToolchainDigest) && digestPattern.MatchString(i.WorkerImageDigest) && checksumPattern.MatchString(i.CheckerDigest)
}
func failure(code string) error { return &contract.ValidationError{Code: code} }
func repositoryError(err error) error {
	var validation *contract.ValidationError
	if errors.As(err, &validation) {
		return validation
	}
	var coded interface{ PublicCode() string }
	if errors.As(err, &coded) {
		return failure(coded.PublicCode())
	}
	return failure("JUDGE_UNAVAILABLE")
}
