package admission

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
)

type repositoryFixture struct {
	byRequest    map[contract.UUID]Accepted
	bySubmission map[contract.ID]contract.JudgeTask
	byID         map[contract.UUID]contract.JudgeTask
	create       func(CreateInput) (Accepted, bool, error)
	created      int
}

func repository() *repositoryFixture {
	return &repositoryFixture{byRequest: map[contract.UUID]Accepted{}, bySubmission: map[contract.ID]contract.JudgeTask{}, byID: map[contract.UUID]contract.JudgeTask{}}
}
func (r *repositoryFixture) FindByRequest(_ context.Context, id contract.UUID) (Accepted, bool, error) {
	a, ok := r.byRequest[id]
	return a, ok, nil
}
func (r *repositoryFixture) FindBySubmission(_ context.Context, id contract.ID) (contract.JudgeTask, bool, error) {
	a, ok := r.bySubmission[id]
	return a, ok, nil
}
func (r *repositoryFixture) Get(_ context.Context, id contract.UUID) (contract.JudgeTask, bool, error) {
	a, ok := r.byID[id]
	return a, ok, nil
}
func (r *repositoryFixture) FindRequests(_ context.Context, ids []contract.UUID) (map[contract.UUID]contract.JudgeTask, error) {
	out := map[contract.UUID]contract.JudgeTask{}
	for _, id := range ids {
		if a, ok := r.byRequest[id]; ok {
			out[id] = a.Task
		}
	}
	return out, nil
}
func (r *repositoryFixture) Create(_ context.Context, input CreateInput) (Accepted, bool, error) {
	if r.create != nil {
		return r.create(input)
	}
	if existing, ok := r.byRequest[input.Request.RequestID]; ok {
		return existing, false, nil
	}
	if _, ok := r.bySubmission[input.Request.SubmissionID]; ok {
		return Accepted{}, false, failure("IDEMPOTENCY_CONFLICT")
	}
	now := contract.Instant("2026-10-08T00:00:00Z")
	task := contract.JudgeTask{TaskBase: contract.TaskBase{RequestID: input.Request.RequestID, Revision: 1, CreatedAt: now, UpdatedAt: now}, JudgeTaskID: input.Source.TaskID, SubmissionID: input.Request.SubmissionID, Status: contract.JudgeQueued}
	a := Accepted{Task: task, RequestHash: input.RequestHash}
	r.byRequest[task.RequestID] = a
	r.bySubmission[task.SubmissionID] = task
	r.byID[task.JudgeTaskID] = task
	r.created++
	return a, true, nil
}

type sourceFixture struct {
	stages     int
	abandoned  []StagedSource
	lastSource []byte
	err        error
}

func (s *sourceFixture) Stage(_ context.Context, id contract.UUID, source []byte, hash string) (StagedSource, error) {
	s.stages++
	s.lastSource = append([]byte(nil), source...)
	if s.err != nil {
		return StagedSource{}, s.err
	}
	registration, _ := contract.NewUUID()
	return StagedSource{RegistrationID: registration, TaskID: id, Key: "private/candidate/" + string(id), SHA256: hash, SizeBytes: int64(len(source))}, nil
}
func (s *sourceFixture) Abandon(_ context.Context, source StagedSource) error {
	s.abandoned = append(s.abandoned, source)
	return nil
}
func validRuntime() RuntimeIdentity {
	return RuntimeIdentity{LanguageID: "cpp17", LanguageConfigVersion: "cpp17-v1", CompilerVersion: "synthetic tested compiler", ToolchainDigest: "sha256:" + strings.Repeat("1", 64), WorkerImageDigest: "sha256:" + strings.Repeat("2", 64), SandboxVersion: "go-judge-v1.13.0", CheckerDigest: strings.Repeat("3", 64)}
}
func fixture(t *testing.T) contract.JudgeTaskRequest {
	t.Helper()
	data, e := os.ReadFile("../contract/testdata/judge-request.json")
	if e != nil {
		t.Fatal(e)
	}
	var request contract.JudgeTaskRequest
	if e := contract.DecodeJSON(data, &request); e != nil {
		t.Fatal(e)
	}
	return request
}
func errorCode(err error) string {
	var v *contract.ValidationError
	if errors.As(err, &v) {
		return v.Code
	}
	return ""
}
func service(t *testing.T, r Repository, s SourceRegistry, ready *bool, checks *int) *Service {
	t.Helper()
	out, e := New(Options{Repository: r, Sources: s, Runtime: func(context.Context) (RuntimeIdentity, bool, error) { *checks++; return validRuntime(), *ready, nil }})
	if e != nil {
		t.Fatal(e)
	}
	return out
}

func TestAcceptedReplaySurvivesUnavailableRuntimeAndNewInputsConflict(t *testing.T) {
	r := repository()
	source := &sourceFixture{}
	ready := true
	checks := 0
	s := service(t, r, source, &ready, &checks)
	request := fixture(t)
	first, created, e := s.Submit(context.Background(), request)
	if e != nil || !created {
		t.Fatalf("first admission: %v %v", created, e)
	}
	ready = false
	replayed, created, e := s.Submit(context.Background(), request)
	if e != nil || created || replayed.JudgeTaskID != first.JudgeTaskID {
		t.Fatalf("accepted replay unavailable: %v %v", created, e)
	}
	if checks != 1 || source.stages != 1 || r.created != 1 {
		t.Fatal("replay contacted fresh dependencies or created duplicate task")
	}
	request.SourceCode += "\r\n"
	request.SourceSHA256, _ = canonical.HashSource(request.SourceCode)
	if _, _, e := s.Submit(context.Background(), request); errorCode(e) != "IDEMPOTENCY_CONFLICT" {
		t.Fatalf("same identity changed source: %v", e)
	}
	if string(source.lastSource) != "int main() { return 0; }\n" {
		t.Fatal("source bytes changed during acceptance")
	}
}
func TestDuplicateSubmissionConflictsBeforeAvailability(t *testing.T) {
	r := repository()
	source := &sourceFixture{}
	ready := true
	checks := 0
	s := service(t, r, source, &ready, &checks)
	request := fixture(t)
	if _, _, e := s.Submit(context.Background(), request); e != nil {
		t.Fatal(e)
	}
	request.RequestID = "123e4567-e89b-12d3-a456-426614174003"
	ready = false
	if _, _, e := s.Submit(context.Background(), request); errorCode(e) != "IDEMPOTENCY_CONFLICT" {
		t.Fatalf("new request for accepted submission: %v", e)
	}
	if checks != 1 || source.stages != 1 {
		t.Fatal("duplicate submission reached fresh readiness/storage")
	}
}

// Model two observations separated by another transaction's commit, including
// the case where execution readiness has already disappeared by replay time.
type committedBetweenLookups struct {
	*repositoryFixture
	missFirst bool
}

func (r *committedBetweenLookups) FindByRequest(ctx context.Context, id contract.UUID) (Accepted, bool, error) {
	if r.missFirst {
		r.missFirst = false
		return Accepted{}, false, nil
	}
	return r.repositoryFixture.FindByRequest(ctx, id)
}

func TestConcurrentCommitBetweenPreflightLookups(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(fmt.Sprintf("changed=%v", changed), func(t *testing.T) {
			r := repository()
			source := &sourceFixture{}
			ready, checks := true, 0
			request := fixture(t)
			first, created, err := service(t, r, source, &ready, &checks).Submit(context.Background(), request)
			if err != nil || !created {
				t.Fatal("cannot seed accepted winner")
			}
			if changed {
				request.SourceCode += "\r\n"
				request.SourceSHA256, _ = canonical.HashSource(request.SourceCode)
			}
			ready = false
			racing := &committedBetweenLookups{repositoryFixture: r, missFirst: true}
			task, created, err := service(t, racing, source, &ready, &checks).Submit(context.Background(), request)
			if changed {
				if created || errorCode(err) != "IDEMPOTENCY_CONFLICT" {
					t.Fatal("racing replay accepted a changed body")
				}
			} else if err != nil || created || task.JudgeTaskID != first.JudgeTaskID {
				t.Fatal("racing accepted request was not recovered")
			}
			if checks != 1 || source.stages != 1 || r.created != 1 {
				t.Fatal("racing accepted request consulted fresh readiness or created new facts")
			}
		})
	}
}

func TestDeterministicRejectionDoesNotReserveTaskIdentity(t *testing.T) {
	r := repository()
	source := &sourceFixture{}
	ready := true
	checks := 0
	s := service(t, r, source, &ready, &checks)
	request := fixture(t)
	r.create = func(input CreateInput) (Accepted, bool, error) {
		if source.stages != 1 || input.Source.TaskID == "" {
			t.Fatal("repository called without staged source")
		}
		return Accepted{}, false, failure("PROBLEM_NOT_SUBMITTABLE")
	}
	if _, created, e := s.Submit(context.Background(), request); created || errorCode(e) != "PROBLEM_NOT_SUBMITTABLE" {
		t.Fatalf("rejected admission: %v %v", created, e)
	}
	if len(r.byRequest) != 0 || len(r.bySubmission) != 0 || len(source.abandoned) != 1 {
		t.Fatal("rejection reserved business identity or lost cleanup candidate")
	}
	r.create = nil
	if _, created, e := s.Submit(context.Background(), request); e != nil || !created {
		t.Fatalf("unreserved request cannot be accepted later: %v %v", created, e)
	}
	if r.created != 1 || len(source.abandoned) != 1 {
		t.Fatal("successful registered source abandoned")
	}
}
func TestConcurrentWinnerReplayAbandonsOnlyLoserCandidate(t *testing.T) {
	r := repository()
	source := &sourceFixture{}
	ready := true
	checks := 0
	s := service(t, r, source, &ready, &checks)
	request := fixture(t)
	// The repository simulates a different transaction committing after this
	// caller's replay lookup but before its unique-key-protected Create.
	r.create = func(input CreateInput) (Accepted, bool, error) {
		raw, _ := json.Marshal(input.Request)
		hash, _ := canonical.RequestHash("JUDGE", nil, raw)
		now := contract.Instant("2026-10-08T00:00:00Z")
		winner := contract.JudgeTask{TaskBase: contract.TaskBase{RequestID: request.RequestID, Revision: 1, CreatedAt: now, UpdatedAt: now}, JudgeTaskID: "123e4567-e89b-12d3-a456-426614174004", SubmissionID: request.SubmissionID, Status: contract.JudgeQueued}
		return Accepted{Task: winner, RequestHash: hash}, false, nil
	}
	task, created, e := s.Submit(context.Background(), request)
	if e != nil || created || task.JudgeTaskID != "123e4567-e89b-12d3-a456-426614174004" {
		t.Fatalf("race winner recovery: %v %v", created, e)
	}
	if len(source.abandoned) != 1 || source.abandoned[0].TaskID == task.JudgeTaskID {
		t.Fatal("winner's source was marked for cleanup")
	}
}
func TestUnavailableAndStorageFailureDoNotCreateTask(t *testing.T) {
	for _, storageFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "unqualified", true: "storage"}[storageFailure], func(t *testing.T) {
			r := repository()
			source := &sourceFixture{}
			ready := storageFailure
			checks := 0
			s := service(t, r, source, &ready, &checks)
			if storageFailure {
				source.err = errors.New("private /hidden path credential")
			}
			_, created, e := s.Submit(context.Background(), fixture(t))
			if created || errorCode(e) != "JUDGE_UNAVAILABLE" || r.created != 0 {
				t.Fatalf("failed dependency accepted: %v", e)
			}
			if strings.Contains(e.Error(), "hidden") || strings.Contains(e.Error(), "credential") {
				t.Fatal("raw dependency diagnostic leaked")
			}
		})
	}
}
func TestByRequestOrderingMissingAndIdentityValidation(t *testing.T) {
	r := repository()
	source := &sourceFixture{}
	ready := true
	checks := 0
	s := service(t, r, source, &ready, &checks)
	first := fixture(t)
	one, _, e := s.Submit(context.Background(), first)
	if e != nil {
		t.Fatal(e)
	}
	second := first
	second.RequestID = "123e4567-e89b-12d3-a456-426614174003"
	second.SubmissionID = "1"
	two, _, e := s.Submit(context.Background(), second)
	if e != nil {
		t.Fatal(e)
	}
	missing := contract.UUID("123e4567-e89b-12d3-a456-426614174004")
	ready = false
	result, e := s.ByRequest(context.Background(), contract.ByRequestRequest{RequestIDs: contract.Array[contract.UUID]{second.RequestID, missing, first.RequestID}})
	if e != nil {
		t.Fatal(e)
	}
	if len(result.Tasks) != 2 || result.Tasks[0].JudgeTaskID != two.JudgeTaskID || result.Tasks[1].JudgeTaskID != one.JudgeTaskID || len(result.MissingRequestIDs) != 1 || result.MissingRequestIDs[0] != missing {
		t.Fatal("by-request lost caller ordering or original task identity")
	}
	if task, e := s.Get(context.Background(), one.JudgeTaskID); e != nil || task.RequestID != first.RequestID {
		t.Fatal("historical query depends on execution availability", e)
	}
	if _, e := s.ByRequest(context.Background(), contract.ByRequestRequest{RequestIDs: contract.Array[contract.UUID]{first.RequestID, contract.UUID(strings.ToUpper(string(first.RequestID)))}}); errorCode(e) != "INVALID_ARGUMENT" {
		t.Fatal("equivalent UUID duplicate admitted")
	}
	if _, e := s.Get(context.Background(), missing); errorCode(e) != "TASK_NOT_FOUND" {
		t.Fatal("missing query fabricated task")
	}
}
