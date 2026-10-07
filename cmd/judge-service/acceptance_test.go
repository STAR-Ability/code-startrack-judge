package main

// Refs #22. These tests execute the real HTTP/domain/storage/worker/outbox
// components against PostgreSQL. Runtime results and Backend inbox behavior are
// explicit fixtures: no submitted code, Linux isolation, or real Backend is
// qualified by this suite.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/admission"
	"github.com/STAR-Ability/code-startrack-judge/internal/callbacks"
	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/catalog"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/httpapi"
	"github.com/STAR-Ability/code-startrack-judge/internal/imports"
	persistenceimports "github.com/STAR-Ability/code-startrack-judge/internal/persistence/imports"
	persistenceoutbox "github.com/STAR-Ability/code-startrack-judge/internal/persistence/outbox"
	persistenceproblems "github.com/STAR-Ability/code-startrack-judge/internal/persistence/problems"
	persistencetasks "github.com/STAR-Ability/code-startrack-judge/internal/persistence/tasks"
	"github.com/STAR-Ability/code-startrack-judge/internal/problems"
	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
	"github.com/STAR-Ability/code-startrack-judge/internal/runtime/restclient"
	"github.com/STAR-Ability/code-startrack-judge/internal/storage"
	"github.com/STAR-Ability/code-startrack-judge/internal/tasks"
	"github.com/STAR-Ability/code-startrack-judge/internal/testutil/judgetask"
	"github.com/STAR-Ability/code-startrack-judge/internal/testutil/postgres"
	"github.com/STAR-Ability/code-startrack-judge/internal/validation"
)

const (
	acceptanceInbound                = "acceptance-inbound-credential-abcdefghijklmnopqrstuvwxyz"
	acceptanceOutbound               = "acceptance-outbound-credential-abcdefghijklmnopqrstuvwxyz"
	acceptancePrivate                = "SYNTHETIC_PRIVATE_SOURCE_ANSWER_TOOL_LOG"
	acceptanceVersion  contract.UUID = "00000000-0000-0000-0000-000000000011"
)

type acceptancePlan struct {
	verdict   contract.JudgeVerdict
	crashOnce bool
}
type acceptanceRuntime struct {
	ready           atomic.Bool
	mu              sync.Mutex
	plans           map[string]acceptancePlan
	inputs          map[string][]judgeruntime.TaskInput
	store           *storage.Store
	validationCalls atomic.Int64
}

func (runtime *acceptanceRuntime) Snapshot(context.Context) judgeruntime.Snapshot {
	snapshot := syntheticSnapshot()
	snapshot.Qualified = runtime.ready.Load()
	snapshot.SandboxReady = snapshot.Qualified
	snapshot.ToolchainReady = snapshot.Qualified
	return snapshot
}
func (runtime *acceptanceRuntime) Execute(ctx context.Context, input judgeruntime.TaskInput, progress judgeruntime.ProgressFunc) (judgeruntime.Outcome, error) {
	if err := progress(ctx, judgeruntime.Progress{Type: "progress", Status: "Compiling"}); err != nil {
		return judgeruntime.Outcome{}, err
	}
	runtime.mu.Lock()
	plan, exists := runtime.plans[input.SourceSHA256]
	runtime.inputs[input.SourceSHA256] = append(runtime.inputs[input.SourceSHA256], input)
	attempt := len(runtime.inputs[input.SourceSHA256])
	runtime.mu.Unlock()
	if !exists || canonical.HashBytes(input.Source) != input.SourceSHA256 {
		return judgeruntime.Outcome{}, &judgeruntime.Failure{Code: "FIXTURE_INPUT_INVALID"}
	}
	if plan.crashOnce && attempt == 1 {
		return judgeruntime.Outcome{}, &judgeruntime.Failure{Code: "FIXTURE_TRANSPORT_LOST", Ambiguous: true}
	}
	privateLog := acceptancePrivate + " /w/secret stdout stderr sha256/private"
	out := judgeruntime.Outcome{Result: contract.JudgeResult{Verdict: plan.verdict, CompileLog: &privateLog}}
	if plan.verdict == contract.VerdictCE {
		return out, nil
	}
	for i, test := range input.Cases {
		verdict := contract.VerdictAC
		status := restclient.Accepted
		if i == 1 && plan.verdict != contract.VerdictAC {
			verdict = plan.verdict
			if verdict == contract.VerdictIE {
				verdict = contract.VerdictWA
			}
			switch verdict {
			case contract.VerdictTLE:
				status = restclient.TimeLimit
			case contract.VerdictMLE:
				status = restclient.MemoryLimit
			case contract.VerdictRE:
				status = restclient.Signalled
			case contract.VerdictOLE:
				status = restclient.OutputLimit
			}
		}
		if err := progress(ctx, judgeruntime.Progress{Type: "progress", Status: "Judging", Ordinal: i + 1}); err != nil {
			return judgeruntime.Outcome{}, err
		}
		out.Cases = append(out.Cases, judgeruntime.CaseResult{TestCaseID: test.TestCaseID, Ordinal: test.Ordinal, Verdict: verdict, CPUTimeNS: uint64(i+1)*uint64(time.Millisecond) + 1, WallTimeNS: uint64(i+2) * uint64(time.Millisecond), MemoryBytes: uint64(256 + i), SandboxStatus: status, CheckerStatus: restclient.NonzeroExit})
		if verdict != contract.VerdictAC {
			break
		}
	}
	if plan.verdict == contract.VerdictIE {
		out.Error = &contract.TaskError{Code: "FIXTURE_CHECKER_FAILED", Message: privateLog, Retryable: true}
	}
	return out, nil
}
func (runtime *acceptanceRuntime) captured(hash string) []judgeruntime.TaskInput {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return append([]judgeruntime.TaskInput{}, runtime.inputs[hash]...)
}

// This is an inbox expectation fixture, not Backend business persistence. It
// stores only frozen dispatch references and received public task projections.
type acceptanceBackend struct {
	mu          sync.Mutex
	pending     map[contract.UUID]contract.ID
	bindings    map[contract.UUID]contract.UUID
	seen        map[contract.UUID]string
	projections map[contract.UUID]contract.JudgeTask
	revisions   map[contract.UUID]map[contract.SafeInt]string
	fault       callbacks.Code
	delay       bool
	dropACK     bool
	deliveries  []callbacks.Delivery
	bodies      [][]byte
	duplicates  int
}

func (backend *acceptanceBackend) expect(request contract.JudgeTaskRequest) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.pending[request.RequestID] = request.SubmissionID
}
func (backend *acceptanceBackend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Host != "backend:8081" || r.URL.Path != "/internal/v2/events/judge" || r.Header.Get("Authorization") != "Bearer "+acceptanceOutbound {
		w.WriteHeader(401)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, contract.MaxResultBytes+1))
	var event contract.CallbackEvent[contract.JudgeTask]
	if err != nil || int64(len(raw)) > contract.MaxResultBytes || contract.DecodeJSON(raw, &event) != nil || r.Header.Get("X-Request-Id") != string(event.RequestID) {
		w.WriteHeader(400)
		return
	}
	backend.mu.Lock()
	backend.bodies = append(backend.bodies, append([]byte{}, raw...))
	fault, delay := backend.fault, backend.delay
	if delay {
		backend.mu.Unlock()
		<-r.Context().Done()
		return
	}
	if fault != "" {
		backend.mu.Unlock()
		switch fault {
		case callbacks.Unauthorized:
			w.WriteHeader(401)
		case callbacks.Conflict:
			w.WriteHeader(409)
		case callbacks.InvalidACK:
			w.Write([]byte(acceptancePrivate))
		default:
			w.WriteHeader(503)
		}
		return
	}
	defer backend.mu.Unlock()
	if backend.pending[event.RequestID] != event.Payload.SubmissionID {
		w.WriteHeader(404)
		return
	}
	if binding := backend.bindings[event.RequestID]; binding != "" && binding != event.AggregateID {
		w.WriteHeader(409)
		return
	}
	backend.bindings[event.RequestID] = event.AggregateID
	duplicate := false
	hash := canonical.HashBytes(raw)
	if prior, known := backend.seen[event.EventID]; known {
		if prior != hash {
			w.WriteHeader(409)
			return
		}
		duplicate = true
	} else {
		payload, _ := json.Marshal(event.Payload)
		payload, _ = canonical.Canonicalize(payload)
		payloadHash := canonical.HashBytes(payload)
		if backend.revisions[event.AggregateID] == nil {
			backend.revisions[event.AggregateID] = map[contract.SafeInt]string{}
		}
		if prior, known := backend.revisions[event.AggregateID][event.Revision]; known && prior != payloadHash {
			w.WriteHeader(409)
			return
		}
		current := backend.projections[event.AggregateID]
		if current.Revision >= event.Revision {
			duplicate = true
		} else {
			backend.projections[event.AggregateID] = event.Payload
		}
		backend.revisions[event.AggregateID][event.Revision] = payloadHash
		backend.seen[event.EventID] = hash
	}
	if duplicate {
		backend.duplicates++
	}
	json.NewEncoder(w).Encode(contract.ApiResponse[contract.CallbackAck]{Data: contract.CallbackAck{Accepted: true, Duplicate: duplicate}, RequestID: event.RequestID})
}
func (backend *acceptanceBackend) Send(ctx context.Context, d *callbacks.Delivery) callbacks.Outcome {
	backend.mu.Lock()
	backend.deliveries = append(backend.deliveries, *d)
	delay, drop := backend.delay, backend.dropACK
	backend.mu.Unlock()
	if canonical.HashBytes(d.CanonicalJSON) != d.PayloadHash {
		return callbacks.Outcome{ErrorCode: callbacks.IntegrityFailure}
	}
	if delay {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 20*time.Millisecond)
		defer cancel()
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, callbacks.Destination, bytes.NewReader(d.CanonicalJSON))
	request.Header.Set("Authorization", "Bearer "+acceptanceOutbound)
	request.Header.Set("X-Request-Id", string(d.RequestID))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	backend.ServeHTTP(recorder, request)
	if ctx.Err() != nil || drop {
		return callbacks.Outcome{ErrorCode: callbacks.Unavailable}
	}
	switch recorder.Code {
	case 401:
		return callbacks.Outcome{ErrorCode: callbacks.Unauthorized}
	case 404:
		return callbacks.Outcome{ErrorCode: callbacks.UnknownTask}
	case 409:
		return callbacks.Outcome{ErrorCode: callbacks.Conflict}
	case 200:
	default:
		return callbacks.Outcome{ErrorCode: callbacks.Unavailable}
	}
	var ack contract.ApiResponse[contract.CallbackAck]
	if contract.DecodeJSON(recorder.Body.Bytes(), &ack) != nil || ack.RequestID != d.RequestID || !ack.Data.Accepted {
		return callbacks.Outcome{ErrorCode: callbacks.InvalidACK}
	}
	return callbacks.Outcome{Accepted: true, Duplicate: ack.Data.Duplicate}
}

type acceptanceFixture struct {
	db           postgres.Database
	store        *storage.Store
	registry     *storage.Registry
	repo         *persistencetasks.Repository
	problemRepo  *persistenceproblems.Repository
	outbox       *persistenceoutbox.Repository
	callbacks    *callbacks.Worker
	backend      *acceptanceBackend
	runtime      *acceptanceRuntime
	server       *httptest.Server
	logs         bytes.Buffer
	sequence     atomic.Int64
	dropResponse atomic.Bool
	committed    chan struct{}
	version      contract.UUID
	statement    string
	importRepo   *persistenceimports.Repository
	pipeline     *imports.ImportPipeline
	mature       *acceptanceMature
}

func newAcceptanceFixture(t *testing.T, realImport ...bool) *acceptanceFixture {
	t.Helper()
	f := &acceptanceFixture{db: postgres.New(t), committed: make(chan struct{}), version: acceptanceVersion, statement: "fixture statement"}
	if len(realImport) == 0 || !realImport[0] {
		judgetask.Seed(t, f.db.Admin, 3)
	} else {
		f.version = ""
	}
	var err error
	f.store, err = storage.New(filepath.Join(t.TempDir(), "private"))
	if err != nil {
		t.Fatal("cannot create private acceptance storage")
	}
	t.Cleanup(func() { f.store.Close() })
	f.registry, err = storage.NewRegistry(f.db.Runtime, f.store)
	if err != nil {
		t.Fatal("cannot create private acceptance registry")
	}
	f.repo, err = persistencetasks.New(f.db.Runtime, f.registry)
	if err != nil {
		t.Fatal("cannot create acceptance task repository")
	}
	if f.repo.RegisterRuntime(context.Background(), judgetask.Identity(), false) != nil {
		t.Fatal("cannot register explicitly synthetic fixture profile")
	}
	f.runtime = &acceptanceRuntime{plans: map[string]acceptancePlan{}, inputs: map[string][]judgeruntime.TaskInput{}, store: f.store}
	f.runtime.ready.Store(true)
	service, err := admission.New(admission.Options{Repository: f.repo, Sources: f.registry, Runtime: func(context.Context) (admission.RuntimeIdentity, bool, error) {
		return judgetask.Identity(), f.runtime.ready.Load(), nil
	}})
	if err != nil {
		t.Fatal("cannot compose real acceptance admission")
	}
	f.problemRepo = persistenceproblems.New(f.db.Runtime, f.registry)
	f.importRepo = persistenceimports.New(f.db.Runtime)
	if len(realImport) > 0 && realImport[0] {
		f.mature = &acceptanceMature{runtime: f.runtime}
		validator, e := validation.New(validation.Options{Engine: f.runtime, Mature: f.mature})
		if e != nil {
			t.Fatal("cannot compose real technical validation coordinator")
		}
		f.pipeline, e = imports.NewPipeline(imports.PipelineOptions{DB: f.db.Runtime, Source: acceptanceSource{}, Registry: f.registry, Problems: f.problemRepo, Validation: validator})
		if e != nil {
			t.Fatal("cannot compose real import pipeline")
		}
	}
	problemService := problems.New(f.problemRepo, problems.Options{FreshReady: func(context.Context) bool { return true }, LanguageCapabilities: func(context.Context) contract.Array[string] { return contract.Array[string]{"cpp17"} }})
	catalogService, err := catalog.New(f.problemRepo, []byte("acceptance-catalog-cursor-key-abcdefghijklmnopqrstuvwxyz"))
	if err != nil {
		t.Fatal("cannot compose acceptance catalog")
	}
	f.backend = &acceptanceBackend{pending: map[contract.UUID]contract.ID{}, bindings: map[contract.UUID]contract.UUID{}, seen: map[contract.UUID]string{}, projections: map[contract.UUID]contract.JudgeTask{}, revisions: map[contract.UUID]map[contract.SafeInt]string{}}
	f.outbox, err = persistenceoutbox.New(f.db.Runtime)
	if err != nil {
		t.Fatal("cannot create acceptance outbox")
	}
	f.callbacks, err = callbacks.NewWorker(f.outbox, f.backend, slog.New(slog.NewTextHandler(&f.logs, nil)))
	if err != nil {
		t.Fatal("cannot compose acceptance callback worker")
	}
	routes := httpapi.Routes{Judge: service, Imports: imports.New(f.importRepo, func(ctx context.Context) bool { return f.pipeline != nil && f.pipeline.Ready(ctx) }), CurrentProblem: problemService.Current, ProblemVersion: problemService.Version, MetadataVersion: problemService.Metadata, Publish: problemService.Publish, Withdraw: problemService.Withdraw, CatalogPage: catalogService.Page}
	handler, err := httpapi.New(httpapi.Options{BackendJudgeToken: acceptanceInbound, Readiness: func(context.Context) httpapi.DependencyState {
		return httpapi.DependencyState{Database: true, PrivateStorage: true, Sandbox: true, Toolchain: true, Catalog: true, Judge: true}
	}, Register: func(mux *http.ServeMux) { httpapi.RegisterRoutes(mux, routes) }})
	if err != nil {
		t.Fatal("cannot compose real acceptance HTTP routes")
	}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/internal/v2/judge-tasks" && f.dropResponse.Swap(false) {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, r)
			if recorder.Code == 202 {
				_, _ = f.callbacks.RunOnce(r.Context()) // Force callback before POST binding.
				close(f.committed)
				<-r.Context().Done()
				return
			}
			w.WriteHeader(recorder.Code)
			w.Write(recorder.Body.Bytes())
			return
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(f.server.Close)
	return f
}
func acceptanceUUID(t *testing.T) contract.UUID {
	t.Helper()
	id, err := contract.NewUUID()
	if err != nil {
		t.Fatal("cannot allocate acceptance correlation")
	}
	return id
}
func (f *acceptanceFixture) request(t *testing.T, verdict contract.JudgeVerdict) contract.JudgeTaskRequest {
	t.Helper()
	id := acceptanceUUID(t)
	version := f.version
	source := "// " + acceptancePrivate + " " + string(id) + "\r\nint main(){return 0;}\r\n"
	hash, _ := canonical.HashSource(source)
	f.runtime.mu.Lock()
	f.runtime.plans[hash] = acceptancePlan{verdict: verdict}
	f.runtime.mu.Unlock()
	return contract.JudgeTaskRequest{RequestID: id, SubmissionID: contract.ID(strconv.FormatInt(f.sequence.Add(1), 10)), ProblemRef: contract.ProblemRef{Source: contract.SourcePlatform, Platform: contract.PlatformStartrack, ProblemID: "1", ProblemVersionID: &version}, LanguageID: "cpp17", SourceCode: source, SourceSHA256: hash}
}
func (f *acceptanceFixture) call(ctx context.Context, method, path string, id contract.UUID, body any) (int, []byte, error) {
	var encoded []byte
	var err error
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
	}
	request, err := http.NewRequestWithContext(ctx, method, f.server.URL+path, bytes.NewReader(encoded))
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Authorization", "Bearer "+acceptanceInbound)
	request.Header.Set("X-Request-Id", string(id))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := f.server.Client().Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, contract.MaxResultBytes+1))
	return response.StatusCode, raw, err
}
func acceptanceDecode[T any](t *testing.T, status int, raw []byte, err error, want int) T {
	t.Helper()
	var response contract.ApiResponse[T]
	if err != nil || status != want || contract.DecodeJSON(raw, &response) != nil {
		t.Fatalf("acceptance response failed: HTTP %d, expected %d", status, want)
	}
	assertAcceptancePublic(t, raw)
	return response.Data
}
func assertAcceptancePublic(t *testing.T, raw []byte) {
	t.Helper()
	if int64(len(raw)) > contract.MaxResultBytes {
		t.Fatal("public acceptance response exceeded contract bound")
	}
	for _, private := range []string{acceptancePrivate, acceptanceInbound, acceptanceOutbound, "sourceCode", "sourceSha256", "transient_source", "objectKey", "private/input", "private/answer", "private/source", "private/reference", "/w/secret", "sha256/private"} {
		if bytes.Contains(raw, []byte(private)) {
			t.Fatal("private fixture data entered public response, callback, or diagnostic")
		}
	}
}
func (f *acceptanceFixture) submit(t *testing.T, request contract.JudgeTaskRequest, want int) contract.JudgeTask {
	t.Helper()
	status, raw, err := f.call(context.Background(), http.MethodPost, "/internal/v2/judge-tasks", request.RequestID, request)
	return acceptanceDecode[contract.JudgeTask](t, status, raw, err, want)
}
func (f *acceptanceFixture) awaitTask(t *testing.T, id contract.UUID, status contract.JudgeStatus) contract.JudgeTask {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		task, found, err := f.repo.Get(context.Background(), id)
		if err != nil || !found {
			t.Fatal("accepted task became unavailable")
		}
		if task.Status == status {
			return task
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("accepted task did not reach expected durable state")
	return contract.JudgeTask{}
}
func (f *acceptanceFixture) startTaskWorker(t *testing.T) func() {
	t.Helper()
	worker, err := tasks.NewWorker(tasks.WorkerOptions{Repository: f.repo, Executor: f.runtime, Source: func(ctx context.Context, l *tasks.Lease) ([]byte, error) {
		return f.store.Read(ctx, storage.Object{Key: l.SourceKey, SHA256: l.SourceSHA256, SizeBytes: l.Frozen.SourceSizeBytes}, contract.MaxSourceBytes)
	}, Concurrency: 1, PollInterval: 10 * time.Millisecond, ShutdownGrace: 50 * time.Millisecond})
	if err != nil {
		t.Fatal("cannot compose real acceptance task worker")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Error("acceptance task worker stopped unexpectedly")
				}
			case <-time.After(5 * time.Second):
				t.Error("acceptance task worker did not drain")
			}
		})
	}
	t.Cleanup(stop)
	return stop
}
func (f *acceptanceFixture) drainCallbacks(t *testing.T) {
	t.Helper()
	for range 100 {
		did, err := f.callbacks.RunOnce(context.Background())
		if err != nil {
			t.Fatal("acceptance callback transaction failed")
		}
		if !did {
			return
		}
	}
	t.Fatal("callback acceptance drain exceeded bounded fixture inventory")
}
func (f *acceptanceFixture) event(t *testing.T, taskID contract.UUID, revision int) *callbacks.Delivery {
	t.Helper()
	var payload, eventID, requestID, hash string
	if f.db.Admin.QueryRow(`SELECT payload::text,event_id::text,request_id::text,payload_hash FROM judge.callback_outbox WHERE judge_task_id=$1 AND revision=$2`, string(taskID), revision).Scan(&payload, &eventID, &requestID, &hash) != nil {
		t.Fatal("accepted revision lacks atomic event")
	}
	raw, err := canonical.Canonicalize([]byte(payload))
	if err != nil {
		t.Fatal("persisted event is not canonicalizable")
	}
	assertAcceptancePublic(t, raw)
	return &callbacks.Delivery{EventID: contract.UUID(eventID), RequestID: contract.UUID(requestID), TaskID: taskID, Revision: int64(revision), PayloadHash: hash, CanonicalJSON: raw}
}

// Seed only the historical clock case through an initial operator INSERT. Every
// immutable trigger remains enabled, and source pin consumption uses the real
// Registry. HTTP admission and retry classification are exercised separately.
func (f *acceptanceFixture) historicalEvent(t *testing.T, template contract.JudgeTask, request contract.JudgeTaskRequest) *callbacks.Delivery {
	t.Helper()
	ctx := context.Background()
	id, eventID := acceptanceUUID(t), acceptanceUUID(t)
	created := time.Now().UTC().Add(-25 * time.Hour).Truncate(time.Microsecond)
	source, err := f.registry.Stage(ctx, id, []byte(request.SourceCode), request.SourceSHA256)
	if err != nil {
		t.Fatal("cannot stage exact historical callback fixture source")
	}
	requestJSON, _ := json.Marshal(request)
	requestHash, err := canonical.RequestHash("JUDGE", nil, requestJSON)
	if err != nil {
		t.Fatal("cannot hash historical fixture request")
	}
	task := contract.JudgeTask{TaskBase: contract.TaskBase{RequestID: request.RequestID, Revision: 1, CreatedAt: contract.UTC(created), UpdatedAt: contract.UTC(created)}, JudgeTaskID: id, SubmissionID: request.SubmissionID, Status: contract.JudgeQueued}
	event := contract.CallbackEvent[contract.JudgeTask]{EventID: eventID, EventType: "JUDGE_TASK_UPDATED", OccurredAt: contract.UTC(created), RequestID: request.RequestID, AggregateID: id, Revision: 1, Payload: task}
	raw, _ := json.Marshal(event)
	body, err := canonical.Canonicalize(raw)
	if err != nil {
		t.Fatal("cannot canonicalize historical fixture event")
	}
	tx, err := f.db.Admin.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal("cannot begin historical fixture transaction")
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO judge.judge_tasks(id,request_id,request_hash,submission_id,problem_id,problem_version_id,source_owner,source_sha256,transient_source_key,language_id,language_config_version,sandbox_version,worker_image_digest,execution_limits,status,created_at,updated_at)
SELECT $1,$2,$3,$4,problem_id,problem_version_id,source_owner,$5,$6,language_id,language_config_version,sandbox_version,worker_image_digest,execution_limits,'QUEUED',$7,$7 FROM judge.judge_tasks WHERE id=$8`, string(id), string(request.RequestID), requestHash, string(request.SubmissionID), source.SHA256, source.Key, created, string(template.JudgeTaskID))
	if err != nil || f.registry.AttachSource(ctx, tx, source) != nil {
		t.Fatal("cannot atomically retain historical fixture source")
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO judge.callback_outbox(event_id,judge_task_id,revision,event_type,request_id,payload,payload_hash,status,next_attempt_at,created_at,updated_at)
VALUES($1,$2,1,'JUDGE_TASK_UPDATED',$3,$4,$5,'PENDING',$6,$6,$6)`, string(eventID), string(id), string(request.RequestID), string(body), canonical.HashBytes(body), created)
	if err != nil || tx.Commit() != nil {
		t.Fatal("cannot atomically insert original historical event")
	}
	return f.event(t, id, 1)
}
func (f *acceptanceFixture) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	if _, err := f.db.Admin.Exec(query, args...); err != nil {
		t.Fatal("isolated acceptance fault injection failed")
	}
}

func TestPortableAcceptanceLostPOSTVerdictsAndReorderedEvents(t *testing.T) {
	f := newAcceptanceFixture(t)
	first := f.request(t, contract.VerdictAC)
	f.backend.expect(first)
	f.dropResponse.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	lost := make(chan error, 1)
	go func() {
		_, _, err := f.call(ctx, http.MethodPost, "/internal/v2/judge-tasks", first.RequestID, first)
		lost <- err
	}()
	select {
	case <-f.committed:
	case <-time.After(5 * time.Second):
		t.Fatal("lost-POST fixture never durably accepted")
	}
	cancel()
	if <-lost == nil {
		t.Fatal("lost-POST fault did not erase caller response")
	}
	status, raw, err := f.call(context.Background(), http.MethodPost, "/internal/v2/judge-tasks/by-request", acceptanceUUID(t), contract.ByRequestRequest{RequestIDs: contract.Array[contract.UUID]{first.RequestID}})
	recovered := acceptanceDecode[contract.ByRequestResponse](t, status, raw, err, 200)
	if len(recovered.Tasks) != 1 {
		t.Fatal("POST recovery lost accepted request")
	}
	task := recovered.Tasks[0]
	f.backend.mu.Lock()
	bound := f.backend.bindings[first.RequestID]
	f.backend.mu.Unlock()
	if bound != task.JudgeTaskID {
		t.Fatal("callback before POST response failed to bind frozen dispatch request")
	}
	if f.submit(t, first, 200).JudgeTaskID != task.JudgeTaskID {
		t.Fatal("POST replay created a second task")
	}
	stop := f.startTaskWorker(t)
	defer stop()
	for _, verdict := range []contract.JudgeVerdict{contract.VerdictAC, contract.VerdictWA, contract.VerdictTLE, contract.VerdictMLE, contract.VerdictRE, contract.VerdictCE, contract.VerdictOLE, contract.VerdictIE} {
		request := first
		accepted := task
		if verdict != contract.VerdictAC {
			request = f.request(t, verdict)
			f.backend.expect(request)
			accepted = f.submit(t, request, 202)
		}
		wantStatus := contract.JudgeStatus("COMPLETED")
		if verdict == contract.VerdictIE {
			wantStatus = "FAILED"
		}
		final := f.awaitTask(t, accepted.JudgeTaskID, wantStatus)
		if final.Result == nil || final.Result.Verdict != verdict || final.Result.TotalTestCount != 3 {
			t.Fatal("controlled verdict fixture lost authoritative result semantics")
		}
		if verdict == contract.VerdictCE && (final.Result.TimeMs != nil || final.Result.MemoryBytes != nil || final.Result.PassedTestCount != 0 || final.Error != nil) {
			t.Fatal("user compile failure became infrastructure failure or invented execution")
		}
		if verdict == contract.VerdictIE && (final.Error == nil || final.Result.PassedTestCount != 1) {
			t.Fatal("definitive infrastructure failure lost prior case facts")
		}
		if verdict != contract.VerdictIE && final.Error != nil {
			t.Fatal("code verdict was projected as infrastructure error")
		}
		status, raw, err = f.call(context.Background(), http.MethodGet, "/internal/v2/judge-tasks/"+string(final.JudgeTaskID), acceptanceUUID(t), nil)
		_ = acceptanceDecode[contract.JudgeTask](t, status, raw, err, 200)
		latest := f.event(t, final.JudgeTaskID, int(final.Revision))
		if !f.backend.Send(context.Background(), latest).Accepted {
			t.Fatal("final event fixture was not accepted")
		}
		older := f.event(t, final.JudgeTaskID, 2)
		out := f.backend.Send(context.Background(), older)
		if !out.Accepted || !out.Duplicate {
			t.Fatal("older event regressed terminal projection")
		}
		f.drainCallbacks(t)
		f.backend.mu.Lock()
		projected := f.backend.projections[final.JudgeTaskID]
		f.backend.mu.Unlock()
		if projected.Revision != final.Revision || projected.Result == nil || projected.Result.Verdict != verdict {
			t.Fatal("duplicate/reordered callback regressed public final facts")
		}
		inputs := f.runtime.captured(request.SourceSHA256)
		if len(inputs) != 1 || string(inputs[0].Source) != request.SourceCode {
			t.Fatal("private source bytes changed or accepted fence was redispatched")
		}
	}
	var event contract.CallbackEvent[contract.JudgeTask]
	delivery := f.event(t, task.JudgeTaskID, 4)
	if contract.DecodeJSON(delivery.CanonicalJSON, &event) != nil {
		t.Fatal("cannot read fixture conflict event")
	}
	event.EventID = acceptanceUUID(t)
	event.Payload.Result.Verdict = contract.VerdictWA
	forged, _ := json.Marshal(event)
	forged, _ = canonical.Canonicalize(forged)
	copy := *delivery
	copy.EventID = event.EventID
	copy.CanonicalJSON = forged
	copy.PayloadHash = canonical.HashBytes(forged)
	if f.backend.Send(context.Background(), &copy).ErrorCode != callbacks.Conflict {
		t.Fatal("same revision with different payload did not conflict")
	}
	f.backend.mu.Lock()
	for _, body := range f.backend.bodies {
		assertAcceptancePublic(t, body)
	}
	f.backend.mu.Unlock()
	assertAcceptancePublic(t, f.logs.Bytes())
}

func TestPortableAcceptanceFrozenVersionWithdrawalAndFreshFenceRecovery(t *testing.T) {
	f := newAcceptanceFixture(t, true)
	f.importAndPublish(t)
	request := f.request(t, contract.VerdictAC)
	f.backend.expect(request)
	f.runtime.mu.Lock()
	plan := f.runtime.plans[request.SourceSHA256]
	plan.crashOnce = true
	f.runtime.plans[request.SourceSHA256] = plan
	f.runtime.mu.Unlock()
	accepted := f.submit(t, request, 202)
	status, raw, err := f.call(context.Background(), http.MethodGet, "/internal/v2/catalog-snapshots?limit=10", acceptanceUUID(t), nil)
	snapshot := acceptanceDecode[contract.CatalogSnapshotPage](t, status, raw, err, 200)
	metadata := contract.MetadataVersionRequest{RequestID: acceptanceUUID(t), BaseProblemVersionID: f.version, Tags: contract.Array[string]{"acceptance"}, DifficultyScale: "UNRATED"}
	status, raw, err = f.call(context.Background(), http.MethodPost, "/internal/v2/problems/1/metadata-versions", metadata.RequestID, metadata)
	draft := acceptanceDecode[contract.PlatformProblemDetail](t, status, raw, err, 201)
	if draft.ProblemRef.ProblemVersionID.Validate() != nil {
		t.Fatal("metadata operation omitted new immutable version")
	}
	publish := contract.PublishRequest{RequestID: acceptanceUUID(t), ProblemVersionID: draft.ProblemRef.ProblemVersionID}
	status, raw, err = f.call(context.Background(), http.MethodPost, "/internal/v2/problems/1/publish", publish.RequestID, publish)
	_ = acceptanceDecode[contract.PlatformProblemDetail](t, status, raw, err, 200)
	page, err := f.problemRepo.SnapshotPage(context.Background(), snapshot.SnapshotID, 0, 10)
	if err != nil || len(page.Items) != 1 || page.Items[0].Problem.ProblemRef.ProblemVersionID == nil || *page.Items[0].Problem.ProblemRef.ProblemVersionID != f.version {
		t.Fatal("new publication rewrote frozen catalog snapshot")
	}
	withdraw := contract.WithdrawRequest{RequestID: acceptanceUUID(t), Reason: "isolated acceptance withdrawal"}
	status, raw, err = f.call(context.Background(), http.MethodPost, "/internal/v2/problems/1/withdraw", withdraw.RequestID, withdraw)
	_ = acceptanceDecode[contract.WithdrawResponse](t, status, raw, err, 200)
	fresh := f.request(t, contract.VerdictAC)
	fresh.ProblemRef.ProblemVersionID = &draft.ProblemRef.ProblemVersionID
	status, raw, err = f.call(context.Background(), http.MethodPost, "/internal/v2/judge-tasks", fresh.RequestID, fresh)
	var rejection contract.ApiError
	if err != nil || status != 409 || contract.DecodeJSON(raw, &rejection) != nil || rejection.Error.Code != "PROBLEM_NOT_SUBMITTABLE" {
		t.Fatal("withdrawn problem accepted new submission")
	}
	assertAcceptancePublic(t, raw)
	stop := f.startTaskWorker(t)
	running := f.awaitTask(t, accepted.JudgeTaskID, "RUNNING")
	stop()
	if n, err := f.registry.CleanSources(context.Background(), 100); err != nil || n != 0 {
		t.Fatal("in-flight private source was cleaned")
	}
	first := f.runtime.captured(request.SourceSHA256)
	if len(first) != 1 {
		t.Fatal("crashed fence was retried in the live process")
	}
	f.exec(t, `UPDATE judge.judge_tasks SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, string(accepted.JudgeTaskID))
	f.repo, err = persistencetasks.New(f.db.Runtime, f.registry)
	if err != nil {
		t.Fatal("cannot recreate repository after process restart")
	}
	stop = f.startTaskWorker(t)
	final := f.awaitTask(t, accepted.JudgeTaskID, "COMPLETED")
	stop()
	inputs := f.runtime.captured(request.SourceSHA256)
	if len(inputs) != 2 || inputs[0].FencingToken == inputs[1].FencingToken || inputs[0].SourceSHA256 != inputs[1].SourceSHA256 || inputs[0].Identity != inputs[1].Identity || inputs[0].Limits != inputs[1].Limits || inputs[0].Cases[0].TestCaseID != inputs[1].Cases[0].TestCaseID {
		t.Fatal("recovery changed frozen execution or reused stale fence")
	}
	stale := &tasks.Lease{Task: running, Token: first[0].FencingToken}
	if !errors.Is(f.repo.Heartbeat(context.Background(), stale), tasks.ErrLeaseLost) {
		t.Fatal("stale worker renewed recovered task")
	}
	if _, err := f.repo.Complete(context.Background(), stale, judgeruntime.Outcome{}); !errors.Is(err, tasks.ErrLeaseLost) {
		t.Fatal("stale worker rewrote recovered result")
	}
	var version, sourceKey, sourceHash string
	var attempts int
	if f.db.Admin.QueryRow(`SELECT problem_version_id::text,transient_source_key,source_sha256::text,attempt_count FROM judge.judge_tasks WHERE id=$1`, string(final.JudgeTaskID)).Scan(&version, &sourceKey, &sourceHash, &attempts) != nil || version != string(f.version) || attempts != 1 {
		t.Fatal("publication/withdrawal/recovery changed accepted version or recovery count")
	}
	if n, err := f.registry.CleanSources(context.Background(), 100); err != nil || n != 0 {
		t.Fatal("new terminal source ignored original retention window")
	}
	source, err := f.store.Read(context.Background(), storage.Object{Key: sourceKey, SHA256: sourceHash, SizeBytes: int64(len(request.SourceCode))}, contract.MaxSourceBytes)
	if err != nil || string(source) != request.SourceCode {
		t.Fatal("retained private source lost exact accepted bytes")
	}
	status, raw, err = f.call(context.Background(), http.MethodGet, "/internal/v2/problems/1/versions/"+string(f.version), acceptanceUUID(t), nil)
	history := acceptanceDecode[contract.PlatformProblemDetail](t, status, raw, err, 200)
	if history.Statement.Content != f.statement || history.License.SourceURL == "" {
		t.Fatal("privacy boundary removed contract-authorized historical statement or license source")
	}
	f.runtime.ready.Store(false)
	if f.submit(t, request, 200).JudgeTaskID != final.JudgeTaskID {
		t.Fatal("history replay depended on current execution readiness")
	}
	f.drainCallbacks(t)
}

func TestPortableAcceptanceCallbackFaultsRestartAndReconciliation(t *testing.T) {
	f := newAcceptanceFixture(t)
	request := f.request(t, contract.VerdictAC)
	accepted := f.submit(t, request, 202)
	initial := f.event(t, accepted.JudgeTaskID, 1)
	for _, code := range []callbacks.Code{callbacks.UnknownTask, callbacks.Unauthorized, callbacks.Conflict, callbacks.InvalidACK, callbacks.Unavailable} {
		f.backend.mu.Lock()
		f.backend.fault = ""
		f.backend.delay = false
		if code != callbacks.UnknownTask {
			f.backend.pending[request.RequestID] = request.SubmissionID
			if code == callbacks.Unavailable {
				f.backend.delay = true
			} else {
				f.backend.fault = code
			}
		}
		f.backend.mu.Unlock()
		f.exec(t, `UPDATE judge.callback_outbox SET next_attempt_at=clock_timestamp() WHERE event_id=$1`, string(initial.EventID))
		if did, err := f.callbacks.RunOnce(context.Background()); err != nil || !did {
			t.Fatal("callback fault was not durably attempted")
		}
		var state, lastCode string
		var hash string
		if f.db.Admin.QueryRow(`SELECT status,last_error_code,payload_hash FROM judge.callback_outbox WHERE event_id=$1`, string(initial.EventID)).Scan(&state, &lastCode, &hash) != nil || state != "PENDING" || lastCode != string(code) || hash != initial.PayloadHash {
			t.Fatal("failed callback was acknowledged, lost, or rewritten")
		}
	}
	f.backend.mu.Lock()
	f.backend.fault = ""
	f.backend.delay = false
	f.backend.dropACK = true
	f.backend.mu.Unlock()
	f.exec(t, `UPDATE judge.callback_outbox SET next_attempt_at=clock_timestamp() WHERE event_id=$1`, string(initial.EventID))
	if did, err := f.callbacks.RunOnce(context.Background()); err != nil || !did {
		t.Fatal("lost-ACK callback fixture failed")
	}
	f.backend.mu.Lock()
	f.backend.dropACK = false
	f.backend.mu.Unlock()
	f.exec(t, `UPDATE judge.callback_outbox SET next_attempt_at=clock_timestamp() WHERE event_id=$1`, string(initial.EventID))
	restarted, err := persistenceoutbox.New(f.db.Runtime)
	if err != nil {
		t.Fatal("cannot recreate durable dispatcher repository")
	}
	old, err := restarted.Claim(context.Background())
	if err != nil || old == nil {
		t.Fatal("cannot claim recoverable callback")
	}
	f.exec(t, `UPDATE judge.callback_outbox SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE event_id=$1`, string(initial.EventID))
	current, err := restarted.Claim(context.Background())
	if err != nil || current == nil || current.LeaseToken == old.LeaseToken || current.EventID != initial.EventID || current.PayloadHash != initial.PayloadHash {
		t.Fatal("dispatcher restart reused lease or regenerated original event")
	}
	if !errors.Is(restarted.Complete(context.Background(), old, callbacks.Outcome{Accepted: true}), callbacks.ErrLeaseLost) {
		t.Fatal("stale callback dispatcher acknowledged fresh lease")
	}
	out := f.backend.Send(context.Background(), current)
	if !out.Accepted || !out.Duplicate || restarted.Complete(context.Background(), current, out) != nil {
		t.Fatal("lost ACK did not reconcile through duplicate original event")
	}
	// Explicit operator-state fault injection covers reconciliation; the real
	// 24-hour classification/backoff clock is covered by outbox PG tests.
	if _, err := f.db.Admin.Exec(`UPDATE judge.callback_outbox SET status='DEAD_LETTER',delivered_at=NULL,last_error_code='CALLBACK_WINDOW_EXPIRED' WHERE event_id=$1`, string(initial.EventID)); err == nil {
		t.Fatal("delivered immutable callback regressed to dead letter")
	}
	manualRequest := f.request(t, contract.VerdictAC)
	f.backend.expect(manualRequest)
	manualTask := f.submit(t, manualRequest, 202)
	initial = f.event(t, manualTask.JudgeTaskID, 1)
	f.exec(t, `UPDATE judge.callback_outbox SET status='DEAD_LETTER',last_error_code='CALLBACK_WINDOW_EXPIRED' WHERE event_id=$1`, string(initial.EventID))
	operator, err := persistenceoutbox.New(f.db.Admin)
	if err != nil {
		t.Fatal("cannot compose isolated operator reconciliation")
	}
	if _, _, err := operator.ClaimReplay(context.Background(), initial.EventID, "acceptance-operator", persistenceoutbox.MappingReconciled); !errors.Is(err, callbacks.ErrPersistence) {
		t.Fatal("manual redelivery bypassed original 24-hour retry window")
	}
	historicalRequest := f.request(t, contract.VerdictAC)
	f.backend.expect(historicalRequest)
	initial = f.historicalEvent(t, manualTask, historicalRequest)
	if did, err := f.callbacks.RunOnce(context.Background()); err != nil || did {
		t.Fatal("expired original event was sent by automatic dispatcher")
	}
	dead, err := restarted.ListDeadLetters(context.Background(), 100, nil)
	if err != nil || len(dead) != 2 {
		t.Fatal("dead letter disappeared from bounded reconciliation inventory")
	}
	listed, _ := json.Marshal(dead)
	assertAcceptancePublic(t, listed)
	replay, receipt, err := operator.ClaimReplay(context.Background(), initial.EventID, "acceptance-operator", persistenceoutbox.MappingReconciled)
	if err != nil || replay == nil || replay.EventID != initial.EventID || replay.PayloadHash != initial.PayloadHash {
		t.Fatal("manual reconciliation rewrote original event")
	}
	if restarted.Complete(context.Background(), replay, f.backend.Send(context.Background(), replay)) != nil {
		t.Fatal("manual reconciliation did not complete immutable receipt")
	}
	var audited string
	if f.db.Admin.QueryRow(`SELECT status FROM judge.callback_redelivery_outcomes WHERE replay_id=$1`, string(receipt)).Scan(&audited) != nil || audited != "DELIVERED" {
		t.Fatal("manual delivery lacks append-only audited outcome")
	}
	assertAcceptancePublic(t, f.logs.Bytes())
}

func TestPortableAcceptanceFinalTransactionFailureRetainsRecoverableTask(t *testing.T) {
	f := newAcceptanceFixture(t)
	request := f.request(t, contract.VerdictWA)
	accepted := f.submit(t, request, 202)
	// The operator revokes only this isolated runtime role. The application never
	// mutates privileges or substitutes successful evidence for a failed commit.
	var role string
	if f.db.Runtime.QueryRow(`SELECT current_user`).Scan(&role) != nil {
		t.Fatal("cannot identify isolated test runtime role")
	}
	quoted := `"` + strings.ReplaceAll(role, `"`, `""`) + `"`
	f.exec(t, `REVOKE INSERT ON judge.judge_case_results FROM `+quoted)
	stop := f.startTaskWorker(t)
	f.awaitTask(t, accepted.JudgeTaskID, "RUNNING")
	deadline := time.Now().Add(3 * time.Second)
	for len(f.runtime.captured(request.SourceSHA256)) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	stop()
	var results, cases, terminalEvents int
	if f.db.Admin.QueryRow(`SELECT (SELECT count(*) FROM judge.judge_results),(SELECT count(*) FROM judge.judge_case_results),(SELECT count(*) FROM judge.callback_outbox WHERE payload->'payload'->>'status' IN('COMPLETED','FAILED'))`).Scan(&results, &cases, &terminalEvents) != nil || results != 0 || cases != 0 || terminalEvents != 0 {
		t.Fatal("failed final transaction left partial authoritative facts")
	}
	f.exec(t, `GRANT INSERT ON judge.judge_case_results TO `+quoted)
	f.exec(t, `UPDATE judge.judge_tasks SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, string(accepted.JudgeTaskID))
	stop = f.startTaskWorker(t)
	final := f.awaitTask(t, accepted.JudgeTaskID, "COMPLETED")
	stop()
	if final.Result == nil || final.Result.Verdict != contract.VerdictWA {
		t.Fatal("fresh recovery lost first failing case after transaction rollback")
	}
}
