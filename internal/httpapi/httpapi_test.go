package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
)

const testRequestID = "123e4567-e89b-12d3-a456-426614174000"

func token() string { return strings.Repeat("a", 32) }
func businessRequest(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token())
	r.Header.Set("X-Request-Id", testRequestID)
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	return r
}
func newHandler(t *testing.T, register func(*http.ServeMux), readiness ReadinessFunc) http.Handler {
	t.Helper()
	h, e := New(Options{BackendJudgeToken: token(), Register: register, Readiness: readiness})
	if e != nil {
		t.Fatal(e)
	}
	return h
}
func responseCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var e contract.ApiError
	if err := contract.DecodeJSON(w.Body.Bytes(), &e); err != nil {
		t.Fatalf("invalid error envelope: %s: %v", w.Body.String(), err)
	}
	if e.RequestID.Validate() != nil {
		t.Fatal("invalid response request identity")
	}
	if len(e.Error.Details) != 0 {
		t.Fatal("error details leak internal data")
	}
	return e.Error.Code
}
func TestAuthenticationAndRequestIdentity(t *testing.T) {
	h := newHandler(t, func(m *http.ServeMux) {
		m.HandleFunc("GET /internal/v2/fixture", func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Cookie") != "" {
				t.Error("cookie crossed business boundary")
			}
			WriteResponse(w, r, 200, map[string]bool{"ok": true})
		})
	}, nil)
	tests := map[string]struct {
		alter  func(*http.Request)
		status int
		code   string
	}{
		"missing bearer":          {func(r *http.Request) { r.Header.Del("Authorization") }, 401, "SERVICE_UNAUTHORIZED"},
		"wrong bearer":            {func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+strings.Repeat("b", 32)) }, 401, "SERVICE_UNAUTHORIZED"},
		"cookie only":             {func(r *http.Request) { r.Header.Del("Authorization"); r.Header.Set("Cookie", "session=synthetic") }, 401, "SERVICE_UNAUTHORIZED"},
		"duplicate bearer":        {func(r *http.Request) { r.Header.Add("Authorization", "Bearer "+token()) }, 401, "SERVICE_UNAUTHORIZED"},
		"missing identity":        {func(r *http.Request) { r.Header.Del("X-Request-Id") }, 400, "INVALID_ARGUMENT"},
		"malformed identity":      {func(r *http.Request) { r.Header.Set("X-Request-Id", "not-a-uuid") }, 400, "INVALID_ARGUMENT"},
		"duplicate identity":      {func(r *http.Request) { r.Header.Add("X-Request-Id", testRequestID) }, 400, "INVALID_ARGUMENT"},
		"cookie ignored with S2S": {func(r *http.Request) { r.Header.Set("Cookie", "session=synthetic") }, 200, ""},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			r := businessRequest("GET", "/internal/v2/fixture", "")
			test.alter(r)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != test.status {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if test.code != "" && responseCode(t, w) != test.code {
				t.Fatal("wrong error code")
			}
			if w.Header().Get("X-Request-Id") == "" {
				t.Fatal("missing response identity header")
			}
		})
	}
}
func TestStrictDecodeBodyAndSizeLimits(t *testing.T) {
	h := newHandler(t, func(m *http.ServeMux) {
		m.HandleFunc("POST /internal/v2/fixture", func(w http.ResponseWriter, r *http.Request) {
			var p contract.PublishRequest
			if e := DecodeBody(r, &p, 160); e != nil {
				WriteError(w, r, ErrorCode(e))
				return
			}
			WriteResponse(w, r, 200, p)
		})
	}, nil)
	valid := `{"requestId":"` + testRequestID + `","problemVersionId":"123e4567-e89b-12d3-a456-426614174001"}`
	tests := map[string]struct {
		body   string
		alter  func(*http.Request)
		status int
		code   string
	}{
		"valid": {valid, nil, 200, ""}, "mismatch": {strings.Replace(valid, testRequestID, "123e4567-e89b-12d3-a456-426614174002", 1), nil, 400, "INVALID_ARGUMENT"},
		"case mismatch before canonicalization": {strings.Replace(valid, testRequestID, strings.ToUpper(testRequestID), 1), nil, 400, "INVALID_ARGUMENT"},
		"unknown callback":                      {strings.TrimSuffix(valid, "}") + `,"callbackUrl":"http://a"}`, nil, 400, "INVALID_ARGUMENT"},
		"missing required":                      {`{"requestId":"` + testRequestID + `"}`, nil, 400, "INVALID_ARGUMENT"}, "null required": {strings.Replace(valid, `"problemVersionId":"123e4567-e89b-12d3-a456-426614174001"`, `"problemVersionId":null`, 1), nil, 400, "INVALID_ARGUMENT"},
		"duplicate field":   {strings.TrimSuffix(valid, "}") + `,"requestId":""}`, nil, 400, "INVALID_ARGUMENT"},
		"declared oversize": {strings.Repeat(" ", 161), nil, 413, "INPUT_TOO_LARGE"}, "streamed oversize": {strings.Repeat(" ", 161), func(r *http.Request) { r.ContentLength = -1 }, 413, "INPUT_TOO_LARGE"},
		"wrong content type": {valid, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, 400, "INVALID_ARGUMENT"}, "duplicate content type": {valid, func(r *http.Request) { r.Header.Add("Content-Type", "application/json") }, 400, "INVALID_ARGUMENT"}, "encoded body": {valid, func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }, 400, "INVALID_ARGUMENT"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			r := businessRequest("POST", "/internal/v2/fixture", test.body)
			if test.alter != nil {
				test.alter(r)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != test.status {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if test.code != "" && responseCode(t, w) != test.code {
				t.Fatal("wrong error code")
			}
		})
	}
	r := businessRequest("POST", "/internal/v2/fixture", strings.Replace(valid, testRequestID, strings.ToUpper(testRequestID), 1))
	r.Header.Set("X-Request-Id", strings.ToUpper(testRequestID))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("valid uppercase identity rejected: %s", w.Body.String())
	}
	var emitted contract.ApiResponse[contract.PublishRequest]
	if e := contract.DecodeJSON(w.Body.Bytes(), &emitted); e != nil {
		t.Fatal(e)
	}
	if w.Header().Get("X-Request-Id") != string(emitted.RequestID) {
		t.Fatal("response header and envelope identity diverged")
	}
}
func TestHealthIsRawAndCapabilityAdmissionIsIndependent(t *testing.T) {
	base := DependencyState{Database: true, PrivateStorage: true, Sandbox: true, Toolchain: true, Catalog: true, Judge: true, Imports: true}
	state := base
	readiness := func(context.Context) DependencyState { return state }
	h := newHandler(t, func(m *http.ServeMux) {
		m.Handle("POST /internal/v2/new-task", RequireCapability(readiness, Judge, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			WriteResponse(w, r, 202, map[string]bool{"accepted": true})
		})))
		m.HandleFunc("GET /internal/v2/history", func(w http.ResponseWriter, r *http.Request) {
			WriteResponse(w, r, 200, map[string]bool{"historical": true})
		})
	}, readiness)
	for _, fault := range []string{"none", "database", "storage", "sandbox", "toolchain", "unimplemented"} {
		t.Run(fault, func(t *testing.T) {
			state = base
			switch fault {
			case "database":
				state.Database = false
			case "storage":
				state.PrivateStorage = false
			case "sandbox":
				state.Sandbox = false
			case "toolchain":
				state.Toolchain = false
			case "unimplemented":
				state.Judge = false
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("GET", "/health", nil))
			want := 503
			if fault == "none" {
				want = 200
			}
			if w.Code != want {
				t.Fatalf("health status %d: %s", w.Code, w.Body.String())
			}
			var raw map[string]json.RawMessage
			if e := json.Unmarshal(w.Body.Bytes(), &raw); e != nil {
				t.Fatal(e)
			}
			if len(raw) != 4 || raw["data"] != nil || raw["requestId"] != nil {
				t.Fatalf("health envelope drift: %s", w.Body.String())
			}
			var health contract.Health
			if e := contract.DecodeJSON(w.Body.Bytes(), &health); e != nil {
				t.Fatal(e)
			}
			if health.Service != "judge-problem-service" || health.ContractVersion != "0.2.0" || health.Capabilities.Judge != (fault == "none") {
				t.Fatalf("untruthful health: %#v", health)
			}
			w = httptest.NewRecorder()
			h.ServeHTTP(w, businessRequest("POST", "/internal/v2/new-task", ""))
			if fault != "none" && w.Code != 503 {
				t.Fatal("new admission remained enabled")
			}
			w = httptest.NewRecorder()
			h.ServeHTTP(w, businessRequest("GET", "/internal/v2/history", ""))
			if w.Code != 200 {
				t.Fatal("historical reads unnecessarily disabled")
			}
		})
	}
	h = newHandler(t, nil, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/health", nil))
	if w.Code != 503 {
		t.Fatal("nil dependency adapter claimed readiness")
	}
}
func TestErrorsAndPanicsNeverLeakRawDiagnostics(t *testing.T) {
	h := newHandler(t, func(m *http.ServeMux) {
		m.HandleFunc("GET /internal/v2/panic", func(http.ResponseWriter, *http.Request) { panic("postgres://secret SQL stacktrace /private/answers") })
		m.HandleFunc("GET /internal/v2/error", func(w http.ResponseWriter, r *http.Request) { WriteError(w, r, ErrorCode(errors.New("secret SQL"))) })
		m.HandleFunc("GET /internal/v2/conflict", func(w http.ResponseWriter, r *http.Request) { WriteError(w, r, "REQUEST_IN_PROGRESS") })
	}, nil)
	for _, p := range []string{"panic", "error"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, businessRequest("GET", "/internal/v2/"+p, ""))
		if w.Code != 500 || responseCode(t, w) != "INTERNAL_ERROR" {
			t.Fatal("wrong internal error")
		}
		for _, secret := range []string{"secret", "SQL", "stacktrace", "/private"} {
			if strings.Contains(w.Body.String(), secret) {
				t.Fatal("raw diagnostics leaked")
			}
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, businessRequest("GET", "/internal/v2/conflict", ""))
	if w.Header().Get("Retry-After") != "2" {
		t.Fatal("in-progress retry header missing")
	}
}
func TestInvalidNestedDTOCannotBeSerialized(t *testing.T) {
	now := contract.Instant("2026-10-08T00:00:00Z")
	task := contract.JudgeTask{TaskBase: contract.TaskBase{RequestID: contract.UUID(testRequestID), Revision: 1, CreatedAt: now, UpdatedAt: now, FinishedAt: &now}, JudgeTaskID: contract.UUID(testRequestID), SubmissionID: "1", Status: contract.JudgeCompleted, Result: &contract.JudgeResult{Verdict: contract.VerdictCE, JudgedAt: now, CompileLog: new(strings.Repeat("x", contract.MaxCompileLogBytes+1))}}
	h := newHandler(t, func(m *http.ServeMux) {
		m.HandleFunc("GET /internal/v2/task", func(w http.ResponseWriter, r *http.Request) { WriteResponse(w, r, 200, task) })
	}, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, businessRequest("GET", "/internal/v2/task", ""))
	if w.Code != 500 || responseCode(t, w) != "INTERNAL_ERROR" {
		t.Fatal("invalid nested task serialized")
	}
}
func TestPostCommitPanicAbortsWithoutAppendingJSON(t *testing.T) {
	h := newHandler(t, func(m *http.ServeMux) {
		m.HandleFunc("GET /internal/v2/panic", func(w http.ResponseWriter, r *http.Request) {
			WriteResponse(w, r, 200, map[string]bool{"ok": true})
			panic("sensitive")
		})
	}, nil)
	w := httptest.NewRecorder()
	func() {
		defer func() {
			if v := recover(); v != http.ErrAbortHandler {
				t.Fatalf("post-commit panic not aborted: %v", v)
			}
		}()
		h.ServeHTTP(w, businessRequest("GET", "/internal/v2/panic", ""))
	}()
	if strings.Contains(w.Body.String(), "INTERNAL_ERROR") || !json.Valid(w.Body.Bytes()) {
		t.Fatal("recovery appended JSON to committed response")
	}
}
func TestReadinessAdapterDeadlineFailsClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	state := inspect(ctx, func(context.Context) DependencyState {
		return DependencyState{Database: true, PrivateStorage: true, Sandbox: true, Toolchain: true, Catalog: true, Judge: true, Imports: true}
	})
	if state != (DependencyState{}) {
		t.Fatal("expired check accepted capability")
	}
	var deadline time.Time
	_ = inspect(context.Background(), func(ctx context.Context) DependencyState { deadline, _ = ctx.Deadline(); return DependencyState{} })
	if deadline.IsZero() {
		t.Fatal("readiness check deadline missing")
	}
}
func TestQueryAndPaginationBoundaries(t *testing.T) {
	for _, raw := range []string{"page=0", "page=-1", "pageSize=101", "page=9007199254740991&pageSize=100", "page=1&page=2", "unknown=1", "q=%zz", "tag=%ff", "minDifficulty=2&maxDifficulty=1", "status=OTHER", "q=%20"} {
		if _, e := ParseProblemListQuery(raw); e == nil {
			t.Errorf("invalid query accepted %s", raw)
		}
	}
	q, e := ParseProblemListQuery("q=%20Hello%20&page=2&pageSize=20&minDifficulty=100&status=DRAFT")
	if e != nil {
		t.Fatal(e)
	}
	if *q.Q != "Hello" || q.Offset != 20 || q.Status != contract.ProblemDraft {
		t.Fatal("query normalization failed")
	}
	meta, e := PageMeta(q.Pagination, 40)
	if e != nil || meta.HasNext {
		t.Fatal("last-page boundary wrong")
	}
	meta, e = PageMeta(q.Pagination, 41)
	if e != nil || !meta.HasNext {
		t.Fatal("next-page boundary wrong")
	}
	for _, raw := range []string{"limit=0", "limit=1001", "cursor=", "cursor=a&cursor=b", "limit=2;limit=3"} {
		if _, e := ParseSnapshotQuery(raw); e == nil {
			t.Errorf("invalid snapshot query accepted %s", raw)
		}
	}
	if q, e := ParseSnapshotQuery(""); e != nil || q.Limit != 100 || q.Cursor != nil {
		t.Fatal("snapshot defaults wrong")
	}
}
