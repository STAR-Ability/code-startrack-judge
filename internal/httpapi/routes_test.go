package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
)

type judgeFixtureService struct {
	task                          contract.JudgeTask
	created                       bool
	submitted, queried, recovered int
	err                           error
}

func (s *judgeFixtureService) Submit(_ context.Context, _ contract.JudgeTaskRequest) (contract.JudgeTask, bool, error) {
	s.submitted++
	return s.task, s.created, s.err
}
func (s *judgeFixtureService) Get(_ context.Context, _ contract.UUID) (contract.JudgeTask, error) {
	s.queried++
	return s.task, s.err
}
func (s *judgeFixtureService) ByRequest(_ context.Context, _ contract.ByRequestRequest) (contract.ByRequestResponse, error) {
	s.recovered++
	return contract.ByRequestResponse{Tasks: contract.Array[contract.JudgeTask]{s.task}}, s.err
}
func consumerFixture(t *testing.T, name string, dst any) []byte {
	t.Helper()
	raw, e := os.ReadFile("../contract/testdata/" + name)
	if e != nil {
		t.Fatal(e)
	}
	if e := contract.DecodeJSON(raw, dst); e != nil {
		t.Fatal(e)
	}
	return raw
}
func judgeRoutes(t *testing.T, service JudgeService) http.Handler {
	t.Helper()
	return newHandler(t, func(m *http.ServeMux) { RegisterRoutes(m, Routes{Judge: service}) }, nil)
}

func TestJudgeRoutesUseSafeEnvelopesAndCreationStatuses(t *testing.T) {
	var task contract.JudgeTask
	consumerFixture(t, "queued-task.json", &task)
	var request contract.JudgeTaskRequest
	raw := consumerFixture(t, "judge-request.json", &request)
	service := &judgeFixtureService{task: task, created: true}
	h := judgeRoutes(t, service)
	for _, created := range []bool{true, false} {
		service.created = created
		w := httptest.NewRecorder()
		h.ServeHTTP(w, businessRequest("POST", "/internal/v2/judge-tasks", string(raw)))
		want := 200
		if created {
			want = 202
		}
		if w.Code != want {
			t.Fatalf("created %v status=%d: %s", created, w.Code, w.Body.String())
		}
		var response contract.ApiResponse[contract.JudgeTask]
		if e := contract.DecodeJSON(w.Body.Bytes(), &response); e != nil {
			t.Fatal(e)
		}
		if response.Data.JudgeTaskID != task.JudgeTaskID || response.RequestID != contract.UUID(testRequestID) {
			t.Fatal("task/envelope identity changed")
		}
		for _, private := range []string{"sourceCode", "sourceSha256", "command", "testCases", "private/"} {
			if strings.Contains(w.Body.String(), private) {
				t.Fatal("private execution input leaked")
			}
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, businessRequest("GET", "/internal/v2/judge-tasks/"+string(task.JudgeTaskID), ""))
	if w.Code != 200 || service.queried != 1 {
		t.Fatal("task GET missing")
	}
	byRequestID := "123e4567-e89b-12d3-a456-426614174005"
	r := businessRequest("POST", "/internal/v2/judge-tasks/by-request", `{"requestIds":["`+string(task.RequestID)+`"]}`)
	r.Header.Set("X-Request-Id", byRequestID)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var recovered contract.ApiResponse[contract.ByRequestResponse]
	if e := contract.DecodeJSON(w.Body.Bytes(), &recovered); e != nil {
		t.Fatal(e)
	}
	if recovered.RequestID != contract.UUID(byRequestID) || recovered.Data.Tasks[0].RequestID != task.RequestID {
		t.Fatal("recovery envelope confused original task requestId")
	}
}
func TestJudgeRouteBoundaryRejectsUnsafeInputBeforeService(t *testing.T) {
	var task contract.JudgeTask
	consumerFixture(t, "queued-task.json", &task)
	var request contract.JudgeTaskRequest
	raw := consumerFixture(t, "judge-request.json", &request)
	service := &judgeFixtureService{task: task, created: true}
	h := judgeRoutes(t, service)
	tests := []struct {
		method, path, body string
		code               string
	}{
		{"POST", "/internal/v2/judge-tasks?callbackUrl=http://attacker", string(raw), "INVALID_ARGUMENT"},
		{"POST", "/internal/v2/judge-tasks", strings.TrimSuffix(strings.TrimSpace(string(raw)), "}") + `,"commands":[]}`, "INVALID_ARGUMENT"},
		{"POST", "/internal/v2/judge-tasks", strings.Replace(string(raw), `"languageId": "cpp17"`, `"languageId": "python"`, 1), "LANGUAGE_NOT_SUPPORTED"},
		{"POST", "/internal/v2/judge-tasks", strings.Repeat(" ", int(contract.MaxJudgeRequestBytes)+1), "INPUT_TOO_LARGE"},
		{"GET", "/internal/v2/judge-tasks/not-uuid", "", "INVALID_ARGUMENT"},
		{"GET", "/internal/v2/judge-tasks/" + string(task.JudgeTaskID) + "?extra=1", "", "INVALID_ARGUMENT"},
		{"GET", "/internal/v2/judge-tasks/" + string(task.JudgeTaskID), "{}", "INVALID_ARGUMENT"},
		{"POST", "/internal/v2/judge-tasks/by-request", `{"requestIds":[]}`, "INVALID_ARGUMENT"},
		{"POST", "/internal/v2/judge-tasks/by-request", `{"requestIds":["` + testRequestID + `"],"requestId":"` + testRequestID + `"}`, "INVALID_ARGUMENT"},
	}
	for _, test := range tests {
		r := businessRequest(test.method, test.path, test.body)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if code := responseCode(t, w); code != test.code {
			t.Fatalf("%s %s code=%s body=%s", test.method, test.path, code, w.Body.String())
		}
	}
	if service.submitted != 0 || service.queried != 0 || service.recovered != 0 {
		t.Fatal("invalid request reached business service")
	}
}
func detailFixture() contract.PlatformProblemDetail {
	now := contract.Instant("2026-10-08T00:00:00Z")
	title := "Synthetic public problem"
	return contract.PlatformProblemDetail{PlatformProblemSummary: contract.PlatformProblemSummary{ProblemRef: contract.PlatformProblemRef{Source: contract.SourcePlatform, Platform: contract.PlatformStartrack, ProblemID: "1", ProblemVersionID: contract.UUID(testRequestID)}, Title: &title, DifficultyScale: contract.DifficultyUnrated, Status: contract.ProblemPublished, CatalogVersion: "1", TimeLimitMs: 1000, MemoryLimitBytes: 1048576, LanguageIDs: contract.Array[string]{"cpp17"}, UpdatedAt: now}, Statement: contract.Statement{Format: "MARKDOWN", Content: "# public statement"}, Samples: contract.Array[contract.Sample]{{Input: "sample", Output: "sample"}}, License: contract.License{Notice: "Synthetic", SourceURL: contract.PackageRepository}}
}

type fixtureDomainError struct{}

func (fixtureDomainError) Error() string      { return "SQL stack credential /private/tests" }
func (fixtureDomainError) PublicCode() string { return "PROBLEM_VERSION_CONFLICT" }
func TestManagementAndCatalogRoutesApplyDTOAndQueryRules(t *testing.T) {
	detail := detailFixture()
	listed := 0
	metadata := 0
	replay := false
	routes := Routes{
		ListProblems: func(_ context.Context, q ProblemListQuery) (contract.Array[contract.PlatformProblemSummary], contract.PageMeta, error) {
			listed++
			if q.Page != 2 || q.Q == nil || *q.Q != "hello" {
				t.Error("query mapping incorrect")
			}
			meta, _ := PageMeta(q.Pagination, 1)
			return nil, meta, nil
		},
		CurrentProblem: func(_ context.Context, id contract.ID) (contract.PlatformProblemDetail, error) {
			if id != "1" {
				t.Error("problem identity changed")
			}
			return detail, nil
		},
		ProblemVersion: func(context.Context, contract.ID, contract.UUID) (contract.PlatformProblemDetail, error) {
			return contract.PlatformProblemDetail{}, fixtureDomainError{}
		},
		MetadataVersion: func(_ context.Context, id contract.ID, request contract.MetadataVersionRequest) (contract.PlatformProblemDetail, bool, error) {
			metadata++
			if id != "1" || len(request.Tags) != 1 || request.Tags[0] != "a" {
				t.Error("metadata normalization incorrect")
			}
			return detail, replay, nil
		},
		CatalogPage: func(_ context.Context, cursor *string, limit contract.SafeInt) (contract.CatalogSnapshotPage, error) {
			if cursor != nil || limit != 100 {
				t.Error("catalog defaults changed")
			}
			return contract.CatalogSnapshotPage{SnapshotID: contract.UUID(testRequestID), CatalogVersion: "1", ExpiresAt: contract.Instant("2026-10-08T00:30:00Z")}, nil
		},
		Languages: func(context.Context) (contract.LanguageCapabilities, error) {
			return contract.LanguageCapabilities{}, &contract.ValidationError{Code: "JUDGE_UNAVAILABLE"}
		},
	}
	h := newHandler(t, func(m *http.ServeMux) { RegisterRoutes(m, routes) }, nil)
	for _, path := range []string{"/internal/v2/problems?page=2&q=%20hello%20", "/internal/v2/problems/1", "/internal/v2/catalog-snapshots"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, businessRequest("GET", path, ""))
		if w.Code != 200 || !json.Valid(w.Body.Bytes()) {
			t.Fatalf("GET %s: %s", path, w.Body.String())
		}
	}
	body := `{"requestId":"` + testRequestID + `","baseProblemVersionId":"` + testRequestID + `","tags":[" a ","a"],"difficulty":null,"difficultyScale":"UNRATED"}`
	for _, again := range []bool{false, true} {
		replay = again
		w := httptest.NewRecorder()
		h.ServeHTTP(w, businessRequest("POST", "/internal/v2/problems/1/metadata-versions", body))
		want := 201
		if again {
			want = 200
		}
		if w.Code != want {
			t.Fatalf("metadata status %d: %s", w.Code, w.Body.String())
		}
	}
	for _, path := range []string{"/internal/v2/problems/0", "/internal/v2/problems/1?private=1", "/internal/v2/catalog-snapshots?cursor="} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, businessRequest("GET", path, ""))
		if responseCode(t, w) != "INVALID_ARGUMENT" {
			t.Fatal("invalid management/query input admitted")
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, businessRequest("GET", "/internal/v2/problems/1/versions/"+testRequestID, ""))
	if responseCode(t, w) != "PROBLEM_VERSION_CONFLICT" || strings.Contains(w.Body.String(), "SQL") {
		t.Fatal("domain error not safely projected")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, businessRequest("GET", "/internal/v2/languages", ""))
	if w.Code != 503 {
		t.Fatal("unqualified languages advertised available")
	}
	if listed != 1 || metadata != 2 {
		t.Fatal("unexpected domain calls")
	}
}
