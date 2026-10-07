package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/STAR-Ability/code-startrack-judge/internal/admission"
	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	persistencetasks "github.com/STAR-Ability/code-startrack-judge/internal/persistence/tasks"
	"github.com/STAR-Ability/code-startrack-judge/internal/storage"
	"github.com/STAR-Ability/code-startrack-judge/internal/testutil/judgetask"
	"github.com/STAR-Ability/code-startrack-judge/internal/testutil/postgres"
)

// These tests use the real schema/registry/task transaction and a deliberately
// synthetic runtime qualification provider. They execute no submitted code and
// establish no Linux sandbox security claim.
func TestPostgresJudgeHTTPAdmissionRecovery(t *testing.T) {
	database := postgres.New(t)
	judgetask.Seed(t, database.Admin, 1)
	store, err := storage.New(filepath.Join(t.TempDir(), "private"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	registry, err := storage.NewRegistry(database.Runtime, store)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := persistencetasks.New(database.Runtime, registry)
	if err != nil {
		t.Fatal(err)
	}
	var qualified atomic.Bool
	qualified.Store(true)
	service, err := admission.New(admission.Options{Repository: repository, Sources: registry, Runtime: func(context.Context) (admission.RuntimeIdentity, bool, error) {
		return judgetask.Identity(), qualified.Load(), nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	handler := judgeRoutes(t, service)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	var request contract.JudgeTaskRequest
	consumerFixture(t, "judge-request.json", &request)
	version := contract.UUID("00000000-0000-0000-0000-000000000011")
	request.ProblemRef.ProblemID = "1"
	request.ProblemRef.ProblemVersionID = &version
	request.SubmissionID = "1"
	call := func(method, path string, id contract.UUID, body any) (int, []byte, error) {
		var encoded []byte
		if body != nil {
			var encodeErr error
			encoded, encodeErr = json.Marshal(body)
			if encodeErr != nil {
				return 0, nil, encodeErr
			}
		}
		r, err := http.NewRequest(method, server.URL+path, strings.NewReader(string(encoded)))
		if err != nil {
			return 0, nil, err
		}
		r.Header.Set("Authorization", "Bearer "+token())
		r.Header.Set("X-Request-Id", string(id))
		if body != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		response, err := server.Client().Do(r)
		if err != nil {
			return 0, nil, err
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(response.Body, contract.MaxResultBytes+1))
		return response.StatusCode, raw, err
	}
	const contenders = 12
	statuses := make(chan int, contenders)
	ids := make(chan contract.UUID, contenders)
	failures := make(chan string, contenders)
	var group sync.WaitGroup
	for range contenders {
		group.Add(1)
		go func() {
			defer group.Done()
			status, raw, err := call("POST", "/internal/v2/judge-tasks", request.RequestID, request)
			if err != nil {
				failures <- "HTTP transport"
				return
			}
			if status != http.StatusAccepted && status != http.StatusOK {
				var failure contract.ApiError
				if contract.DecodeJSON(raw, &failure) == nil {
					failures <- fmt.Sprintf("HTTP %d (%s)", status, failure.Error.Code)
				} else {
					failures <- fmt.Sprintf("HTTP %d (invalid error envelope)", status)
				}
				return
			}
			var response contract.ApiResponse[contract.JudgeTask]
			if err := contract.DecodeJSON(raw, &response); err != nil {
				failures <- fmt.Sprintf("HTTP %d (invalid task envelope)", status)
				return
			}
			statuses <- status
			ids <- response.Data.JudgeTaskID
		}()
	}
	group.Wait()
	close(statuses)
	close(ids)
	close(failures)
	for failure := range failures {
		t.Fatalf("concurrent HTTP admission failed: %s", failure)
	}
	created, replayed := 0, 0
	for status := range statuses {
		switch status {
		case http.StatusAccepted:
			created++
		case http.StatusOK:
			replayed++
		default:
			t.Fatalf("unexpected admission HTTP status %d", status)
		}
	}
	if created != 1 || replayed != contenders-1 {
		t.Fatalf("concurrent admission created=%d replayed=%d", created, replayed)
	}
	var taskID contract.UUID
	for id := range ids {
		if taskID == "" {
			taskID = id
		}
		if id != taskID {
			t.Fatal("concurrent acceptance returned more than one task")
		}
	}
	var tasks, events int
	if err := database.Admin.QueryRow(`SELECT (SELECT count(*) FROM judge.judge_tasks),(SELECT count(*) FROM judge.callback_outbox)`).Scan(&tasks, &events); err != nil {
		t.Fatal("cannot inspect durable task and event counts")
	}
	if tasks != 1 || events != 1 {
		t.Fatalf("acceptance not atomic: tasks=%d events=%d", tasks, events)
	}
	qualified.Store(false)
	status, raw, err := call("POST", "/internal/v2/judge-tasks", request.RequestID, request)
	if err != nil || status != 200 {
		t.Fatalf("accepted replay depends on new readiness: status=%d", status)
	}
	var replay contract.ApiResponse[contract.JudgeTask]
	if err := contract.DecodeJSON(raw, &replay); err != nil || replay.Data.JudgeTaskID != taskID {
		t.Fatal("accepted replay lost persisted task")
	}
	changed := request
	changed.SourceCode += "\r\n"
	changed.SourceSHA256, _ = canonical.HashSource(changed.SourceCode)
	status, raw, err = call("POST", "/internal/v2/judge-tasks", changed.RequestID, changed)
	if err != nil || status != 409 {
		t.Fatal("changed accepted input not rejected")
	}
	var conflict contract.ApiError
	if err := contract.DecodeJSON(raw, &conflict); err != nil || conflict.Error.Code != "IDEMPOTENCY_CONFLICT" {
		t.Fatal("wrong durable conflict projection")
	}
	duplicate := request
	duplicate.RequestID = "123e4567-e89b-12d3-a456-426614174003"
	status, _, err = call("POST", "/internal/v2/judge-tasks", duplicate.RequestID, duplicate)
	if err != nil || status != 409 {
		t.Fatal("fresh duplicate submission did not conflict during unavailability")
	}
	lookupID := contract.UUID("123e4567-e89b-12d3-a456-426614174004")
	missingID := contract.UUID("123e4567-e89b-12d3-a456-426614174005")
	status, raw, err = call("POST", "/internal/v2/judge-tasks/by-request", lookupID, contract.ByRequestRequest{RequestIDs: contract.Array[contract.UUID]{missingID, request.RequestID}})
	if err != nil || status != 200 {
		t.Fatal("by-request recovery failed")
	}
	var recovered contract.ApiResponse[contract.ByRequestResponse]
	if err := contract.DecodeJSON(raw, &recovered); err != nil || recovered.RequestID != lookupID || len(recovered.Data.Tasks) != 1 || recovered.Data.Tasks[0].RequestID != request.RequestID || len(recovered.Data.MissingRequestIDs) != 1 || recovered.Data.MissingRequestIDs[0] != missingID {
		t.Fatal("recovery mixed HTTP/original request identities or missing tasks")
	}
	status, raw, err = call("GET", "/internal/v2/judge-tasks/"+string(taskID), lookupID, nil)
	if err != nil || status != 200 {
		t.Fatal("historical task query unavailable")
	}
	if strings.Contains(string(raw), "sourceCode") || strings.Contains(string(raw), "objectKey") || strings.Contains(string(raw), "private/") {
		t.Fatal("private inputs leaked through task API")
	}
	if err := database.Admin.QueryRow(`SELECT (SELECT count(*) FROM judge.judge_tasks),(SELECT count(*) FROM judge.callback_outbox)`).Scan(&tasks, &events); err != nil || tasks != 1 || events != 1 {
		t.Fatal("replay/query created execution or callback side effects")
	}
}
