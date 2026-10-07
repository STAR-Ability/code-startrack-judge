package runtime

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
)

type testRouteTransport struct {
	base *url.URL
	next http.RoundTripper
}

func (t testRouteTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	copy := r.Clone(r.Context())
	u := *r.URL
	u.Scheme = t.base.Scheme
	u.Host = t.base.Host
	copy.URL = &u
	copy.Host = ""
	return t.next.RoundTrip(copy)
}
func schedulerFixture(t *testing.T) (*SchedulerClient, *Adapter, *mockFactory, memoryBlobs, string) {
	t.Helper()
	a, f, _, blobs := testAdapter(t)
	spool := privateTempDir(t)
	token := "scheduler-credential-abcdefghijklmnopqrstuvwxyz"
	handler, e := NewSchedulerServer(a, token, spool)
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	base, e := url.Parse(server.URL)
	if e != nil {
		t.Fatal(e)
	}
	c, e := newSchedulerClient(token, blobs, testRouteTransport{base: base, next: http.DefaultTransport})
	if e != nil {
		t.Fatal(e)
	}
	return c, a, f, blobs, spool
}
func TestSchedulerHandshakeWaitsForDurableAcknowledgment(t *testing.T) {
	c, a, f, blobs, spool := schedulerFixture(t)
	task := testTask(a, blobs, 1)
	before := len(f.requests)
	progressReceived := make(chan struct{})
	release := make(chan struct{})
	result := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var once sync.Once
	go func() {
		out, e := c.Execute(ctx, task, func(_ context.Context, p Progress) error {
			if p.Status == "Compiling" {
				once.Do(func() { close(progressReceived) })
				<-release
			}
			return nil
		})
		if e == nil && out.Result.Verdict != contract.VerdictAC {
			e = errors.New("wrong outcome")
		}
		result <- e
	}()
	select {
	case <-progressReceived:
	case <-ctx.Done():
		t.Fatal("progress not delivered")
	}
	f.mu.Lock()
	count := len(f.requests)
	f.mu.Unlock()
	if count != before {
		t.Fatal("compile dispatched before durable RUNNING ACK")
	}
	close(release)
	if e := <-result; e != nil {
		t.Fatal(e)
	}
	entries, e := os.ReadDir(spool)
	if e != nil || len(entries) != 0 {
		t.Fatal("private attempt spool survived terminal response")
	}
	if _, e = c.Execute(ctx, task, nil); e == nil {
		t.Fatal("duplicate scheduler fence dispatched")
	}
}
func TestSchedulerRejectedProgressPreventsExecution(t *testing.T) {
	c, a, f, blobs, _ := schedulerFixture(t)
	before := len(f.requests)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, e := c.Execute(ctx, testTask(a, blobs, 1), func(context.Context, Progress) error { return errors.New("fenced write rejected") })
	if e == nil {
		t.Fatal("rejected progress accepted")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) != before {
		t.Fatal("sandbox ran after rejected progress")
	}
}
func TestSchedulerSnapshotAndMissingBlobFailClosed(t *testing.T) {
	c, a, f, blobs, _ := schedulerFixture(t)
	snapshot := c.Snapshot(context.Background())
	if !snapshot.Qualified || len(snapshot.Languages.Languages) != 1 || snapshot.Identity != a.identity {
		t.Fatal("qualified identity not preserved")
	}
	task := testTask(a, blobs, 1)
	delete(blobs, task.Cases[0].Input.SHA256)
	before := len(f.requests)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, e := c.Execute(ctx, task, nil); e == nil {
		t.Fatal("missing private blob accepted")
	}
	if len(f.requests) != before {
		t.Fatal("missing-blob request dispatched")
	}
}
func TestSchedulerAuthenticationAndUnknownRoutes(t *testing.T) {
	a, _, _, _ := testAdapter(t)
	spool := privateTempDir(t)
	s, e := NewSchedulerServer(a, "scheduler-credential-abcdefghijklmnopqrstuvwxyz", spool)
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		path, token string
		want        int
	}{{"/snapshot", "", 401}, {"/snapshot", "wrong", 401}, {"/config", "scheduler-credential-abcdefghijklmnopqrstuvwxyz", 404}, {"/snapshot?secret=private", "scheduler-credential-abcdefghijklmnopqrstuvwxyz", 401}} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		req.Header.Set("Authorization", "Bearer "+tc.token)
		response := httptest.NewRecorder()
		s.ServeHTTP(response, req)
		if response.Code != tc.want || bytes.Contains(response.Body.Bytes(), []byte("credential-")) {
			t.Fatal("private route/authentication boundary failed")
		}
	}
}
func TestLedgerRetainsFenceAcrossReopen(t *testing.T) {
	directory := privateTempDir(t)
	ledger, e := NewFileLedger(directory)
	if e != nil {
		t.Fatal(e)
	}
	task := contract.UUID("11111111-1111-4111-8111-111111111111")
	fence := contract.UUID("22222222-2222-4222-8222-222222222222")
	if e = ledger.Begin(context.Background(), task, fence); e != nil {
		t.Fatal(e)
	}
	reopened, e := NewFileLedger(directory)
	if e != nil {
		t.Fatal(e)
	}
	if reopened.Begin(context.Background(), task, fence) == nil {
		t.Fatal("restarted judger reused fence")
	}
	info, e := os.Stat(filepath.Join(directory, string(fence)+"-judge.dispatch"))
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("dispatch reservation permissions incorrect")
	}
}
func TestInternalValidationUsesEveryCaseAndDoesNotInventValidators(t *testing.T) {
	a, f, _, blobs := testAdapter(t)
	task := testTask(a, blobs, 2)
	cpp := []byte("int main(){return 0;}\n")
	py := []byte("raise SystemExit(42)\n")
	cppRef := BlobRef{SHA256: canonical.HashBytes(cpp), SizeBytes: int64(len(cpp))}
	pyRef := BlobRef{SHA256: canonical.HashBytes(py), SizeBytes: int64(len(py))}
	blobs[cppRef.SHA256] = cpp
	blobs[pyRef.SHA256] = py
	f.checkerExits = []int{42, 43, 42, 42}
	input := ValidationInput{JobID: task.TaskID, ItemID: task.TaskID, FencingToken: task.FencingToken, Identity: a.identity, Limits: task.Limits, Cases: task.Cases, InputValidators: []Program{{File: pyRef, LanguageID: "python3"}}, AcceptedReferences: []Program{{File: cppRef, LanguageID: LanguageID}, {File: cppRef, LanguageID: LanguageID}}}
	out, e := a.ValidatePrograms(context.Background(), input)
	if e != nil {
		t.Fatal(e)
	}
	if !out.ValidatorsPassed || out.ReferencesPassed || len(out.ValidatorCases) != 2 || len(out.ReferenceCases) != 4 {
		t.Fatal("required exact validation flow incomplete")
	}
	input.FencingToken = "44444444-4444-4444-8444-444444444444"
	input.InputValidators = nil
	out, e = a.ValidatePrograms(context.Background(), input)
	if e != nil || out.ValidatorsPassed {
		t.Fatal("missing validator fabricated as passing")
	}
}
