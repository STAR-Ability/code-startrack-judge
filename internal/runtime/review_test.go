package runtime

import (
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

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/runtime/restclient"
)

// Independent review wrappers inject changes after an operation's initial
// readiness check, without editing the engine or its existing mock fixture.
type reviewFactory struct {
	base   SessionFactory
	upload func()
	run    func(context.Context, restclient.Request) error
}

func (f reviewFactory) NewSession() Session {
	return reviewSession{Session: f.base.NewSession(), factory: f}
}

type reviewSession struct {
	Session
	factory reviewFactory
}

func (s reviewSession) Upload(ctx context.Context, data []byte) (restclient.FileID, error) {
	id, err := s.Session.Upload(ctx, data)
	if err == nil && s.factory.upload != nil {
		s.factory.upload()
	}
	return id, err
}
func (s reviewSession) Run(ctx context.Context, request restclient.Request) ([]restclient.Result, error) {
	if s.factory.run != nil {
		if err := s.factory.run(ctx, request); err != nil {
			return nil, err
		}
	}
	return s.Session.Run(ctx, request)
}

func TestReviewInstanceFailureDuringUploadsPreventsDispatch(t *testing.T) {
	a, f, verifier, blobs := testAdapter(t)
	task := testTask(a, blobs, 1)
	before := len(f.requests)
	var once sync.Once
	a.factory = reviewFactory{base: f, upload: func() { once.Do(func() { verifier.mu.Lock(); verifier.fail = true; verifier.mu.Unlock() }) }}
	out, err := a.Execute(context.Background(), task, func(context.Context, Progress) error { return nil })
	if err == nil && out.Result.Verdict != contract.VerdictIE {
		t.Fatal("instance failure after uploads was accepted")
	}
	f.mu.Lock()
	after := len(f.requests)
	f.mu.Unlock()
	if after != before {
		t.Fatal("sandbox dispatched after isolation failed during uploads")
	}
	if a.Snapshot(context.Background()).Qualified {
		t.Fatal("failed isolation remained ready")
	}
}

func TestReviewQualificationRefreshPreservesLiveSameInstance(t *testing.T) {
	a, f, _, blobs := testAdapter(t)
	task := testTask(a, blobs, 1)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	a.factory = reviewFactory{base: f, run: func(ctx context.Context, request restclient.Request) error {
		args := request.Commands[0].Args
		if len(args) == 2 && args[0] == "/usr/bin/g++" && args[1] == "--version" {
			once.Do(func() { close(entered) })
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- a.Qualify(ctx) }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("refresh did not reach compiler probe")
	}
	qualified := a.Snapshot(ctx).Qualified
	out, executionError := a.Execute(ctx, task, func(context.Context, Progress) error { return nil })
	close(release)
	qualificationError := <-result
	if !qualified || executionError != nil || out.Result.Verdict != contract.VerdictAC || qualificationError != nil {
		t.Fatal("normal same-instance qualification refresh interrupted active execution")
	}
}

func TestReviewDefinitiveIEPreservesExecutedCasesAcrossIPC(t *testing.T) {
	client, a, _, blobs, spool := schedulerFixture(t)
	task := testTask(a, blobs, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := client.Execute(ctx, task, func(_ context.Context, p Progress) error {
		if p.Status == "Judging" && p.Ordinal == 2 {
			entries, err := os.ReadDir(spool)
			if err != nil || len(entries) != 1 {
				return errors.New("isolated spool unavailable")
			}
			if os.Remove(filepath.Join(spool, entries[0].Name(), task.Cases[1].Input.SHA256)) != nil {
				return errors.New("cannot inject isolated input failure")
			}
		}
		return nil
	})
	if err != nil || out.Result.Verdict != contract.VerdictIE || out.Error == nil || out.Result.PassedTestCount != 1 || len(out.Cases) != 1 || out.Cases[0].Verdict != contract.VerdictAC {
		t.Fatal("definitive post-case IE lost authoritative current-attempt facts across IPC")
	}
}

func reviewScheduler(t *testing.T) (*SchedulerClient, *SchedulerServer, *Adapter, memoryBlobs) {
	t.Helper()
	a, _, _, blobs := testAdapter(t)
	token := "scheduler-review-credential-abcdefghijklmnopqrstuvwxyz"
	handler, err := NewSchedulerServer(a, token, privateTempDir(t))
	if err != nil {
		t.Fatal("cannot configure independent scheduler fixture")
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	base, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal("cannot locate independent scheduler fixture")
	}
	client, err := newSchedulerClient(token, blobs, testRouteTransport{base: base, next: http.DefaultTransport})
	if err != nil {
		t.Fatal("cannot configure independent scheduler client")
	}
	t.Cleanup(client.Close)
	return client, handler, a, blobs
}

func TestReviewConcurrentSchedulerRequestWaitsForActiveAttempt(t *testing.T) {
	client, handler, a, blobs := reviewScheduler(t)
	first := testTask(a, blobs, 1)
	second := testTask(a, blobs, 1)
	second.TaskID = "55555555-5555-4555-8555-555555555555"
	second.FencingToken = "66666666-6666-4666-8666-666666666666"
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	type result struct {
		out Outcome
		err error
	}
	firstResult := make(chan result, 1)
	go func() {
		out, err := client.Execute(ctx, first, func(ctx context.Context, p Progress) error {
			if p.Status == "Compiling" {
				close(entered)
				select {
				case <-release:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		})
		firstResult <- result{out, err}
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("first scheduler request never reached durable progress")
	}
	secondResult := make(chan result, 1)
	go func() {
		out, err := client.Execute(ctx, second, func(context.Context, Progress) error { return nil })
		secondResult <- result{out, err}
	}()
	deadline := time.Now().Add(2 * time.Second)
	for len(handler.waiters) != 2 && time.Now().Before(deadline) {
		select {
		case <-secondResult:
			t.Fatal("normal concurrent scheduler request was rejected before active attempt finished")
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(handler.waiters) != 2 {
		t.Fatal("concurrent scheduler request never entered bounded queue")
	}
	releaseOnce.Do(func() { close(release) })
	for _, completion := range []result{<-firstResult, <-secondResult} {
		if completion.err != nil || completion.out.Result.Verdict != contract.VerdictAC {
			t.Fatal("queued scheduler request did not execute after active attempt drained")
		}
	}
}

func TestReviewSpoolCleanupFailureSuppressesSuccessAndLatchesReadiness(t *testing.T) {
	client, handler, a, blobs := reviewScheduler(t)
	handler.removeSpool = func(string) error { return errors.New("independent private cleanup fault") }
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := client.Execute(ctx, testTask(a, blobs, 1), func(context.Context, Progress) error { return nil })
	var failure *Failure
	if !errors.As(err, &failure) || failure.Code != "SCHEDULER_SPOOL_CLEANUP_FAILED" || !failure.Ambiguous {
		t.Fatal("failed private cleanup emitted an authoritative successful outcome")
	}
	if client.Snapshot(ctx).Qualified || a.Snapshot(ctx).Qualified {
		t.Fatal("failed private cleanup left scheduler ready")
	}
	if a.Qualify(ctx) == nil || a.Snapshot(ctx).Qualified {
		t.Fatal("normal qualification cleared a private cleanup fault without restart")
	}
}
