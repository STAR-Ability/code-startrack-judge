package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
	"github.com/STAR-Ability/code-startrack-judge/internal/tasks"
)

const fatalStopPrivateDiagnostic = "private source, credential and worker diagnostic"

type fatalStopTaskRepository struct {
	mu                                            sync.Mutex
	leases                                        []*tasks.Lease
	claims, running, heartbeats, complete, failed int
}

func (r *fatalStopTaskRepository) Claim(context.Context) (*tasks.Lease, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.claims++
	if len(r.leases) == 0 {
		return nil, nil
	}
	lease := r.leases[0]
	r.leases = r.leases[1:]
	return lease, nil
}
func (r *fatalStopTaskRepository) Running(context.Context, *tasks.Lease) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.running++
	return nil
}
func (r *fatalStopTaskRepository) Heartbeat(context.Context, *tasks.Lease) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.heartbeats++
	return nil
}
func (r *fatalStopTaskRepository) Complete(context.Context, *tasks.Lease, judgeruntime.Outcome) (contract.JudgeTask, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.complete++
	return contract.JudgeTask{}, nil
}
func (r *fatalStopTaskRepository) Fail(context.Context, *tasks.Lease, string) (contract.JudgeTask, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failed++
	return contract.JudgeTask{}, nil
}
func (r *fatalStopTaskRepository) counts() [5]int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return [5]int{r.claims, r.running, r.heartbeats, r.complete, r.failed}
}

type fatalStopTaskExecutor struct {
	execute func(context.Context, judgeruntime.TaskInput, judgeruntime.ProgressFunc) (judgeruntime.Outcome, error)
}

func (fatalStopTaskExecutor) Snapshot(context.Context) judgeruntime.Snapshot {
	return judgeruntime.Snapshot{Qualified: true, SandboxReady: true, ToolchainReady: true}
}
func (e fatalStopTaskExecutor) Execute(ctx context.Context, input judgeruntime.TaskInput, progress judgeruntime.ProgressFunc) (judgeruntime.Outcome, error) {
	return e.execute(ctx, input, progress)
}

func applicationFatalStopWorker(t *testing.T, gate <-chan struct{}, execute func(context.Context, judgeruntime.TaskInput, judgeruntime.ProgressFunc) (judgeruntime.Outcome, error)) (*tasks.Worker, *fatalStopTaskRepository) {
	t.Helper()
	hash := sha256.Sum256([]byte("source"))
	repo := &fatalStopTaskRepository{}
	for range 2 {
		id, err := contract.NewUUID()
		if err != nil {
			t.Fatal(err)
		}
		token, err := contract.NewUUID()
		if err != nil {
			t.Fatal(err)
		}
		repo.leases = append(repo.leases, &tasks.Lease{Task: contract.JudgeTask{JudgeTaskID: id}, Token: token, SourceSHA256: hex.EncodeToString(hash[:]), Frozen: tasks.Frozen{SourceSizeBytes: 6}})
	}
	worker, err := tasks.NewWorker(tasks.WorkerOptions{Repository: repo, Executor: fatalStopTaskExecutor{execute: execute}, Source: func(context.Context, *tasks.Lease) ([]byte, error) { return []byte("source"), nil }, Concurrency: 1, PollInterval: time.Minute, ShutdownGrace: time.Minute, FatalStop: gate})
	if err != nil {
		t.Fatal(err)
	}
	return worker, repo
}

func closeApplicationFatalTestChannel(ch chan struct{}) {
	select {
	case <-ch:
	default:
		close(ch)
	}
}
func awaitApplicationFatalEvent(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("application worker did not complete the expected handshake")
	}
}
func awaitApplicationFatalError(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("application used healthy drain grace after a fatal worker stop")
		return nil
	}
}

func TestApplicationFatalStopAbortsRealTaskWorker(t *testing.T) {
	for _, phase := range []string{"active", "operator_grace"} {
		for _, mode := range []string{"error", "panic", "mixed_cancellation", "wrapped_cancellation"} {
			t.Run(phase+"/"+mode, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				gate := make(chan struct{})
				entered, companionReady, companionDraining := make(chan struct{}), make(chan struct{}), make(chan struct{})
				releaseFault, releaseAttempt := make(chan struct{}), make(chan struct{})
				attemptContext := make(chan context.Context, 1)
				attemptCanceled := make(chan error, 1)
				worker, repo := applicationFatalStopWorker(t, gate, func(attempt context.Context, _ judgeruntime.TaskInput, progress judgeruntime.ProgressFunc) (judgeruntime.Outcome, error) {
					if err := progress(attempt, judgeruntime.Progress{Type: "progress", Status: "Compiling"}); err != nil {
						return judgeruntime.Outcome{}, err
					}
					attemptContext <- attempt
					close(entered)
					select {
					case <-attempt.Done():
						attemptCanceled <- attempt.Err()
					case <-releaseAttempt:
					}
					return judgeruntime.Outcome{}, nil // Deliberately return late success.
				})
				app := application{fatalStop: gate, workers: []workerSpec{
					{code: "TASK_WORKER_STOPPED", run: worker.Run},
					{code: "COMPANION_WORKER_STOPPED", run: func(ctx context.Context) error {
						close(companionReady)
						if phase == "operator_grace" {
							<-ctx.Done()
							close(companionDraining)
						}
						<-releaseFault
						switch mode {
						case "panic":
							panic(fatalStopPrivateDiagnostic)
						case "mixed_cancellation":
							return errors.Join(context.Canceled, errors.New(fatalStopPrivateDiagnostic))
						case "wrapped_cancellation":
							return fmt.Errorf("%s: %w", fatalStopPrivateDiagnostic, context.Canceled)
						default:
							return errors.New(fatalStopPrivateDiagnostic)
						}
					}},
				}}
				t.Cleanup(func() {
					cancel()
					closeApplicationFatalTestChannel(releaseFault)
					closeApplicationFatalTestChannel(releaseAttempt)
				})
				notifications, wait := app.startWorkers(ctx)
				awaitApplicationFatalEvent(t, entered)
				awaitApplicationFatalEvent(t, companionReady)
				attempt := <-attemptContext
				if phase == "operator_grace" {
					cancel()
					awaitApplicationFatalEvent(t, companionDraining)
					if attempt.Err() != nil {
						t.Fatal("operator cancellation aborted accepted work before a companion fault")
					}
				}
				close(releaseFault)
				firstNotification := awaitApplicationFatalError(t, notifications)
				select {
				case <-gate:
				default:
					t.Fatal("worker failure notification preceded the application abort gate")
				}
				if !errors.Is(awaitApplicationFatalError(t, attemptCanceled), context.Canceled) {
					t.Fatal("companion failure did not cancel the task's detached attempt")
				}
				done := make(chan error, 1)
				go func() { done <- wait() }()
				if err := awaitApplicationFatalError(t, done); err == nil || err.Error() != "COMPANION_WORKER_STOPPED" {
					t.Fatal("secondary task failure replaced the original bounded companion failure")
				}
				seen := map[string]int{firstNotification.Error(): 1}
				for len(notifications) > 0 {
					seen[(<-notifications).Error()]++
				}
				if len(seen) != 2 || seen["COMPANION_WORKER_STOPPED"] != 1 || seen["TASK_WORKER_STOPPED"] != 1 {
					t.Fatal("application exposed private diagnostics or lost bounded worker notifications")
				}
				if retained := wait(); retained == nil || retained.Error() != "COMPANION_WORKER_STOPPED" {
					t.Fatal("consumed notification erased the original failure")
				}
				if repo.counts() != [5]int{1, 1, 0, 0, 0} {
					t.Fatal("companion fault acquired, renewed or finalized an aborted reservation")
				}
			})
		}
	}
}

func TestApplicationFatalStopExpectedCancellationPreservesRealTaskDrain(t *testing.T) {
	for _, mode := range []string{"nil", "direct_cancellation"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			gate, entered, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			companionStopped := make(chan struct{})
			attemptContext := make(chan context.Context, 1)
			worker, repo := applicationFatalStopWorker(t, gate, func(attempt context.Context, _ judgeruntime.TaskInput, progress judgeruntime.ProgressFunc) (judgeruntime.Outcome, error) {
				if err := progress(attempt, judgeruntime.Progress{Type: "progress", Status: "Compiling"}); err != nil {
					return judgeruntime.Outcome{}, err
				}
				attemptContext <- attempt
				close(entered)
				select {
				case <-attempt.Done():
					return judgeruntime.Outcome{}, attempt.Err()
				case <-release:
					return judgeruntime.Outcome{}, nil
				}
			})
			app := application{fatalStop: gate, workers: []workerSpec{
				{code: "TASK_WORKER_STOPPED", run: worker.Run},
				{code: "COMPANION_WORKER_STOPPED", run: func(ctx context.Context) error {
					<-ctx.Done()
					close(companionStopped)
					if mode == "direct_cancellation" {
						return ctx.Err()
					}
					return nil
				}},
			}}
			t.Cleanup(func() { cancel(); closeApplicationFatalTestChannel(release) })
			notifications, wait := app.startWorkers(ctx)
			awaitApplicationFatalEvent(t, entered)
			attempt := <-attemptContext
			cancel()
			awaitApplicationFatalEvent(t, companionStopped)
			if attempt.Err() != nil {
				t.Fatal("expected operator stop canceled an accepted attempt")
			}
			close(release)
			done := make(chan error, 1)
			go func() { done <- wait() }()
			if awaitApplicationFatalError(t, done) != nil || len(notifications) != 0 {
				t.Fatal("nil or direct cancellation became a worker fault")
			}
			select {
			case <-gate:
				t.Fatal("expected cancellation closed the fatal gate")
			default:
			}
			if repo.counts() != [5]int{1, 1, 0, 1, 0} {
				t.Fatal("expected cancellation prevented accepted completion or continued acquisition")
			}
		})
	}
}

func TestApplicationFatalStopConcurrentFaultsCloseOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gate, release := make(chan struct{}), make(chan struct{})
	started := make(chan struct{}, 8)
	app := application{fatalStop: gate}
	for i := range 8 {
		code := fmt.Sprintf("FIXED_WORKER_%d_STOPPED", i)
		app.workers = append(app.workers, workerSpec{code: code, run: func(context.Context) error {
			started <- struct{}{}
			<-release
			if i%2 == 0 {
				panic(fatalStopPrivateDiagnostic)
			}
			return errors.New(fatalStopPrivateDiagnostic)
		}})
	}
	t.Cleanup(func() { closeApplicationFatalTestChannel(release) })
	notifications, wait := app.startWorkers(ctx)
	for range 8 {
		awaitApplicationFatalEvent(t, started)
	}
	close(release)
	done := make(chan error, 1)
	go func() { done <- wait() }()
	first := awaitApplicationFatalError(t, done)
	awaitApplicationFatalEvent(t, gate)
	if first == nil || len(notifications) != 8 {
		t.Fatal("concurrent faults lost bounded failures")
	}
	seen := make(map[string]bool)
	for range 8 {
		code := (<-notifications).Error()
		if seen[code] {
			t.Fatal("concurrent fault produced a duplicate bounded report")
		}
		seen[code] = true
	}
	for i := range 8 {
		if !seen[fmt.Sprintf("FIXED_WORKER_%d_STOPPED", i)] {
			t.Fatal("concurrent fault exposed a private diagnostic")
		}
	}
	if !seen[first.Error()] || wait() != first {
		t.Fatal("concurrent faults did not retain their original bounded failure")
	}
}
