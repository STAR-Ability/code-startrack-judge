package tasks

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
)

type fatalStopExecutor struct {
	snapshot func(context.Context) judgeruntime.Snapshot
	execute  func(context.Context, judgeruntime.TaskInput, judgeruntime.ProgressFunc) (judgeruntime.Outcome, error)
}

func (e fatalStopExecutor) Snapshot(ctx context.Context) judgeruntime.Snapshot {
	if e.snapshot != nil {
		return e.snapshot(ctx)
	}
	return judgeruntime.Snapshot{Qualified: true, SandboxReady: true, ToolchainReady: true}
}
func (e fatalStopExecutor) Execute(ctx context.Context, input judgeruntime.TaskInput, progress judgeruntime.ProgressFunc) (judgeruntime.Outcome, error) {
	return e.execute(ctx, input, progress)
}

type fatalStopRepository struct {
	*workerRepository
	claim      func(context.Context) (*Lease, error)
	running    func(context.Context, *Lease) error
	heartbeat  func(context.Context, *Lease) error
	heartbeats atomic.Int32
}

func (r *fatalStopRepository) Claim(ctx context.Context) (*Lease, error) {
	if r.claim != nil {
		return r.claim(ctx)
	}
	return r.workerRepository.Claim(ctx)
}
func (r *fatalStopRepository) Running(ctx context.Context, lease *Lease) error {
	if r.running != nil {
		return r.running(ctx, lease)
	}
	return r.workerRepository.Running(ctx, lease)
}
func (r *fatalStopRepository) Heartbeat(ctx context.Context, lease *Lease) error {
	r.heartbeats.Add(1)
	if r.heartbeat != nil {
		return r.heartbeat(ctx, lease)
	}
	return nil
}

func closeFatalTestChannel(ch chan struct{}) {
	select {
	case <-ch:
	default:
		close(ch)
	}
}
func awaitFatalStop(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("worker used the healthy one-minute grace after fatal stop")
		return nil
	}
}

func TestWorkerFatalStopPreclosedRejectsAcquisition(t *testing.T) {
	repo := &workerRepository{leases: workerLeases(4)}
	var sources, executions atomic.Int32
	gate := make(chan struct{})
	close(gate)
	worker, err := NewWorker(WorkerOptions{Repository: repo, Executor: fatalStopExecutor{execute: func(context.Context, judgeruntime.TaskInput, judgeruntime.ProgressFunc) (judgeruntime.Outcome, error) {
		executions.Add(1)
		return judgeruntime.Outcome{}, nil
	}}, Source: func(ctx context.Context, lease *Lease) ([]byte, error) {
		sources.Add(1)
		return workerSource(ctx, lease)
	}, Concurrency: 2, FatalStop: gate})
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(worker.Run(context.Background()), ErrWorkerStopped) {
		t.Fatal("preclosed application gate did not return a bounded fatal stop")
	}
	claims, running, complete, failed := repo.counts()
	if claims != 0 || running != 0 || complete != 0 || failed != 0 || sources.Load() != 0 || executions.Load() != 0 {
		t.Fatal("preclosed application gate acquired or executed a task")
	}
}

func TestWorkerFatalStopPreservesReadiness(t *testing.T) {
	for _, missing := range []string{"qualification", "sandbox", "toolchain"} {
		t.Run(missing, func(t *testing.T) {
			repo := &workerRepository{leases: workerLeases(1)}
			measured := make(chan struct{}, 1)
			gate := make(chan struct{})
			executor := fatalStopExecutor{snapshot: func(context.Context) judgeruntime.Snapshot {
				select {
				case measured <- struct{}{}:
				default:
				}
				return judgeruntime.Snapshot{Qualified: missing != "qualification", SandboxReady: missing != "sandbox", ToolchainReady: missing != "toolchain"}
			}}
			worker, err := NewWorker(WorkerOptions{Repository: repo, Executor: executor, Source: workerSource, Concurrency: 1, PollInterval: time.Minute, FatalStop: gate})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- worker.Run(ctx) }()
			await(t, measured)
			cancel()
			if awaitFatalStop(t, done) != nil {
				t.Fatal("operator stop of an unqualified worker became a fatal stop")
			}
			claims, _, _, _ := repo.counts()
			if claims != 0 {
				t.Fatal("application gate bypassed measured readiness")
			}
		})
	}
}

func TestWorkerFatalStopAcquisitionRacesRetainReservations(t *testing.T) {
	for _, point := range []string{"snapshot", "claim"} {
		t.Run(point, func(t *testing.T) {
			repo := &fatalStopRepository{workerRepository: &workerRepository{leases: workerLeases(1)}}
			gate, entered, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var sources, executions atomic.Int32
			executor := fatalStopExecutor{execute: func(context.Context, judgeruntime.TaskInput, judgeruntime.ProgressFunc) (judgeruntime.Outcome, error) {
				executions.Add(1)
				return judgeruntime.Outcome{}, nil
			}}
			if point == "snapshot" {
				executor.snapshot = func(context.Context) judgeruntime.Snapshot {
					close(entered)
					<-release
					return judgeruntime.Snapshot{Qualified: true, SandboxReady: true, ToolchainReady: true}
				}
			} else {
				repo.claim = func(ctx context.Context) (*Lease, error) {
					close(entered)
					<-release
					return repo.workerRepository.Claim(ctx)
				}
			}
			worker, err := NewWorker(WorkerOptions{Repository: repo, Executor: executor, Source: func(ctx context.Context, lease *Lease) ([]byte, error) {
				sources.Add(1)
				return workerSource(ctx, lease)
			}, Concurrency: 1, ShutdownGrace: time.Minute, FatalStop: gate})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { closeFatalTestChannel(gate); closeFatalTestChannel(release) })
			done := make(chan error, 1)
			go func() { done <- worker.Run(context.Background()) }()
			await(t, entered)
			close(gate)
			close(release)
			if !errors.Is(awaitFatalStop(t, done), ErrWorkerStopped) {
				t.Fatal("late acquisition response concealed fatal stop")
			}
			claims, running, complete, failed := repo.counts()
			wantClaims := 0
			if point == "claim" {
				wantClaims = 1
			}
			if claims != wantClaims || running != 0 || complete != 0 || failed != 0 || sources.Load() != 0 || executions.Load() != 0 {
				t.Fatal("late acquisition response dispatched or finalized a reservation")
			}
		})
	}
}

func TestWorkerFatalStopCancelsDetachedAttemptsDuringGrace(t *testing.T) {
	for _, operatorStop := range []bool{false, true} {
		t.Run(map[bool]string{false: "active", true: "operator_grace"}[operatorStop], func(t *testing.T) {
			repo := &workerRepository{leases: workerLeases(4)}
			gate, entered, cancelled := make(chan struct{}), make(chan struct{}, 2), make(chan struct{}, 2)
			executor := fatalStopExecutor{execute: func(ctx context.Context, _ judgeruntime.TaskInput, progress judgeruntime.ProgressFunc) (judgeruntime.Outcome, error) {
				if err := progress(ctx, judgeruntime.Progress{Type: "progress", Status: "Compiling"}); err != nil {
					return judgeruntime.Outcome{}, err
				}
				entered <- struct{}{}
				<-ctx.Done()
				cancelled <- struct{}{}
				return judgeruntime.Outcome{}, ctx.Err()
			}}
			worker, err := NewWorker(WorkerOptions{Repository: repo, Executor: executor, Source: workerSource, Concurrency: 2, ShutdownGrace: time.Minute, FatalStop: gate})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			t.Cleanup(func() { closeFatalTestChannel(gate) })
			done := make(chan error, 1)
			go func() { done <- worker.Run(ctx) }()
			await(t, entered)
			await(t, entered)
			if operatorStop {
				cancel()
			}
			close(gate)
			if !errors.Is(awaitFatalStop(t, done), ErrWorkerStopped) || len(cancelled) != 2 {
				t.Fatal("application fatal stop did not abort both detached attempts")
			}
			claims, running, complete, failed := repo.counts()
			if claims != 2 || running != 2 || complete != 0 || failed != 0 {
				t.Fatal("fatal stop acquired new work or finalized uncertain attempts")
			}
		})
	}
}

func TestWorkerFatalStopRejectsLateSource(t *testing.T) {
	for _, late := range []string{"size", "checksum", "error"} {
		t.Run(late, func(t *testing.T) {
			repo := &workerRepository{leases: workerLeases(1)}
			gate, entered := make(chan struct{}), make(chan struct{})
			var executions atomic.Int32
			executor := fatalStopExecutor{execute: func(context.Context, judgeruntime.TaskInput, judgeruntime.ProgressFunc) (judgeruntime.Outcome, error) {
				executions.Add(1)
				return judgeruntime.Outcome{}, nil
			}}
			worker, err := NewWorker(WorkerOptions{Repository: repo, Executor: executor, Source: func(ctx context.Context, _ *Lease) ([]byte, error) {
				close(entered)
				<-ctx.Done()
				if late == "error" {
					return nil, errors.New(privatePanicCanary)
				}
				if late == "size" {
					return []byte("short"), nil
				}
				return []byte("mutate"), nil
			}, Concurrency: 1, FatalStop: gate})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { closeFatalTestChannel(gate) })
			done := make(chan error, 1)
			go func() { done <- worker.Run(context.Background()) }()
			await(t, entered)
			close(gate)
			if !errors.Is(awaitFatalStop(t, done), ErrWorkerStopped) {
				t.Fatal("late source response erased fatal stop")
			}
			_, running, complete, failed := repo.counts()
			if running != 0 || complete != 0 || failed != 0 || executions.Load() != 0 {
				t.Fatal("late source response dispatched or failed an aborted reservation")
			}
		})
	}
}

func TestWorkerFatalStopRejectsLateExecutionAndDetachedProgress(t *testing.T) {
	for _, late := range []string{"success", "error", "running_progress", "heartbeat_progress"} {
		t.Run(late, func(t *testing.T) {
			repo := &fatalStopRepository{workerRepository: &workerRepository{leases: workerLeases(1)}}
			gate, entered := make(chan struct{}), make(chan struct{})
			progressResult := make(chan error, 1)
			acknowledge := late != "running_progress"
			executor := fatalStopExecutor{execute: func(ctx context.Context, _ judgeruntime.TaskInput, progress judgeruntime.ProgressFunc) (judgeruntime.Outcome, error) {
				if acknowledge {
					if err := progress(ctx, judgeruntime.Progress{Type: "progress", Status: "Compiling"}); err != nil {
						return judgeruntime.Outcome{}, err
					}
				}
				close(entered)
				<-ctx.Done()
				if late == "running_progress" || late == "heartbeat_progress" {
					progressResult <- progress(context.Background(), judgeruntime.Progress{Type: "progress", Status: "Compiling"})
				}
				if late == "error" {
					return judgeruntime.Outcome{}, errors.New(privatePanicCanary)
				}
				return judgeruntime.Outcome{}, nil
			}}
			worker, err := NewWorker(WorkerOptions{Repository: repo, Executor: executor, Source: workerSource, Concurrency: 1, FatalStop: gate})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { closeFatalTestChannel(gate) })
			done := make(chan error, 1)
			go func() { done <- worker.Run(context.Background()) }()
			await(t, entered)
			close(gate)
			if !errors.Is(awaitFatalStop(t, done), ErrWorkerStopped) {
				t.Fatal("late execution response erased fatal stop")
			}
			_, running, complete, failed := repo.counts()
			wantRunning := 0
			if acknowledge {
				wantRunning = 1
			}
			if running != wantRunning || complete != 0 || failed != 0 || repo.heartbeats.Load() != 0 {
				t.Fatal("late execution response renewed or finalized an aborted attempt")
			}
			if len(progressResult) > 0 && !errors.Is(<-progressResult, context.Canceled) {
				t.Fatal("detached progress ignored its own attempt cancellation")
			}
		})
	}
}

func TestWorkerFatalStopCancelsDetachedProgressPersistence(t *testing.T) {
	for _, operation := range []string{"running", "heartbeat"} {
		t.Run(operation, func(t *testing.T) {
			repo := &fatalStopRepository{workerRepository: &workerRepository{leases: workerLeases(1)}}
			gate, entered := make(chan struct{}), make(chan struct{})
			writeResult := make(chan error, 1)
			blocked := func(ctx context.Context, _ *Lease) error {
				close(entered)
				<-ctx.Done()
				writeResult <- ctx.Err()
				return ctx.Err()
			}
			if operation == "running" {
				repo.running = blocked
			} else {
				repo.heartbeat = blocked
			}
			executor := fatalStopExecutor{execute: func(ctx context.Context, _ judgeruntime.TaskInput, progress judgeruntime.ProgressFunc) (judgeruntime.Outcome, error) {
				if operation == "heartbeat" {
					if err := progress(ctx, judgeruntime.Progress{Type: "progress", Status: "Compiling"}); err != nil {
						return judgeruntime.Outcome{}, err
					}
				}
				err := progress(context.Background(), judgeruntime.Progress{Type: "progress", Status: "Compiling"})
				return judgeruntime.Outcome{}, err
			}}
			worker, err := NewWorker(WorkerOptions{Repository: repo, Executor: executor, Source: workerSource, Concurrency: 1, FatalStop: gate})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { closeFatalTestChannel(gate) })
			done := make(chan error, 1)
			go func() { done <- worker.Run(context.Background()) }()
			await(t, entered)
			close(gate)
			if !errors.Is(awaitFatalStop(t, done), ErrWorkerStopped) || !errors.Is(<-writeResult, context.Canceled) {
				t.Fatal("detached progress persistence did not receive attempt cancellation")
			}
			_, _, complete, failed := repo.counts()
			if complete != 0 || failed != 0 {
				t.Fatal("aborted progress persistence created a terminal write")
			}
		})
	}
}

func TestWorkerFatalStopProgressRetainsCallbackDeadline(t *testing.T) {
	repo := &fatalStopRepository{workerRepository: &workerRepository{leases: workerLeases(1)}}
	gate, entered := make(chan struct{}), make(chan struct{})
	deadline := time.Now().Add(time.Hour)
	progressCtx, cancelProgress := context.WithDeadline(context.Background(), deadline)
	defer cancelProgress()
	writeResult := make(chan error, 1)
	observedDeadline := make(chan time.Time, 1)
	repo.running = func(ctx context.Context, _ *Lease) error {
		actual, _ := ctx.Deadline()
		observedDeadline <- actual
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	}
	executor := fatalStopExecutor{execute: func(_ context.Context, _ judgeruntime.TaskInput, progress judgeruntime.ProgressFunc) (judgeruntime.Outcome, error) {
		writeResult <- progress(progressCtx, judgeruntime.Progress{Type: "progress", Status: "Compiling"})
		return judgeruntime.Outcome{}, &judgeruntime.Failure{Code: "DISPATCH_ACK_FAILED", Ambiguous: true}
	}}
	worker, err := NewWorker(WorkerOptions{Repository: repo, Executor: executor, Source: workerSource, Concurrency: 1, PollInterval: time.Minute, FatalStop: gate})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	await(t, entered)
	if !deadline.Equal(<-observedDeadline) {
		t.Fatal("attempt cancellation propagation discarded the progress deadline")
	}
	cancelProgress()
	if !errors.Is(awaitFatalStop(t, writeResult), context.Canceled) {
		t.Fatal("progress persistence ignored callback cancellation")
	}
	cancel()
	if awaitFatalStop(t, done) != nil {
		t.Fatal("callback cancellation became an application fatal stop")
	}
	_, _, complete, failed := repo.counts()
	if complete != 0 || failed != 0 {
		t.Fatal("uncertain acknowledgment created a terminal write")
	}
}

func TestWorkerFatalStopOpenOrNilPreservesHealthyDrain(t *testing.T) {
	for _, configured := range []bool{false, true} {
		t.Run(map[bool]string{false: "nil", true: "open"}[configured], func(t *testing.T) {
			repo := &workerRepository{leases: workerLeases(2)}
			executor := &workerExecutor{ready: true, called: map[contract.UUID]int{}, entered: make(chan struct{}, 1), release: make(chan struct{})}
			var gate chan struct{}
			if configured {
				gate = make(chan struct{})
			}
			worker, err := NewWorker(WorkerOptions{Repository: repo, Executor: executor, Source: workerSource, Concurrency: 1, ShutdownGrace: time.Minute, FatalStop: gate})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			t.Cleanup(func() { closeFatalTestChannel(executor.release) })
			done := make(chan error, 1)
			go func() { done <- worker.Run(ctx) }()
			await(t, executor.entered)
			cancel()
			close(executor.release)
			if awaitFatalStop(t, done) != nil {
				t.Fatal("healthy operator drain became a fatal stop")
			}
			claims, running, complete, failed := repo.counts()
			if claims != 1 || running != 1 || complete != 1 || failed != 0 {
				t.Fatal("open fatal gate prevented healthy completion or continued acquisition")
			}
		})
	}
}
