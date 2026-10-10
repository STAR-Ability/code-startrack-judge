package tasks

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
)

const privatePanicCanary = "synthetic-private-source-answer-token-panic"

type panicReviewExecutor struct {
	base     *workerExecutor
	snapshot bool
}

type panicPeerExecutor struct {
	entered   chan struct{}
	panicNow  chan struct{}
	cancelled chan struct{}
	calls     atomic.Int32
}

func (*panicPeerExecutor) Snapshot(context.Context) judgeruntime.Snapshot {
	return judgeruntime.Snapshot{Qualified: true, SandboxReady: true, ToolchainReady: true}
}

func (e *panicPeerExecutor) Execute(ctx context.Context, _ judgeruntime.TaskInput, progress judgeruntime.ProgressFunc) (judgeruntime.Outcome, error) {
	if err := progress(ctx, judgeruntime.Progress{Type: "progress", Status: "Compiling"}); err != nil {
		return judgeruntime.Outcome{}, err
	}
	first := e.calls.Add(1) == 1
	e.entered <- struct{}{}
	if first {
		<-e.panicNow
		panic(privatePanicCanary)
	}
	<-ctx.Done()
	close(e.cancelled)
	return judgeruntime.Outcome{}, ctx.Err()
}

func TestWorkerFaultCancelsPeerWithoutHealthyDrainGrace(t *testing.T) {
	for _, operatorStop := range []bool{false, true} {
		t.Run(map[bool]string{false: "fault", true: "fault_during_operator_stop"}[operatorStop], func(t *testing.T) {
			repo := &workerRepository{leases: workerLeases(4)}
			executor := &panicPeerExecutor{entered: make(chan struct{}, 2), panicNow: make(chan struct{}), cancelled: make(chan struct{})}
			worker, err := NewWorker(WorkerOptions{Repository: repo, Executor: executor, Source: workerSource, Concurrency: 2, PollInterval: 10 * time.Millisecond, ShutdownGrace: time.Minute})
			if err != nil {
				t.Fatal("cannot configure concurrent panic worker")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- worker.Run(ctx) }()
			await(t, executor.entered)
			await(t, executor.entered)
			if operatorStop {
				cancel()
			}
			close(executor.panicNow)
			select {
			case <-executor.cancelled:
			case <-time.After(3 * time.Second):
				t.Fatal("worker fault used the healthy one-minute drain window")
			}
			select {
			case err := <-done:
				if !errors.Is(err, ErrWorkerStopped) || strings.Contains(err.Error(), privatePanicCanary) {
					t.Fatal("worker fault lost its bounded failure during stop")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("faulted worker did not terminate after peer cancellation")
			}
			claims, running, completed, failed := repo.counts()
			if claims != 2 || running != 2 || completed != 0 || failed != 0 {
				t.Fatal("faulted workers acquired new work or finalized uncertain leases")
			}
		})
	}
}

func (e panicReviewExecutor) Snapshot(ctx context.Context) judgeruntime.Snapshot {
	if e.snapshot {
		panic(privatePanicCanary)
	}
	return e.base.Snapshot(ctx)
}
func (e panicReviewExecutor) Execute(ctx context.Context, _ judgeruntime.TaskInput, progress judgeruntime.ProgressFunc) (judgeruntime.Outcome, error) {
	if err := progress(ctx, judgeruntime.Progress{Type: "progress", Status: "Compiling"}); err != nil {
		return judgeruntime.Outcome{}, err
	}
	panic(privatePanicCanary)
}

func TestReviewNestedWorkerPanicStopsAcquisitionWithFixedError(t *testing.T) {
	for _, point := range []string{"source", "executor", "snapshot"} {
		t.Run(point, func(t *testing.T) {
			repo := &workerRepository{leases: workerLeases(4)}
			executor := Executor(panicReviewExecutor{base: &workerExecutor{ready: true}, snapshot: point == "snapshot"})
			source := SourceReader(workerSource)
			if point == "source" {
				source = func(context.Context, *Lease) ([]byte, error) { panic(privatePanicCanary) }
			}
			worker, err := NewWorker(WorkerOptions{Repository: repo, Executor: executor, Source: source, Concurrency: 1, PollInterval: 10 * time.Millisecond, ShutdownGrace: 10 * time.Millisecond})
			if err != nil {
				t.Fatal("cannot configure panic regression worker")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := worker.Run(ctx); !errors.Is(err, ErrWorkerStopped) || strings.Contains(err.Error(), privatePanicCanary) {
				t.Fatal("private panic did not terminate worker with a bounded fixed error")
			}
			claims, running, completed, failed := repo.counts()
			expectedClaims := 1
			if point == "snapshot" {
				expectedClaims = 0
			}
			expectedRunning := 0
			if point == "executor" {
				expectedRunning = 1
			}
			if claims != expectedClaims || running != expectedRunning || completed != 0 || failed != 0 {
				t.Fatal("panic retried acquisition or finalized an uncertain attempt")
			}
		})
	}
}
