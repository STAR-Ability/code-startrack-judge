package tasks

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
)

const privatePanicCanary = "synthetic-private-source-answer-token-panic"

type panicReviewExecutor struct {
	base     *workerExecutor
	snapshot bool
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
