package tasks

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
)

type workerRepository struct {
	mu                                sync.Mutex
	leases                            []*Lease
	claims, running, complete, failed int
	rejectAck                         bool
}

func (r *workerRepository) Claim(context.Context) (*Lease, error) {
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
func (r *workerRepository) Running(context.Context, *Lease) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.running++
	if r.rejectAck {
		return ErrLeaseLost
	}
	return nil
}
func (*workerRepository) Heartbeat(context.Context, *Lease) error { return nil }
func (r *workerRepository) Complete(context.Context, *Lease, judgeruntime.Outcome) (contract.JudgeTask, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.complete++
	return contract.JudgeTask{}, nil
}
func (r *workerRepository) Fail(context.Context, *Lease, string) (contract.JudgeTask, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failed++
	return contract.JudgeTask{}, nil
}
func (r *workerRepository) counts() (int, int, int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.claims, r.running, r.complete, r.failed
}

type workerExecutor struct {
	mu                sync.Mutex
	ready             bool
	called            map[contract.UUID]int
	active, maxActive int
	entered           chan struct{}
	release           chan struct{}
	ambiguous         bool
}

func (e *workerExecutor) Snapshot(context.Context) judgeruntime.Snapshot {
	return judgeruntime.Snapshot{Qualified: e.ready, SandboxReady: e.ready, ToolchainReady: e.ready}
}
func (e *workerExecutor) Execute(ctx context.Context, in judgeruntime.TaskInput, progress judgeruntime.ProgressFunc) (judgeruntime.Outcome, error) {
	e.mu.Lock()
	e.called[in.FencingToken]++
	e.active++
	if e.active > e.maxActive {
		e.maxActive = e.active
	}
	e.mu.Unlock()
	defer func() { e.mu.Lock(); e.active--; e.mu.Unlock() }()
	if err := progress(ctx, judgeruntime.Progress{Type: "progress", Status: "Compiling"}); err != nil {
		return judgeruntime.Outcome{}, &judgeruntime.Failure{Code: "DISPATCH_ACK_FAILED", Ambiguous: true}
	}
	if e.entered != nil {
		e.entered <- struct{}{}
	}
	if e.release != nil {
		select {
		case <-ctx.Done():
			return judgeruntime.Outcome{}, ctx.Err()
		case <-e.release:
		}
	}
	if e.ambiguous {
		return judgeruntime.Outcome{}, &judgeruntime.Failure{Code: "SANDBOX_OPERATION_UNCERTAIN", Ambiguous: true}
	}
	return judgeruntime.Outcome{}, nil
}
func workerLeases(n int) []*Lease {
	leases := make([]*Lease, n)
	hash, _ := canonical.HashSource("source")
	for i := range leases {
		id, _ := contract.NewUUID()
		token, _ := contract.NewUUID()
		leases[i] = &Lease{Task: contract.JudgeTask{JudgeTaskID: id}, Token: token, SourceSHA256: hash, Frozen: Frozen{SourceSizeBytes: 6}}
	}
	return leases
}
func workerSource(context.Context, *Lease) ([]byte, error) { return []byte("source"), nil }
func await(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not make expected progress")
	}
}

func TestWorkerBoundsConcurrencyAndStopsAcquisition(t *testing.T) {
	repo := &workerRepository{leases: workerLeases(8)}
	executor := &workerExecutor{ready: true, called: map[contract.UUID]int{}, entered: make(chan struct{}, 8), release: make(chan struct{})}
	worker, err := NewWorker(WorkerOptions{Repository: repo, Executor: executor, Source: workerSource, Concurrency: 2, PollInterval: 10 * time.Millisecond, ShutdownGrace: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = worker.Run(ctx); close(done) }()
	await(t, executor.entered)
	await(t, executor.entered)
	cancel()
	close(executor.release)
	await(t, done)
	claims, _, complete, failed := repo.counts()
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if claims != 2 || complete != 2 || failed != 0 || executor.maxActive != 2 {
		t.Fatalf("bounded drain counts claims=%d completed=%d failed=%d concurrent=%d", claims, complete, failed, executor.maxActive)
	}
	for _, count := range executor.called {
		if count != 1 {
			t.Fatal("fence dispatched more than once")
		}
	}
}
func TestWorkerUncertainAttemptAndRejectedAcknowledgement(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(map[bool]string{false: "uncertain", true: "rejected_ack"}[reject], func(t *testing.T) {
			repo := &workerRepository{leases: workerLeases(1), rejectAck: reject}
			executor := &workerExecutor{ready: true, called: map[contract.UUID]int{}, ambiguous: true}
			worker, err := NewWorker(WorkerOptions{Repository: repo, Executor: executor, Source: workerSource, Concurrency: 1, PollInterval: 10 * time.Millisecond, ShutdownGrace: time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			if worker.Run(ctx) != nil {
				t.Fatal("worker shutdown failed")
			}
			_, running, complete, failed := repo.counts()
			if running != 1 || complete != 0 || failed != 0 {
				t.Fatal("uncertain or unfenced attempt was finalized")
			}
			executor.mu.Lock()
			defer executor.mu.Unlock()
			for _, count := range executor.called {
				if count != 1 {
					t.Fatal("uncertain fence was retried")
				}
			}
		})
	}
}
func TestWorkerStopsWhenIsolationUnqualified(t *testing.T) {
	repo := &workerRepository{leases: workerLeases(1)}
	executor := &workerExecutor{called: map[contract.UUID]int{}}
	worker, _ := NewWorker(WorkerOptions{Repository: repo, Executor: executor, Source: workerSource, Concurrency: 1, PollInterval: 10 * time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_ = worker.Run(ctx)
	claims, _, _, _ := repo.counts()
	if claims != 0 || len(executor.called) != 0 {
		t.Fatal("unqualified isolation acquired new execution")
	}
}
