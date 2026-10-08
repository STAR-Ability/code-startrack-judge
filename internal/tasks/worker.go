package tasks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
)

type Executor interface {
	Snapshot(context.Context) judgeruntime.Snapshot
	Execute(context.Context, judgeruntime.TaskInput, judgeruntime.ProgressFunc) (judgeruntime.Outcome, error)
}
type SourceReader func(context.Context, *Lease) ([]byte, error)
type WorkerOptions struct {
	Repository    Repository
	Executor      Executor
	Source        SourceReader
	Concurrency   int
	PollInterval  time.Duration
	ShutdownGrace time.Duration
	// Report receives fixed errors only; private inputs and raw failures never log.
	Report func(error)
}
type Worker struct{ options WorkerOptions }

func NewWorker(o WorkerOptions) (*Worker, error) {
	if o.Repository == nil || o.Executor == nil || o.Source == nil || o.Concurrency < 1 || o.Concurrency > 64 {
		return nil, ErrInvalid
	}
	if o.PollInterval == 0 {
		o.PollInterval = time.Second
	}
	if o.PollInterval < 10*time.Millisecond || o.PollInterval > time.Minute {
		return nil, ErrInvalid
	}
	if o.ShutdownGrace == 0 {
		o.ShutdownGrace = 30 * time.Second
	}
	if o.ShutdownGrace < 0 || o.ShutdownGrace > time.Minute {
		return nil, ErrInvalid
	}
	return &Worker{options: o}, nil
}

// Run stops acquisition immediately on shutdown and lets live work drain for a
// bounded grace period. A cancelled/uncertain attempt stops heartbeat and is
// retained for counted recovery; it is never retried under its old token.
func (w *Worker) Run(ctx context.Context) error {
	claims, stopClaims := context.WithCancel(ctx)
	defer stopClaims()
	attempts, cancel := context.WithCancel(context.Background())
	defer cancel()
	faulted := make(chan struct{})
	var faultOnce sync.Once
	fault := func() {
		faultOnce.Do(func() {
			close(faulted)
			stopClaims()
			// A failed worker cannot use the healthy operator-stop grace period.
			// Its peers retain uncertain leases for counted recovery.
			cancel()
		})
	}
	finish := func() error {
		select {
		case <-faulted:
			return ErrWorkerStopped
		default:
			return nil
		}
	}
	var group sync.WaitGroup
	for range w.options.Concurrency {
		group.Add(1)
		go func() {
			defer group.Done()
			// A private panic must never reach Go's stderr panic value/stack dump.
			// Its attempt stays recoverable; the owning process sees one fixed error.
			defer func() {
				if recover() != nil {
					fault()
				}
			}()
			w.loop(claims, attempts, fault)
		}()
	}
	done := make(chan struct{})
	go func() { group.Wait(); close(done) }()
	select {
	case <-done:
		return finish()
	case <-claims.Done():
	}
	timer := time.NewTimer(w.options.ShutdownGrace)
	defer timer.Stop()
	select {
	case <-done:
		return finish()
	case <-timer.C:
		cancel()
		<-done
		return finish()
	}
}
func (w *Worker) loop(claims, attempts context.Context, fault func()) {
	for {
		if claims.Err() != nil {
			return
		}
		ready := w.options.Executor.Snapshot(claims)
		if ready.Qualified && ready.SandboxReady && ready.ToolchainReady {
			lease, err := w.options.Repository.Claim(claims)
			if err != nil {
				w.report(ErrPersistence)
			} else if lease != nil {
				w.execute(attempts, lease, fault)
				continue
			}
		}
		timer := time.NewTimer(w.options.PollInterval)
		select {
		case <-claims.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
func (w *Worker) report(err error) {
	if w.options.Report != nil {
		w.options.Report(err)
	}
}
func (w *Worker) execute(parent context.Context, l *Lease, fault func()) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	heartbeatDone := make(chan struct{})
	stopHeartbeat := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		defer func() {
			if recover() != nil {
				fault()
				cancel()
			}
		}()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stopHeartbeat:
				return
			case <-ticker.C:
				if w.options.Repository.Heartbeat(ctx, l) != nil {
					cancel()
					return
				}
			}
		}
	}()
	defer func() { close(stopHeartbeat); <-heartbeatDone }()
	source, err := w.options.Source(ctx, l)
	if err != nil || len(source) > judgeruntime.MaxSourceBytes || int64(len(source)) != l.Frozen.SourceSizeBytes {
		if ctx.Err() == nil {
			_, _ = w.options.Repository.Fail(ctx, l, "PRIVATE_SOURCE_INTEGRITY_FAILED")
		}
		return
	}
	hash := sha256.Sum256(source)
	if hex.EncodeToString(hash[:]) != l.SourceSHA256 {
		_, _ = w.options.Repository.Fail(ctx, l, "PRIVATE_SOURCE_INTEGRITY_FAILED")
		return
	}
	input := judgeruntime.TaskInput{TaskID: l.Task.JudgeTaskID, FencingToken: l.Token, LanguageID: judgeruntime.LanguageID, Identity: l.Frozen.Identity, Source: source, SourceSHA256: l.SourceSHA256, Limits: l.Frozen.Limits, Cases: l.Cases}
	acknowledged := false
	outcome, err := w.options.Executor.Execute(ctx, input, func(progressCtx context.Context, p judgeruntime.Progress) error {
		if progressCtx.Err() != nil {
			return progressCtx.Err()
		}
		if !acknowledged {
			if p.Type != "progress" || p.Status != "Compiling" || p.Ordinal != 0 {
				return ErrInvalid
			}
			if err := w.options.Repository.Running(progressCtx, l); err != nil {
				return err
			}
			acknowledged = true
			return nil
		}
		// Before another compiler/case/checker step, prove a live fence. This renews
		// only private lease data and never creates a public timestamp/revision.
		return w.options.Repository.Heartbeat(progressCtx, l)
	})
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		var failure *judgeruntime.Failure
		if errors.As(err, &failure) && failure.Ambiguous {
			return
		}
		code := "JUDGE_EXECUTION_FAILED"
		if failure != nil && diagnosticPattern.MatchString(failure.Code) {
			code = failure.Code
		}
		if _, err := w.options.Repository.Fail(ctx, l, code); err != nil {
			w.report(ErrPersistence)
		}
		return
	}
	if !acknowledged {
		w.report(ErrInvalid)
		return
	}
	if _, err := w.options.Repository.Complete(ctx, l, outcome); err != nil {
		w.report(ErrPersistence)
	}
}
