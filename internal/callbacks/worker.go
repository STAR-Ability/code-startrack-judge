package callbacks

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

type Worker struct {
	repository Repository
	sender     Sender
	logger     *slog.Logger
}

func NewWorker(repository Repository, sender Sender, logger *slog.Logger) (*Worker, error) {
	if repository == nil || sender == nil || logger == nil {
		return nil, ErrInvalid
	}
	return &Worker{repository: repository, sender: sender, logger: logger}, nil
}

// RunOnce reserves at most one event. Network execution takes place outside the
// claim transaction; losing the completion transaction leaves a recoverable lease.
func (w *Worker) RunOnce(ctx context.Context) (bool, error) {
	d, err := w.repository.Claim(ctx)
	if err != nil {
		return false, err
	}
	if d == nil {
		return false, nil
	}
	sendCtx, cancel := context.WithTimeout(ctx, RequestTimeout)
	outcome := w.sender.Send(sendCtx, d)
	cancel()
	if !outcome.Valid() {
		outcome = Outcome{ErrorCode: InvalidACK}
	}
	if err := w.repository.Complete(ctx, d, outcome); err != nil {
		return true, err
	}
	attrs := []any{"event_id", string(d.EventID), "request_id", string(d.RequestID), "attempt", d.AttemptCount}
	if outcome.Accepted {
		w.logger.Info("callback delivered", append(attrs, "duplicate", outcome.Duplicate)...)
	} else {
		attrs = append(attrs, "code", string(outcome.ErrorCode))
		if outcome.ErrorCode == Unauthorized || outcome.ErrorCode == Conflict || outcome.ErrorCode == IntegrityFailure {
			w.logger.Error("callback requires reconciliation", attrs...)
		} else {
			w.logger.Warn("callback delivery retained", attrs...)
		}
	}
	return true, nil
}

// Run is a bounded single dispatcher. Multiple workers may share the durable
// repository because PostgreSQL claims use SKIP LOCKED and fresh fenced leases.
func (w *Worker) Run(ctx context.Context) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		didWork, err := w.RunOnce(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			code := "CALLBACK_PERSISTENCE_UNAVAILABLE"
			if errors.Is(err, ErrLeaseLost) {
				code = string(LeaseExpired)
			}
			w.logger.Error("callback dispatcher retained event", "code", code)
		}
		if didWork && err == nil {
			continue
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
