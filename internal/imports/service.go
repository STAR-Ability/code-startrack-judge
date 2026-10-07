// Package imports owns durable admission and recovery for the fixed-source
// package pipeline. Execution and object writes occur outside SQL transactions.
package imports

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
)

type Error struct{ Code string }

func (e *Error) Error() string      { return "import workflow " + e.Code }
func (e *Error) PublicCode() string { return e.Code }

var ErrNotFound = &Error{Code: "TASK_NOT_FOUND"}
var ErrConflict = &Error{Code: "IDEMPOTENCY_CONFLICT"}
var ErrUnavailable = &Error{Code: "JUDGE_UNAVAILABLE"}
var ErrLeaseLost = errors.New("import lease is not live")

type Repository interface {
	FindByRequest(context.Context, contract.UUID) (contract.ImportJob, string, error)
	Accept(context.Context, contract.ImportRequest, string) (contract.ImportJob, bool, error)
	Get(context.Context, contract.UUID) (contract.ImportJob, error)
}

type Service struct {
	repository Repository
	ready      func(context.Context) bool
}

func New(repository Repository, ready func(context.Context) bool) *Service {
	return &Service{repository: repository, ready: ready}
}

func (s *Service) Submit(ctx context.Context, request contract.ImportRequest) (contract.ImportJob, bool, error) {
	if err := request.Validate(); err != nil {
		return contract.ImportJob{}, false, err
	}
	// Struct marshaling is only an input to the shared canonical profile.
	body, err := json.Marshal(request)
	if err != nil {
		return contract.ImportJob{}, false, ErrUnavailable
	}
	hash, err := canonical.RequestHash("IMPORT", nil, body)
	if err != nil {
		return contract.ImportJob{}, false, err
	}
	job, existingHash, err := s.repository.FindByRequest(ctx, request.RequestID)
	if err == nil {
		if existingHash != hash {
			return contract.ImportJob{}, false, ErrConflict
		}
		return job, false, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return contract.ImportJob{}, false, err
	}
	if s.ready == nil || !s.ready(ctx) {
		return contract.ImportJob{}, false, ErrUnavailable
	}
	return s.repository.Accept(ctx, request, hash)
}

func (s *Service) Get(ctx context.Context, id contract.UUID) (contract.ImportJob, error) {
	if err := id.Validate(); err != nil {
		return contract.ImportJob{}, err
	}
	return s.repository.Get(ctx, id)
}

// Lease hides scheduling state from public ImportJob DTOs.
type Lease struct {
	JobID    contract.UUID
	Token    contract.UUID
	Revision string
	Items    []PendingItem
}
type PendingItem struct {
	ID          contract.UUID
	Ordinal     int
	PackagePath string
}

// Prepared writes no objects and performs no network/compilation in Apply.
// Its database registration runs only after the current lease has been locked
// and checked. A rollback retains staging for safe orphan reconciliation.
type Prepared interface {
	Apply(context.Context, *sql.Tx, PendingItem) (ItemResult, error)
}
type ItemResult struct {
	Item     contract.ImportItem
	Evidence *RejectedEvidence
}
type RejectedEvidence struct {
	// ID is preallocated by the pipeline so deferred object-owner references can
	// join the item's transaction. It is excluded from the evidence hash.
	ID                   contract.UUID                      `json:"-"`
	FailureStage         string                             `json:"failureStage"`
	SourceArchiveKey     *string                            `json:"sourceArchiveKey"`
	SourceSHA256         *string                            `json:"sourceSha256"`
	NormalizedArchiveKey *string                            `json:"normalizedArchiveKey"`
	NormalizedSHA256     *string                            `json:"normalizedSha256"`
	LicenseEvidenceID    *contract.UUID                     `json:"licenseEvidenceId"`
	Provenance           map[string]any                     `json:"provenance"`
	SourceMetadata       map[string]any                     `json:"sourceMetadata"`
	Adaptations          []any                              `json:"adaptations"`
	Errors               contract.Array[contract.TaskError] `json:"errors"`
	ValidationLogKey     *string                            `json:"validationLogKey"`
}
type WorkerRepository interface {
	Claim(context.Context) (*Lease, error)
	Heartbeat(context.Context, Lease) error
	CompleteItem(context.Context, Lease, PendingItem, Prepared) error
}

// AttemptRetainer appends private incomplete validation evidence without
// completing an item or extending its execution reservation.
type AttemptRetainer interface {
	RetainAttempt(context.Context, Lease, PendingItem, Prepared) error
}
type Pipeline interface {
	Prepare(context.Context, Lease, PendingItem) (Prepared, error)
}

type Worker struct {
	Repository   WorkerRepository
	Pipeline     Pipeline
	Ready        func(context.Context) bool
	PollInterval time.Duration
}

func (w *Worker) Run(ctx context.Context) error {
	if w.Repository == nil || w.Pipeline == nil || w.Ready == nil {
		return ErrUnavailable
	}
	interval := w.PollInterval
	if interval <= 0 {
		interval = time.Second
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			if w.Ready(ctx) {
				lease, err := w.Repository.Claim(ctx)
				if err == nil && lease != nil {
					w.execute(ctx, *lease)
				}
			}
			timer.Reset(interval)
		}
	}
}

func (w *Worker) execute(parent context.Context, lease Lease) {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !w.Ready(ctx) || w.Repository.Heartbeat(ctx, lease) != nil {
					cancel()
					return
				}
			}
		}
	}()
	defer func() { cancel(); <-done }()
	for _, item := range lease.Items {
		if ctx.Err() != nil || !w.Ready(ctx) {
			return
		}
		prepared, err := w.Pipeline.Prepare(ctx, lease, item)
		// An ambiguous infrastructure/transport failure consumes this reservation.
		// Stop heartbeats; only a fresh counted recovery may prepare it again.
		if err != nil || prepared == nil {
			cancel()
			<-done
			if prepared != nil {
				if retainer, ok := w.Repository.(AttemptRetainer); ok {
					retentionCtx, stop := context.WithTimeout(context.WithoutCancel(parent), 5*time.Second)
					_ = retainer.RetainAttempt(retentionCtx, lease, item, prepared)
					stop()
				}
			}
			return
		}
		if err = w.Repository.CompleteItem(ctx, lease, item, prepared); err != nil {
			return
		}
	}
}
