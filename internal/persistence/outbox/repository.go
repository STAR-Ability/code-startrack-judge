// Package outbox owns callback delivery state; it never updates JudgeTask facts.
package outbox

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/callbacks"
	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
)

type Repository struct{ db *sql.DB }

func New(db *sql.DB) (*Repository, error) {
	if db == nil {
		return nil, callbacks.ErrInvalid
	}
	return &Repository{db: db}, nil
}

// Claim sweeps a bounded set of expired reservations before claiming one due
// row. Every claim has a fresh lease_owner UUID, which acts as a fencing token.
func (r *Repository) Claim(ctx context.Context) (*callbacks.Delivery, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, callbacks.ErrPersistence
	}
	defer tx.Rollback() //nolint:errcheck -- rollback after commit is harmless.
	if err := reap(ctx, tx); err != nil {
		return nil, callbacks.ErrPersistence
	}
	token, err := contract.NewUUID()
	if err != nil {
		return nil, callbacks.ErrPersistence
	}
	row := tx.QueryRowContext(ctx, `WITH due AS (
 SELECT event_id FROM judge.callback_outbox
 WHERE status='PENDING' AND next_attempt_at<=clock_timestamp()
 AND created_at+interval '24 hours'>clock_timestamp()
 ORDER BY next_attempt_at,event_id FOR UPDATE SKIP LOCKED LIMIT 1
)
UPDATE judge.callback_outbox o SET status='SENDING',attempt_count=o.attempt_count+1,
 lease_owner=$1,lease_expires_at=clock_timestamp()+interval '60 seconds',updated_at=clock_timestamp()
FROM due WHERE o.event_id=due.event_id
RETURNING o.event_id::text,o.request_id::text,o.judge_task_id::text,o.revision,o.payload_hash,
 o.payload::text,o.lease_owner::text,o.lease_expires_at,o.attempt_count`, string(token))
	d, err := scanDelivery(row)
	if errors.Is(err, sql.ErrNoRows) {
		if err := tx.Commit(); err != nil {
			return nil, callbacks.ErrPersistence
		}
		return nil, nil
	}
	if err != nil {
		return nil, callbacks.ErrPersistence
	}
	if err := tx.Commit(); err != nil {
		return nil, callbacks.ErrPersistence
	}
	return d, nil
}

type rowScanner interface{ Scan(...any) error }

func scanDelivery(row rowScanner) (*callbacks.Delivery, error) {
	d := new(callbacks.Delivery)
	var event, request, task, token, payload string
	err := row.Scan(&event, &request, &task, &d.Revision, &d.PayloadHash, &payload, &token, &d.LeaseExpiresAt, &d.AttemptCount)
	if err != nil {
		return nil, err
	}
	d.EventID, d.RequestID, d.TaskID, d.LeaseToken = contract.UUID(event), contract.UUID(request), contract.UUID(task), contract.UUID(token)
	// Invalid persisted JSON/hash is reserved like any other attempt and then
	// reported by Client as an integrity failure. It is never sent unchecked.
	d.CanonicalJSON, err = canonical.Canonicalize([]byte(payload))
	if err != nil {
		d.CanonicalJSON = nil
	}
	return d, nil
}

func reap(ctx context.Context, tx *sql.Tx) error {
	// The CTE locks before recording an interrupted manual action and releasing
	// its lease. A concurrent active dispatcher remains untouched.
	_, err := tx.ExecContext(ctx, `WITH expired AS MATERIALIZED (
 SELECT event_id,lease_owner,status FROM judge.callback_outbox
 WHERE (status='PENDING' AND created_at+interval '24 hours'<=clock_timestamp())
 OR (status='SENDING' AND lease_expires_at<=clock_timestamp())
 ORDER BY next_attempt_at,event_id FOR UPDATE SKIP LOCKED LIMIT 100
), audit AS (
 INSERT INTO judge.callback_redelivery_outcomes(replay_id,status,last_error_code,duplicate,finished_at)
 SELECT a.replay_id,'INTERRUPTED','CALLBACK_LEASE_EXPIRED',false,clock_timestamp()
 FROM expired e JOIN judge.callback_redelivery_requests a ON a.event_id=e.event_id AND a.lease_token=e.lease_owner
 ON CONFLICT (replay_id) DO NOTHING RETURNING replay_id
)
UPDATE judge.callback_outbox o SET
 status=CASE WHEN o.created_at+interval '24 hours'<=clock_timestamp() THEN 'DEAD_LETTER' ELSE 'PENDING' END,
 next_attempt_at=LEAST(clock_timestamp(),o.created_at+interval '24 hours'),lease_owner=NULL,lease_expires_at=NULL,
 last_error_code=COALESCE(o.last_error_code,CASE WHEN e.status='SENDING' THEN 'CALLBACK_LEASE_EXPIRED' ELSE 'CALLBACK_WINDOW_EXPIRED' END),
 updated_at=clock_timestamp()
FROM expired e WHERE o.event_id=e.event_id`)
	return err
}

func (r *Repository) Complete(ctx context.Context, d *callbacks.Delivery, outcome callbacks.Outcome) error {
	if d == nil || d.EventID.Validate() != nil || d.LeaseToken.Validate() != nil || !outcome.Valid() {
		return callbacks.ErrInvalid
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return callbacks.ErrPersistence
	}
	defer tx.Rollback() //nolint:errcheck -- rollback after commit is harmless.
	var attemptCount int
	err = tx.QueryRowContext(ctx, `SELECT attempt_count FROM judge.callback_outbox
WHERE event_id=$1 AND status='SENDING' AND lease_owner=$2 AND lease_expires_at>clock_timestamp()
FOR UPDATE`, string(d.EventID), string(d.LeaseToken)).Scan(&attemptCount)
	if errors.Is(err, sql.ErrNoRows) {
		return callbacks.ErrLeaseLost
	}
	if err != nil {
		return callbacks.ErrPersistence
	}
	var status string
	if outcome.Accepted {
		err = tx.QueryRowContext(ctx, `UPDATE judge.callback_outbox SET status='DELIVERED',
 lease_owner=NULL,lease_expires_at=NULL,last_error_code=NULL,delivered_at=clock_timestamp(),updated_at=clock_timestamp()
WHERE event_id=$1 AND status='SENDING' AND lease_owner=$2 AND lease_expires_at>clock_timestamp()
RETURNING status`, string(d.EventID), string(d.LeaseToken)).Scan(&status)
	} else {
		err = tx.QueryRowContext(ctx, `UPDATE judge.callback_outbox SET
 status=CASE WHEN created_at+interval '24 hours'<=clock_timestamp() THEN 'DEAD_LETTER' ELSE 'PENDING' END,
 next_attempt_at=LEAST(clock_timestamp()+($3::bigint*interval '1 millisecond'),created_at+interval '24 hours'),
 lease_owner=NULL,lease_expires_at=NULL,last_error_code=$4,updated_at=clock_timestamp()
WHERE event_id=$1 AND status='SENDING' AND lease_owner=$2 AND lease_expires_at>clock_timestamp()
RETURNING status`, string(d.EventID), string(d.LeaseToken), callbacks.Backoff(attemptCount).Milliseconds(), string(outcome.ErrorCode)).Scan(&status)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return callbacks.ErrLeaseLost
	}
	if err != nil {
		return callbacks.ErrPersistence
	}
	auditStatus := "FAILED"
	var errorCode any = string(outcome.ErrorCode)
	if outcome.Accepted {
		auditStatus = "DELIVERED"
		errorCode = nil
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO judge.callback_redelivery_outcomes(replay_id,status,last_error_code,duplicate,finished_at)
SELECT replay_id,$3,$4,$5,clock_timestamp() FROM judge.callback_redelivery_requests
WHERE event_id=$1 AND lease_token=$2`, string(d.EventID), string(d.LeaseToken), auditStatus, errorCode, outcome.Duplicate)
	if err != nil {
		return callbacks.ErrPersistence
	}
	if err := tx.Commit(); err != nil {
		return callbacks.ErrPersistence
	}
	return nil
}

// DeadLetter contains only bounded reconciliation metadata. The event payload,
// hidden artifacts, private logs and source object references are not listed.
type DeadLetter struct {
	EventID       contract.UUID `json:"eventId"`
	RequestID     contract.UUID `json:"requestId"`
	TaskID        contract.UUID `json:"judgeTaskId"`
	Revision      int64         `json:"revision"`
	PayloadHash   string        `json:"payloadHash"`
	AttemptCount  int           `json:"attemptCount"`
	LastErrorCode *string       `json:"lastErrorCode"`
	CreatedAt     time.Time     `json:"createdAt"`
	UpdatedAt     time.Time     `json:"updatedAt"`
}

func (r *Repository) ListDeadLetters(ctx context.Context, limit int, after *contract.UUID) ([]DeadLetter, error) {
	if limit < 1 || limit > 100 || (after != nil && after.Validate() != nil) {
		return nil, callbacks.ErrInvalid
	}
	var cursor any
	if after != nil {
		cursor = string(*after)
	}
	rows, err := r.db.QueryContext(ctx, `SELECT event_id::text,request_id::text,judge_task_id::text,revision,payload_hash,attempt_count,last_error_code,created_at,updated_at
FROM judge.callback_outbox WHERE status='DEAD_LETTER' AND ($2::uuid IS NULL OR event_id>$2::uuid) ORDER BY event_id LIMIT $1`, limit, cursor)
	if err != nil {
		return nil, callbacks.ErrPersistence
	}
	defer rows.Close()
	result := make([]DeadLetter, 0)
	for rows.Next() {
		var d DeadLetter
		var event, request, task string
		if rows.Scan(&event, &request, &task, &d.Revision, &d.PayloadHash, &d.AttemptCount, &d.LastErrorCode, &d.CreatedAt, &d.UpdatedAt) != nil {
			return nil, callbacks.ErrPersistence
		}
		d.EventID, d.RequestID, d.TaskID = contract.UUID(event), contract.UUID(request), contract.UUID(task)
		if d.LastErrorCode != nil && !callbacks.Code(*d.LastErrorCode).Valid() {
			code := string(callbacks.IntegrityFailure)
			d.LastErrorCode = &code
		}
		result = append(result, d)
	}
	if rows.Err() != nil {
		return nil, callbacks.ErrPersistence
	}
	return result, nil
}

type ReplayReason string

const (
	MappingReconciled ReplayReason = "MAPPING_RECONCILED"
	AuthRestored      ReplayReason = "AUTH_RESTORED"
	TransportRestored ReplayReason = "TRANSPORT_RESTORED"
	ConflictResolved  ReplayReason = "CONFLICT_RESOLVED"
)

func validReason(reason ReplayReason) bool {
	switch reason {
	case MappingReconciled, AuthRestored, TransportRestored, ConflictResolved:
		return true
	}
	return false
}

func validOperator(ref string) bool {
	if len(ref) < 1 || len(ref) > 128 {
		return false
	}
	for _, b := range []byte(ref) {
		if !((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '-' || b == '_' || b == '.' || b == '@') {
			return false
		}
	}
	return true
}

// ClaimReplay is a single explicit delivery reservation after reconciliation.
// It records the operator action without resetting created_at or the retry
// window. Failure/expiry returns to retained DEAD_LETTER, never a new 24h queue.
func (r *Repository) ClaimReplay(ctx context.Context, eventID contract.UUID, operatorRef string, reason ReplayReason) (*callbacks.Delivery, contract.UUID, error) {
	if eventID.Validate() != nil || !validOperator(operatorRef) || !validReason(reason) {
		return nil, "", callbacks.ErrInvalid
	}
	token, err := contract.NewUUID()
	if err != nil {
		return nil, "", callbacks.ErrPersistence
	}
	replayID, err := contract.NewUUID()
	if err != nil {
		return nil, "", callbacks.ErrPersistence
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", callbacks.ErrPersistence
	}
	defer tx.Rollback() //nolint:errcheck -- rollback after commit is harmless.
	if reap(ctx, tx) != nil {
		return nil, "", callbacks.ErrPersistence
	}
	row := tx.QueryRowContext(ctx, `UPDATE judge.callback_outbox SET status='SENDING',attempt_count=attempt_count+1,
lease_owner=$2,lease_expires_at=clock_timestamp()+interval '60 seconds',updated_at=clock_timestamp()
WHERE event_id=$1 AND status='DEAD_LETTER'
RETURNING event_id::text,request_id::text,judge_task_id::text,revision,payload_hash,payload::text,lease_owner::text,lease_expires_at,attempt_count`, string(eventID), string(token))
	d, err := scanDelivery(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", callbacks.ErrInvalid
	}
	if err != nil {
		return nil, "", callbacks.ErrPersistence
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO judge.callback_redelivery_requests(replay_id,event_id,lease_token,operator_ref,reason,created_at)
VALUES($1,$2,$3,$4,$5,clock_timestamp())`, string(replayID), string(eventID), string(token), operatorRef, string(reason))
	if err != nil {
		return nil, "", callbacks.ErrPersistence
	}
	if tx.Commit() != nil {
		return nil, "", callbacks.ErrPersistence
	}
	return d, replayID, nil
}
