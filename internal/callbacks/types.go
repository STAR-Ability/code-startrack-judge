// Package callbacks delivers immutable JudgeTask events to the fixed Backend receiver.
package callbacks

import (
	"context"
	"errors"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
)

const (
	Destination    = "http://backend:8081/internal/v2/events/judge"
	DeliveryWindow = 24 * time.Hour
	LeaseDuration  = 60 * time.Second
	RequestTimeout = 10 * time.Second
)

type Code string

const (
	Unauthorized     Code = "CALLBACK_UNAUTHORIZED"
	UnknownTask      Code = "CALLBACK_TASK_NOT_FOUND"
	Conflict         Code = "CALLBACK_EVENT_CONFLICT"
	InvalidArgument  Code = "CALLBACK_INVALID_ARGUMENT"
	Unavailable      Code = "CALLBACK_UNAVAILABLE"
	InvalidACK       Code = "CALLBACK_INVALID_ACK"
	Rejected         Code = "CALLBACK_REJECTED"
	UnexpectedHTTP   Code = "CALLBACK_HTTP_UNEXPECTED"
	IntegrityFailure Code = "CALLBACK_INTEGRITY_FAILURE"
	LeaseExpired     Code = "CALLBACK_LEASE_EXPIRED"
	WindowExpired    Code = "CALLBACK_WINDOW_EXPIRED"
)

func (c Code) Valid() bool {
	switch c {
	case Unauthorized, UnknownTask, Conflict, InvalidArgument, Unavailable, InvalidACK, Rejected, UnexpectedHTTP, IntegrityFailure, LeaseExpired, WindowExpired:
		return true
	}
	return false
}

var (
	ErrLeaseLost   = errors.New("callback lease lost")
	ErrPersistence = errors.New("callback persistence unavailable")
	ErrInvalid     = errors.New("invalid callback operation")
)

// Delivery is an internal lease. CanonicalJSON is the original JCS event body,
// never an API response envelope or a freshly generated event identity.
type Delivery struct {
	EventID        contract.UUID
	RequestID      contract.UUID
	TaskID         contract.UUID
	Revision       int64
	PayloadHash    string
	CanonicalJSON  []byte
	LeaseToken     contract.UUID
	LeaseExpiresAt time.Time
	AttemptCount   int
}

type Outcome struct {
	Accepted  bool
	Duplicate bool
	ErrorCode Code
}

func (o Outcome) Valid() bool {
	return (o.Accepted && o.ErrorCode == "") || (!o.Accepted && !o.Duplicate && o.ErrorCode.Valid())
}

// Backoff uses the count of reserved deliveries, including interrupted sends.
// The caller caps next_attempt_at at the original creation-time deadline.
func Backoff(attemptCount int) time.Duration {
	switch attemptCount {
	case 1:
		return time.Second
	case 2:
		return 2 * time.Second
	case 3:
		return 4 * time.Second
	case 4:
		return 8 * time.Second
	case 5:
		return 16 * time.Second
	default:
		return 30 * time.Second
	}
}

type Repository interface {
	Claim(context.Context) (*Delivery, error)
	Complete(context.Context, *Delivery, Outcome) error
}

type Sender interface {
	Send(context.Context, *Delivery) Outcome
}
