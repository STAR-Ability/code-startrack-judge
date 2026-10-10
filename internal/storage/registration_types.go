package storage

import (
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"time"
)

// SourceRegistration is an internal durable candidate pin, not a wire DTO.
// Admission may alias this type to preserve the acceptance transaction seam.
type SourceRegistration struct {
	RegistrationID contract.UUID
	TaskID         contract.UUID
	Key            string
	SHA256         string
	SizeBytes      int64
}

func (SourceRegistration) String() string   { return "source registration (redacted)" }
func (SourceRegistration) GoString() string { return "source registration (redacted)" }

type StagedObject struct {
	RegistrationID contract.UUID
	Object         Object
	ExpiresAt      time.Time
}

func (StagedObject) String() string   { return "staged private object (redacted)" }
func (StagedObject) GoString() string { return "staged private object (redacted)" }
