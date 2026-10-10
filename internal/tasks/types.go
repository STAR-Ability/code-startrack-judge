// Package tasks defines private frozen attempts and deterministic final reducers.
package tasks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
)

var (
	ErrPersistence   = errors.New("task persistence unavailable")
	ErrLeaseLost     = errors.New("task execution lease lost")
	ErrInvalid       = errors.New("invalid task attempt")
	ErrWorkerStopped = errors.New("task worker stopped unexpectedly")
)

type Frozen struct {
	ArtifactID      contract.UUID               `json:"artifactId"`
	Identity        judgeruntime.FrozenIdentity `json:"identity"`
	Limits          judgeruntime.Limits         `json:"limits"`
	Checker         judgeruntime.CheckerConfig  `json:"checker"`
	SourceSizeBytes int64                       `json:"sourceSizeBytes"`
	SourceFilename  string                      `json:"sourceFilename"`
	CompileTemplate json.RawMessage             `json:"compileTemplate"`
	RunTemplate     json.RawMessage             `json:"runTemplate"`
	CompileLimits   json.RawMessage             `json:"compileLimits"`
}
type Lease struct {
	Task         contract.JudgeTask
	Token        contract.UUID
	AttemptCount int
	ExpiresAt    time.Time
	SourceKey    string
	SourceSHA256 string
	Frozen       Frozen
	Cases        []judgeruntime.Case
}

func (l Lease) String() string {
	return fmt.Sprintf("task attempt [recovery=%d cases=%d private inputs redacted]", l.AttemptCount, len(l.Cases))
}
func (l Lease) GoString() string  { return l.String() }
func (Frozen) String() string     { return "frozen task [private execution configuration redacted]" }
func (f Frozen) GoString() string { return f.String() }

type Repository interface {
	Claim(context.Context) (*Lease, error)
	Running(context.Context, *Lease) error
	Heartbeat(context.Context, *Lease) error
	Complete(context.Context, *Lease, judgeruntime.Outcome) (contract.JudgeTask, error)
	Fail(context.Context, *Lease, string) (contract.JudgeTask, error)
}

type CaseFact struct {
	TestCaseID    contract.UUID
	Ordinal       int
	Verdict       string
	CPUTimeMS     *contract.SafeInt
	WallTimeMS    *contract.SafeInt
	MemoryBytes   *contract.SafeInt
	ExitCode      *int
	SandboxStatus *string
	CheckerStatus *string
}
type Final struct {
	Result contract.JudgeResult
	Error  *contract.TaskError
	Cases  []CaseFact
}
