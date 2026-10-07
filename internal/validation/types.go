// SPDX-License-Identifier: Apache-2.0

// Package validation joins mature technical checks with exact-profile program
// evidence. It never executes a process, extracts an archive, or publishes.
package validation

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/packages"
	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
)

const ProblemtoolsVersion = "v1.20260907"
const HelperProfile = "ROLE_SEPARATED_PROBLEMTOOLS_V1"
const MaxPrivateLogBytes = 8 << 20

var ErrUnavailable = errors.New("qualified package validation unavailable")
var ErrInvalid = errors.New("invalid sealed validation input")
var codePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
var shaPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Context struct {
	ProblemtoolsVersion string `json:"problemtoolsVersion"`
	AdapterVersion      string `json:"adapterVersion"`
	ToolchainVersion    string `json:"toolchainVersion"`
	ImageDigest         string `json:"imageDigest"`
	ConfigSHA256        string `json:"configSha256"`
	SourceSHA256        string `json:"sourceSha256"`
	NormalizedSHA256    string `json:"normalizedSha256"`
}
type Evidence struct {
	Check         string  `json:"check"`
	SubjectSHA256 *string `json:"subjectSha256"`
	LogObjectKey  *string `json:"logObjectKey"`
	Summary       string  `json:"summary"`
}
type Checkpoint struct {
	Passed   bool       `json:"passed"`
	Evidence []Evidence `json:"evidence"`
}
type Results struct {
	Structure          Checkpoint `json:"structure"`
	Statement          Checkpoint `json:"statement"`
	TestData           Checkpoint `json:"testData"`
	Validators         Checkpoint `json:"validators"`
	ReferenceSolutions Checkpoint `json:"referenceSolutions"`
}

func (r Results) AllPassed() bool {
	return r.Structure.Passed && r.Statement.Passed && r.TestData.Passed && r.Validators.Passed && r.ReferenceSolutions.Passed
}
func (r Results) Validate() error {
	for _, part := range []Checkpoint{r.Structure, r.Statement, r.TestData, r.Validators, r.ReferenceSolutions} {
		if len(part.Evidence) < 1 || len(part.Evidence) > 65536 {
			return ErrInvalid
		}
		for _, e := range part.Evidence {
			if !codePattern.MatchString(e.Check) || e.SubjectSHA256 != nil && !shaPattern.MatchString(*e.SubjectSHA256) || e.LogObjectKey != nil && (strings.TrimSpace(*e.LogObjectKey) == "" || utf8.RuneCountInString(*e.LogObjectKey) > 1024) || !utf8.ValidString(e.Summary) || strings.TrimSpace(e.Summary) == "" || utf8.RuneCountInString(e.Summary) > 500 {
				return ErrInvalid
			}
		}
	}
	return nil
}

type Request struct {
	JobID        contract.UUID
	ItemID       contract.UUID
	FencingToken contract.UUID
	Candidate    *packages.Artifact
	// Every program/case event is privately journaled outside SQL transactions.
	// A failing journal stops execution; its failure cannot become PASSED.
	RecordEvidence judgeruntime.ValidationEvidenceFunc
}

func (Request) String() string     { return "private validation request [bytes and paths redacted]" }
func (r Request) GoString() string { return r.String() }

type Report struct {
	// PORTABLE_ONLY cannot be inserted into package_validation_runs. It provides
	// mock DTO/control-flow evidence without an execution/image claim.
	Status                string
	Context               Context
	Results               Results
	Errors                contract.Array[contract.TaskError]
	Adaptations           []packages.Adaptation
	StartedAt             time.Time
	FinishedAt            time.Time
	RawLog                []byte
	ProgramEvidenceSHA256 string
	ProgramEvidenceCount  uint64
}

func (Report) String() string     { return "private validation report [raw diagnostics redacted]" }
func (r Report) GoString() string { return r.String() }

type Engine interface {
	Snapshot(context.Context) judgeruntime.Snapshot
	ValidateProgramsWithEvidence(context.Context, judgeruntime.ValidationInput, judgeruntime.ValidationEvidenceFunc) (judgeruntime.ValidationOutcome, error)
}
type MatureSnapshot struct {
	Qualified            bool
	Identity             judgeruntime.FrozenIdentity
	ProblemtoolsVersion  string
	ProblemtoolsRevision string
	HelperProfile        string
}

// MatureVerifier is a trusted isolated helper seam. Its implementation must run
// every mature verification part and dispatch imported programs/compilers/TeX
// through reviewed isolation with separate reference/input/checker visibility.
// Running unmodified verifyproblem in one sandbox does not satisfy this seam.
type MatureVerifier interface {
	Snapshot(context.Context) MatureSnapshot
	Verify(context.Context, MatureInput) (MatureOutcome, error)
}
type MatureInput struct {
	JobID                 contract.UUID
	FencingToken          contract.UUID
	StepName              string
	Identity              judgeruntime.FrozenIdentity
	Candidate             *packages.Artifact
	FixedTimeLimitSeconds string
}

func (MatureInput) String() string {
	return "private mature verification input [bytes and paths redacted]"
}
func (v MatureInput) GoString() string { return v.String() }

type PartOutcome struct {
	// Part is one of STRUCTURE, STATEMENT, TEST_DATA, VALIDATORS, REFERENCES.
	Part     string
	Passed   bool
	Errors   int
	Warnings int
	// NotRun records incomplete upstream steps, including a fatal early stop.
	NotRun bool
}
type MatureOutcome struct {
	Identity  judgeruntime.FrozenIdentity
	Completed bool
	Parts     []PartOutcome
	RawLog    []byte
}

func (MatureOutcome) String() string {
	return "private mature verification outcome [raw diagnostics redacted]"
}
func (v MatureOutcome) GoString() string { return v.String() }

// UnavailableMatureVerifier is the fail-closed production default until the
// reviewed execution hook has actual Linux qualification and a built identity.
type UnavailableMatureVerifier struct{}

func (UnavailableMatureVerifier) Snapshot(context.Context) MatureSnapshot { return MatureSnapshot{} }
func (UnavailableMatureVerifier) Verify(context.Context, MatureInput) (MatureOutcome, error) {
	return MatureOutcome{}, ErrUnavailable
}

type Options struct {
	Engine Engine
	Mature MatureVerifier
	// Only trusted test construction uses this flag. It forces PORTABLE_ONLY,
	// leaves execution Context empty, and cannot supply publication evidence.
	ControlFlowOnly bool
}
type Validator struct{ options Options }

func New(options Options) (*Validator, error) {
	if options.Engine == nil {
		return nil, ErrInvalid
	}
	if options.Mature == nil {
		options.Mature = UnavailableMatureVerifier{}
	}
	return &Validator{options: options}, nil
}
