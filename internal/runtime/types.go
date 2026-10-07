// Package runtime owns the private, role-aware adapter around pinned go-judge.
// It never executes programs in the service process or accepts command templates.
package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/runtime/restclient"
)

const (
	LanguageID            = "cpp17"
	SandboxVersion        = "go-judge/v1.13.0@e9d70a0d9a3df0c62182a6e7090d7af650a1d5f8"
	CheckerSourceSHA256   = "2901f589366382433562ec550b2f0c979ad94e3a3a4f737ef013bdd4fa334328"
	CheckerImplementation = "problemtools/6010cbaa37a1612117f49566b2fff8646d53faa2/default_validator"
	CompilerConfigVersion = "cpp17-gcc-v0.2.1"
	CompilerVersion       = "g++ (Debian 12.2.0-14+deb12u1) 12.2.0"
	CPP17ToolchainDigest  = "sha256:eaeffb6e8511935426934aac863940fbd004ef31dab0d7fc27a129bb7c19d9a8"
	MaxSourceBytes        = contract.MaxSourceBytes
	MaxFileBytes          = 64 << 20
)

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var imagePattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var tolerancePattern = regexp.MustCompile(`^(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)

// FrozenIdentity is persisted at admission. Image digests describe actual built
// images; an unbuilt source/configuration digest cannot stand in for one.
type FrozenIdentity struct {
	LanguageConfigVersion string `json:"languageConfigVersion"`
	CompilerVersion       string `json:"compilerVersion"`
	ToolchainDigest       string `json:"toolchainDigest"`
	WorkerImageDigest     string `json:"workerImageDigest"`
	SandboxVersion        string `json:"sandboxVersion"`
	CheckerDigest         string `json:"checkerDigest"`
}

func (i FrozenIdentity) Validate() error {
	if i.LanguageConfigVersion != CompilerConfigVersion || i.CompilerVersion != CompilerVersion || i.ToolchainDigest != CPP17ToolchainDigest || !imagePattern.MatchString(i.WorkerImageDigest) || i.SandboxVersion != SandboxVersion || !digestPattern.MatchString(i.CheckerDigest) {
		return failure("RUNTIME_IDENTITY_INVALID", false)
	}
	return nil
}

// BlobRef names exact private bytes, without an object key or filesystem path.
type BlobRef struct {
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"sizeBytes"`
}
type BlobReader interface {
	ReadBlob(context.Context, string, int64, int64) ([]byte, error)
}

func (r BlobRef) valid() bool {
	return digestPattern.MatchString(r.SHA256) && r.SizeBytes >= 0 && r.SizeBytes <= MaxFileBytes
}
func bytesMatch(data []byte, ref BlobRef) bool {
	sum := sha256.Sum256(data)
	return int64(len(data)) == ref.SizeBytes && hex.EncodeToString(sum[:]) == ref.SHA256
}

// Limits use exact nanoseconds/bytes. Their values must match the sealed manifest.
type Limits struct {
	CPUTimeNS   uint64 `json:"cpuTimeNS"`
	WallTimeNS  uint64 `json:"wallTimeNS"`
	MemoryBytes uint64 `json:"memoryBytes"`
	OutputBytes uint64 `json:"outputBytes"`
	Processes   uint64 `json:"processes"`
}

func (l Limits) Validate() error {
	if l.CPUTimeNS == 0 || l.CPUTimeNS > uint64(60*time.Second) || l.CPUTimeNS%uint64(time.Millisecond) != 0 || l.WallTimeNS != 2*l.CPUTimeNS || l.MemoryBytes == 0 || l.MemoryBytes > 2<<30 || l.OutputBytes == 0 || l.OutputBytes > MaxFileBytes || l.Processes != 32 {
		return failure("RUNTIME_LIMITS_INVALID", false)
	}
	return nil
}

// CheckerConfig is a typed copy of the frozen manifest DEFAULT checker.
type CheckerConfig struct {
	Implementation         string  `json:"implementation"`
	SourceSHA256           string  `json:"sourceSha256"`
	CaseSensitive          bool    `json:"caseSensitive"`
	SpaceChangeSensitive   bool    `json:"spaceChangeSensitive"`
	FloatAbsoluteTolerance *string `json:"floatAbsoluteTolerance"`
	FloatRelativeTolerance *string `json:"floatRelativeTolerance"`
}

func DefaultChecker() CheckerConfig {
	return CheckerConfig{Implementation: CheckerImplementation, SourceSHA256: CheckerSourceSHA256}
}
func validTolerance(value *string) bool {
	if value == nil {
		return true
	}
	if len(*value) > 64 || !tolerancePattern.MatchString(*value) {
		return false
	}
	// Compare decimal magnitude without expanding 10^exponent. A bounded lexeme
	// with a huge exponent must not allocate a huge rational in the API process.
	mantissa, exponentText, hasExponent := strings.Cut(strings.ToLower(*value), "e")
	exponent := new(big.Int)
	if hasExponent {
		if _, ok := exponent.SetString(exponentText, 10); !ok {
			return false
		}
	}
	whole, fraction, _ := strings.Cut(mantissa, ".")
	digits := strings.TrimLeft(whole+fraction, "0")
	if digits == "" {
		return true
	}
	power := new(big.Int).Add(exponent, big.NewInt(int64(len(digits)-len(fraction))))
	cmp := power.Cmp(big.NewInt(1))
	if cmp < 0 {
		return true
	}
	if cmp > 0 {
		return false
	}
	return digits[0] == '1' && strings.Trim(digits[1:], "0") == ""
}
func (c CheckerConfig) Validate() error {
	if c.Implementation != CheckerImplementation || c.SourceSHA256 != CheckerSourceSHA256 || !validTolerance(c.FloatAbsoluteTolerance) || !validTolerance(c.FloatRelativeTolerance) {
		return failure("CHECKER_CONFIG_INVALID", false)
	}
	return nil
}
func (c CheckerConfig) args() []string {
	args := []string{"/usr/local/bin/startrack-checker-launcher", "/w/default_validator", "/w/input", "/w/answer", "/w/feedback"}
	if c.CaseSensitive {
		args = append(args, "case_sensitive")
	}
	if c.SpaceChangeSensitive {
		args = append(args, "space_change_sensitive")
	}
	if c.FloatAbsoluteTolerance != nil {
		args = append(args, "float_absolute_tolerance", *c.FloatAbsoluteTolerance)
	}
	if c.FloatRelativeTolerance != nil {
		args = append(args, "float_relative_tolerance", *c.FloatRelativeTolerance)
	}
	return args
}

type Case struct {
	TestCaseID contract.UUID `json:"testCaseId"`
	Ordinal    int           `json:"ordinal"`
	Input      BlobRef       `json:"input"`
	Answer     BlobRef       `json:"answer"`
	Checker    CheckerConfig `json:"checker"`
}
type TaskInput struct {
	TaskID       contract.UUID  `json:"taskId"`
	FencingToken contract.UUID  `json:"fencingToken"`
	LanguageID   string         `json:"languageId"`
	Identity     FrozenIdentity `json:"identity"`
	Source       []byte         `json:"source"`
	SourceSHA256 string         `json:"sourceSha256"`
	Limits       Limits         `json:"limits"`
	Cases        []Case         `json:"cases"`
}

// CaseResult is private original evidence; stdout/answers/paths are absent.
type CaseResult struct {
	TestCaseID    contract.UUID         `json:"testCaseId"`
	Ordinal       int                   `json:"ordinal"`
	Verdict       contract.JudgeVerdict `json:"verdict"`
	CPUTimeNS     uint64                `json:"cpuTimeNS"`
	WallTimeNS    uint64                `json:"wallTimeNS"`
	MemoryBytes   uint64                `json:"memoryBytes"`
	ExitCode      int                   `json:"exitCode"`
	SandboxStatus restclient.Status     `json:"sandboxStatus"`
	CheckerStatus restclient.Status     `json:"checkerStatus"`
}
type Outcome struct {
	Result contract.JudgeResult `json:"result"`
	Cases  []CaseResult         `json:"cases"`
	Error  *contract.TaskError  `json:"error"`
}

// Failure contains a fixed diagnostic only. Ambiguous means the fencing token
// must expire/recover; it never authorizes a transport retry under the same token.
type Failure struct {
	Code      string `json:"code"`
	Ambiguous bool   `json:"ambiguous"`
}

func (e *Failure) Error() string                   { return "runtime adapter: " + e.Code }
func failure(code string, ambiguous bool) *Failure { return &Failure{Code: code, Ambiguous: ambiguous} }

type Progress struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Ordinal int    `json:"ordinal"`
}
type ProgressFunc func(context.Context, Progress) error

type Session interface {
	Upload(context.Context, []byte) (restclient.FileID, error)
	Run(context.Context, restclient.Request) ([]restclient.Result, error)
	Download(context.Context, restclient.FileID, int64) ([]byte, error)
	Close() error
}
type SessionFactory interface{ NewSession() Session }
type restFactory struct{ client *restclient.Client }

func (f restFactory) NewSession() Session { return f.client.NewSession() }

// IsolationVerifier must measure the currently supervised Linux runtime. It is
// a trusted deployment seam, never a request flag or an attestation DTO alone.
// InstanceID must change across a go-judge restart; qualified facts cannot carry
// over to another process, image, kernel or security profile.
type IsolationVerifier interface {
	Verify(context.Context, FrozenIdentity) (string, error)
}

type Snapshot struct {
	SandboxReady         bool
	ToolchainReady       bool
	Qualified            bool
	MatureReady          bool
	ProblemtoolsVersion  string
	ProblemtoolsRevision string
	HelperProfile        string
	Identity             FrozenIdentity
	Languages            contract.LanguageCapabilities
}

func (t TaskInput) String() string {
	return fmt.Sprintf("runtime task [cases=%d source redacted]", len(t.Cases))
}
func (t TaskInput) GoString() string { return t.String() }
