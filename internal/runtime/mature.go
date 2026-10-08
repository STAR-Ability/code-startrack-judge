// SPDX-License-Identifier: Apache-2.0
package runtime

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/packages"
	"github.com/STAR-Ability/code-startrack-judge/internal/runtime/restclient"
)

const GraderSourceSHA256 = "054b86e6de225d45eb63c548d058ddf326e37b7af517904ff34f89e024bae205"
const MaxMatureFrameBytes = 192 << 20
const ProblemtoolsVersion = "v1.20260907"
const ProblemtoolsRevision = "6010cbaa37a1612117f49566b2fff8646d53faa2"
const MatureHelperProfile = "ROLE_SEPARATED_PROBLEMTOOLS_V1"

// MatureInput is an authenticated private import DTO. Its manifest is sealed;
// callers cannot supply commands, checker flags, paths outside that artifact,
// network destinations, or execution limits different from the manifest.
type MatureInput struct {
	JobID        contract.UUID     `json:"jobId"`
	ItemID       contract.UUID     `json:"itemId"`
	FencingToken contract.UUID     `json:"fencingToken"`
	Identity     FrozenIdentity    `json:"identity"`
	Manifest     packages.Manifest `json:"manifest"`
}

func (MatureInput) String() string     { return "private mature validation input [artifact redacted]" }
func (m MatureInput) GoString() string { return m.String() }
func (m MatureInput) valid() bool {
	return m.JobID.Validate() == nil && m.ItemID.Validate() == nil && m.FencingToken.Validate() == nil && m.Identity.Validate() == nil && packages.ValidateManifest(m.Manifest) == nil
}

type MaturePartOutcome struct {
	Part     string `json:"part"`
	Passed   bool   `json:"passed"`
	Errors   int    `json:"errors"`
	Warnings int    `json:"warnings"`
	NotRun   bool   `json:"notRun"`
}
type MatureOutcome struct {
	Completed bool                `json:"completed"`
	Parts     []MaturePartOutcome `json:"parts"`
	Errors    int                 `json:"errors"`
	Warnings  int                 `json:"warnings"`
	RawLog    []byte              `json:"rawLog"`
}

func (MatureOutcome) String() string     { return "private mature outcome [diagnostics redacted]" }
func (m MatureOutcome) GoString() string { return m.String() }

func (m MatureOutcome) valid() bool {
	if len(m.Parts) != 5 || m.Errors < 0 || m.Errors > 1000000 || m.Warnings < 0 || m.Warnings > 1000000 || len(m.RawLog) > 2<<20 {
		return false
	}
	seen := map[string]bool{}
	errorsTotal, warningsTotal := 0, 0
	for _, p := range m.Parts {
		switch p.Part {
		case "STRUCTURE", "STATEMENT", "TEST_DATA", "VALIDATORS", "REFERENCES":
		default:
			return false
		}
		if seen[p.Part] || p.Errors < 0 || p.Errors > 1000000 || p.Warnings < 0 || p.Warnings > 1000000 || p.Passed != (p.Errors == 0 && !p.NotRun) {
			return false
		}
		seen[p.Part] = true
		errorsTotal += p.Errors
		warningsTotal += p.Warnings
	}
	return m.Errors == errorsTotal && m.Warnings == warningsTotal
}

// MatureRequest is emitted only by the trusted wrapper. Native operations are
// a finite protocol whose inputs are resolved from the frozen artifact by Go.
type MatureRequest struct {
	Operation    string `json:"operation"`
	ProgramPath  string `json:"programPath,omitempty"`
	Ordinal      int    `json:"ordinal,omitempty"`
	InputBase64  string `json:"inputBase64,omitempty"`
	OutputBase64 string `json:"outputBase64,omitempty"`
}
type MatureResponse struct {
	OK             bool   `json:"ok"`
	Code           string `json:"code"`
	Compiled       bool   `json:"compiled"`
	WaitStatus     int    `json:"waitStatus"`
	CPUNS          uint64 `json:"cpuNs"`
	StdoutBase64   string `json:"stdoutBase64"`
	StderrBase64   string `json:"stderrBase64"`
	FeedbackBase64 string `json:"feedbackBase64"`
	Errors         int    `json:"errors"`
	Warnings       int    `json:"warnings"`
}

func (MatureRequest) String() string      { return "private mature request [program and bytes redacted]" }
func (r MatureRequest) GoString() string  { return r.String() }
func (MatureResponse) String() string     { return "private mature response [stdio redacted]" }
func (r MatureResponse) GoString() string { return r.String() }

type MatureHandler func(context.Context, MatureRequest) (MatureResponse, error)
type MatureRunner interface {
	Run(context.Context, MatureInput, BlobReader, MatureHandler) (MatureOutcome, error)
}

func (a *Adapter) RunMature(ctx context.Context, input MatureInput) (MatureOutcome, error) {
	if !input.valid() || input.Identity != a.identity {
		return MatureOutcome{}, failure("MATURE_INPUT_INVALID", false)
	}
	if len(a.grader) == 0 || a.matureRunner == nil {
		return MatureOutcome{}, failure("MATURE_HELPER_UNAVAILABLE", false)
	}
	if !a.Snapshot(ctx).MatureReady {
		return MatureOutcome{}, failure("RUNTIME_NOT_READY", false)
	}
	ledger, ok := a.ledger.(StepLedger)
	if !ok {
		return MatureOutcome{}, failure("VALIDATION_LEDGER_INVALID", false)
	}
	if e := ledger.BeginStep(ctx, input.JobID, input.FencingToken, "problemtools:"+string(input.ItemID)); e != nil {
		return MatureOutcome{}, failure("ATTEMPT_ALREADY_DISPATCHED", false)
	}
	programs := map[string]Program{}
	validators, references := map[string]bool{}, map[string]bool{}
	for _, p := range input.Manifest.InputValidators {
		programs[p.File.Path] = Program{LanguageID: p.LanguageID, File: refFromManifest(p.File)}
		validators[p.File.Path] = true
	}
	for _, p := range input.Manifest.ReferenceSolutions {
		programs[p.File.Path] = Program{LanguageID: p.LanguageID, File: refFromManifest(p.File)}
		references[p.File.Path] = true
	}
	prepared := map[string]programArtifact{}
	compileResponses := map[string]MatureResponse{}
	requestNumber := 0
	handle := func(ctx context.Context, r MatureRequest) (MatureResponse, error) {
		requestNumber++
		if requestNumber > 1<<25 {
			return MatureResponse{}, failure("MATURE_OPERATION_BOUNDS", false)
		}
		id := string(input.FencingToken) + "/problemtools/" + decimal(requestNumber)
		response := MatureResponse{}
		programFields := r.ProgramPath != "" && r.Ordinal == 0 && r.InputBase64 == "" && r.OutputBase64 == ""
		switch r.Operation {
		case "COMPILE":
			p, exists := programs[r.ProgramPath]
			if !programFields || !exists {
				return response, failure("MATURE_OPERATION_INVALID", false)
			}
			if cached, exists := compileResponses[r.ProgramPath]; exists {
				return cached, nil
			}
			artifact, compiled, e := a.matureCompile(ctx, id+"/compile", p)
			if e != nil {
				return response, e
			}
			response = compiled
			if response.Compiled {
				prepared[r.ProgramPath] = artifact
			}
			compileResponses[r.ProgramPath] = response
			return response, nil
		case "RUN_REFERENCE", "RUN_VALIDATOR":
			artifact, exists := prepared[r.ProgramPath]
			if !exists || r.OutputBase64 != "" {
				return response, failure("MATURE_OPERATION_INVALID", false)
			}
			var data []byte
			l := validatorLimits()
			if r.Operation == "RUN_REFERENCE" {
				if !references[r.ProgramPath] || r.Ordinal < 1 || r.Ordinal > len(input.Manifest.Tests) || r.InputBase64 != "" {
					return response, failure("MATURE_OPERATION_INVALID", false)
				}
				var e error
				data, e = a.read(ctx, refFromManifest(input.Manifest.Tests[r.Ordinal-1].Input))
				if e != nil {
					return response, e
				}
				l = limitsFromManifest(input.Manifest.Limits)
			} else {
				if !validators[r.ProgramPath] || r.Ordinal != 0 {
					return response, failure("MATURE_OPERATION_INVALID", false)
				}
				var e error
				data, e = decodeMatureBytes(r.InputBase64, MaxFileBytes)
				if e != nil {
					return response, e
				}
			}
			return a.matureRunBytes(ctx, id, artifact.argv(), data, map[string][]byte{artifact.name(): artifact.data}, l)
		case "GRADE":
			if r.ProgramPath != "" || r.Ordinal != 0 || r.OutputBase64 != "" {
				return response, failure("MATURE_OPERATION_INVALID", false)
			}
			data, e := decodeMatureBytes(r.InputBase64, MaxFileBytes)
			if e != nil {
				return response, e
			}
			return a.matureRunBytes(ctx, id, []string{"/usr/local/bin/python3", "-I", "/w/default_grader.py"}, data, map[string][]byte{"default_grader.py": a.grader}, checkerLimits())
		case "CHECK_OUTPUT":
			if r.ProgramPath != "" || r.Ordinal < 1 || r.Ordinal > len(input.Manifest.Tests) || r.InputBase64 != "" {
				return response, failure("MATURE_OPERATION_INVALID", false)
			}
			output, e := decodeMatureBytes(r.OutputBase64, int64(input.Manifest.Limits.OutputLimitBytes))
			if e != nil {
				return response, e
			}
			c := input.Manifest.Tests[r.Ordinal-1]
			in, e := a.read(ctx, refFromManifest(c.Input))
			if e != nil {
				return response, e
			}
			answer, e := a.read(ctx, refFromManifest(c.Answer))
			if e != nil {
				return response, e
			}
			return a.matureRunBytes(ctx, id, checkerFromManifest(c.Checker).args(), output, map[string][]byte{"default_validator": a.checker, "input": in, "answer": answer}, checkerLimits())
		case "STATEMENT_PDF", "STATEMENT_HTML":
			if r.ProgramPath != "" || r.Ordinal != 0 || r.InputBase64 != "" || r.OutputBase64 != "" {
				return response, failure("MATURE_OPERATION_INVALID", false)
			}
			files, e := a.matureStatementFiles(ctx, input.Manifest)
			if e != nil {
				return response, e
			}
			bridge, e := a.bridgeBytes(ctx)
			if e != nil {
				return response, e
			}
			files["problemtools-bridge.py"] = bridge
			kind := "pdf"
			if r.Operation == "STATEMENT_HTML" {
				kind = "html"
			}
			response, e = a.matureRunBytes(ctx, id, []string{"/usr/local/bin/python3", "-I", "/w/problemtools-bridge.py", "--statement", kind}, nil, files, statementLimits())
			if e != nil {
				return response, e
			}
			raw, e := decodeMatureBytes(response.StdoutBase64, 8<<20)
			if e != nil {
				return response, e
			}
			var report struct {
				OK       bool `json:"ok"`
				Errors   int  `json:"errors"`
				Warnings int  `json:"warnings"`
			}
			if response.WaitStatus != 0 && len(bytes.TrimSpace(raw)) == 0 {
				response.Errors = 1
				return response, nil
			}
			if strictDecode(bytes.TrimSpace(raw), &report) != nil || report.Errors < 0 || report.Errors > 1000000 || report.Warnings < 0 || report.Warnings > 1000000 {
				return response, failure("MATURE_STATEMENT_REPORT_INVALID", false)
			}
			if response.WaitStatus != 0 || !report.OK {
				if report.Errors == 0 {
					report.Errors = 1
				}
			}
			response.Errors, response.Warnings = report.Errors, report.Warnings
			return response, nil
		default:
			return response, failure("MATURE_OPERATION_INVALID", false)
		}
	}
	reader := a.reader
	if scoped, ok := ctx.Value(blobReaderContextKey{}).(BlobReader); ok {
		reader = scoped
	}
	out, e := a.matureRunner.Run(ctx, input, reader, handle)
	if e != nil {
		var f *Failure
		if errors.As(e, &f) && f.Code == "MATURE_SPOOL_CLEANUP_FAILED" {
			a.failClosed()
		}
		return out, e
	}
	if !out.valid() {
		return MatureOutcome{}, failure("MATURE_REPORT_INVALID", false)
	}
	return out, nil
}

func decodeMatureBytes(encoded string, max int64) ([]byte, error) {
	if int64(len(encoded)) > (max+2)/3*4 {
		return nil, failure("MATURE_BYTES_BOUNDS", false)
	}
	raw, e := base64.StdEncoding.Strict().DecodeString(encoded)
	if e != nil || int64(len(raw)) > max {
		return nil, failure("MATURE_BYTES_INVALID", false)
	}
	return raw, nil
}
func matureWaitStatus(r restclient.Result) int {
	switch r.Status {
	case restclient.Accepted, restclient.NonzeroExit:
		return (r.ExitStatus & 255) << 8
	case restclient.Signalled:
		if r.ExitStatus > 0 && r.ExitStatus < 128 {
			return r.ExitStatus
		}
		return 9
	case restclient.DangerousSyscall:
		return 31
	case restclient.TimeLimit:
		// Mature judging recognizes SIGXCPU as TLE independently of its
		// relaxed comparison window. The exact runtime status/CPU facts stay
		// in separate original evidence; this is a compatibility projection
		// for both CPU and wall TimeLimit, never a raised source limit.
		return 24
	default:
		return 9
	}
}
func statementLimits() Limits {
	return Limits{CPUTimeNS: uint64(120 * time.Second), WallTimeNS: uint64(240 * time.Second), MemoryBytes: 2 << 30, OutputBytes: 8 << 20, Processes: 128}
}

func (a *Adapter) bridgeBytes(ctx context.Context) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || !digestPattern.MatchString(a.bridgeDigest) {
		return nil, failure("MATURE_HELPER_IDENTITY_INVALID", false)
	}
	raw, e := readTrustedHelper(MatureBridgePath, 1<<20)
	if e != nil || !bytesMatch(raw, BlobRef{SHA256: a.bridgeDigest, SizeBytes: int64(len(raw))}) {
		return nil, failure("MATURE_HELPER_IDENTITY_INVALID", false)
	}
	return raw, nil
}

func (a *Adapter) matureRunBytes(ctx context.Context, id string, argv []string, input []byte, files map[string][]byte, l Limits) (response MatureResponse, err error) {
	if e := a.verifyOperation(ctx); e != nil {
		return response, e
	}
	s := a.factory.NewSession()
	defer func() {
		if e := s.Close(); e != nil {
			a.failClosed()
			err = failure("SANDBOX_CLEANUP_FAILED", true)
		}
	}()
	stdin, e := s.Upload(ctx, input)
	if e != nil {
		return response, transportFailure(e, false)
	}
	copyIn := map[string]restclient.FileID{}
	for name, data := range files {
		id, e := s.Upload(ctx, data)
		if e != nil {
			return response, transportFailure(e, false)
		}
		copyIn[name] = id
	}
	cmd := command(argv, stdin, copyIn, l)
	checkerRun := len(argv) > 0 && argv[0] == "/usr/local/bin/startrack-checker-launcher"
	if checkerRun {
		cmd.CopyOutCached = append(cmd.CopyOutCached, restclient.Output{Name: "feedback/judgemessage.txt"})
	}
	r, e := a.runOne(ctx, s, id, cmd)
	if e != nil {
		return response, e
	}
	if infrastructure(r) {
		return response, failure("MATURE_SANDBOX_INFRASTRUCTURE_FAILED", false)
	}
	// Native checker exits 42/43 are NonzeroExit, for which the REST projection
	// permits absent outputs. A captured empty file is valid; a missing file is not.
	if _, exists := r.CachedFiles["feedback/judgemessage.txt"]; checkerRun && !exists {
		return response, failure("MATURE_CHECKER_FEEDBACK_MISSING", false)
	}
	response.OK, response.Compiled, response.WaitStatus, response.CPUNS = true, true, matureWaitStatus(r), r.CPUTimeNS
	for name, target := range map[string]*string{"stdout": &response.StdoutBase64, "stderr": &response.StderrBase64} {
		file, exists := r.CachedFiles[name]
		if !exists {
			return response, failure("MATURE_STDIO_MISSING", false)
		}
		data, e := s.Download(ctx, file, int64(l.OutputBytes))
		if e != nil {
			return response, transportFailure(e, false)
		}
		*target = base64.StdEncoding.EncodeToString(data)
	}
	if file, exists := r.CachedFiles["feedback/judgemessage.txt"]; exists {
		data, e := s.Download(ctx, file, 8<<20)
		if e != nil {
			return response, transportFailure(e, false)
		}
		response.FeedbackBase64 = base64.StdEncoding.EncodeToString(data)
	}
	return response, nil
}
func (a *Adapter) matureStatementFiles(ctx context.Context, m packages.Manifest) (map[string][]byte, error) {
	allowed := map[string]BlobRef{m.Statement.ValidationView.Path: refFromManifest(m.Statement.ValidationView)}
	for _, f := range m.Files {
		if f.Role == "OTHER" && strings.HasPrefix(f.NormalizedPath, "problem_statement/") || f.NormalizedPath == "problem.yaml" {
			allowed[f.NormalizedPath] = BlobRef{SHA256: f.NormalizedSHA256, SizeBytes: f.NormalizedSizeBytes}
		}
	}
	for _, c := range m.Tests {
		if c.Visibility == "SAMPLE" {
			allowed[c.Input.Path] = refFromManifest(c.Input)
			allowed[c.Answer.Path] = refFromManifest(c.Answer)
		}
	}
	files := map[string][]byte{}
	for path, ref := range allowed {
		raw, e := a.read(ctx, ref)
		if e != nil {
			return nil, e
		}
		files["problem/"+path] = raw
	}
	return statementChunks(files)
}
