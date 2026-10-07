package runtime

import (
	"bytes"
	"context"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/runtime/restclient"
)

// Program is a frozen package source reference, never a caller-selected argv.
// Python3 is available only for internal validation, not public submissions.
type Program struct {
	File       BlobRef `json:"file"`
	LanguageID string  `json:"languageId"`
}
type ValidationInput struct {
	JobID              contract.UUID  `json:"jobId"`
	ItemID             contract.UUID  `json:"itemId"`
	FencingToken       contract.UUID  `json:"fencingToken"`
	Identity           FrozenIdentity `json:"identity"`
	Limits             Limits         `json:"limits"`
	Cases              []Case         `json:"cases"`
	InputValidators    []Program      `json:"inputValidators"`
	AcceptedReferences []Program      `json:"acceptedReferences"`
}
type ProgramCaseEvidence struct {
	SourceSHA256   string                `json:"sourceSha256"`
	Ordinal        int                   `json:"ordinal"`
	Passed         bool                  `json:"passed"`
	Verdict        contract.JudgeVerdict `json:"verdict"`
	Status         restclient.Status     `json:"status"`
	ExitCode       int                   `json:"exitCode"`
	CPUTimeNS      uint64                `json:"cpuTimeNS"`
	WallTimeNS     uint64                `json:"wallTimeNS"`
	MemoryBytes    uint64                `json:"memoryBytes"`
	DiagnosticCode string                `json:"diagnosticCode"`
}
type ValidationOutcome struct {
	ValidatorsPassed   bool                  `json:"validatorsPassed"`
	ReferencesPassed   bool                  `json:"referencesPassed"`
	ValidatorCases     []ProgramCaseEvidence `json:"validatorCases"`
	ReferenceCases     []ProgramCaseEvidence `json:"referenceCases"`
	ValidatorCaseCount uint64                `json:"validatorCaseCount"`
	ReferenceCaseCount uint64                `json:"referenceCaseCount"`
}
type ValidationEvidence struct {
	Kind string              `json:"kind"`
	Case ProgramCaseEvidence `json:"case"`
}
type ValidationEvidenceFunc func(context.Context, ValidationEvidence) error

const MaxCollectedEvidence = 16384

type programArtifact struct {
	data     []byte
	language string
}

func (p Program) valid() bool {
	return p.File.valid() && p.File.SizeBytes > 0 && (p.LanguageID == LanguageID || p.LanguageID == "python3")
}
func (p programArtifact) argv() []string {
	if p.language == "python3" {
		return []string{"/usr/local/bin/python3", "-I", "/w/main.py"}
	}
	return []string{"/w/main"}
}
func (p programArtifact) name() string {
	if p.language == "python3" {
		return "main.py"
	}
	return "main"
}

func (a *Adapter) prepareProgram(ctx context.Context, id string, p Program) (programArtifact, contract.JudgeVerdict, string, error) {
	data, e := a.read(ctx, p.File)
	if e != nil {
		return programArtifact{}, "", "", e
	}
	if p.LanguageID == "python3" {
		return programArtifact{data: bytes.Clone(data), language: p.LanguageID}, contract.VerdictAC, "", nil
	}
	exe, verdict, code, e := a.compile(ctx, id, data)
	return programArtifact{data: exe, language: p.LanguageID}, verdict, code, e
}

// ValidatePrograms executes every real input validator and every ACCEPTED
// reference on every frozen test. It neither invents missing validators nor
// treats relaxed verifyproblem reference limits as this exact-profile evidence.
// The package owner separately retains all mature verifyproblem checkpoints.
func (a *Adapter) ValidatePrograms(ctx context.Context, input ValidationInput) (out ValidationOutcome, err error) {
	if uint64(len(input.Cases))*uint64(len(input.InputValidators)+len(input.AcceptedReferences)) > MaxCollectedEvidence {
		return out, failure("VALIDATION_EVIDENCE_SINK_REQUIRED", false)
	}
	return a.validatePrograms(ctx, input, nil)
}
func (a *Adapter) ValidateProgramsWithEvidence(ctx context.Context, input ValidationInput, sink ValidationEvidenceFunc) (ValidationOutcome, error) {
	if sink == nil {
		return ValidationOutcome{}, failure("VALIDATION_EVIDENCE_SINK_REQUIRED", false)
	}
	return a.validatePrograms(ctx, input, sink)
}
func (a *Adapter) validatePrograms(ctx context.Context, input ValidationInput, sink ValidationEvidenceFunc) (out ValidationOutcome, err error) {
	out.ValidatorCases = []ProgramCaseEvidence{}
	out.ReferenceCases = []ProgramCaseEvidence{}
	if input.JobID.Validate() != nil || input.ItemID.Validate() != nil || input.FencingToken.Validate() != nil || input.Identity != a.identity || input.Limits.Validate() != nil || len(input.Cases) < 1 || len(input.Cases) > 4096 || len(input.InputValidators) > 128 || len(input.AcceptedReferences) < 1 || len(input.AcceptedReferences) > 4096 {
		return out, failure("VALIDATION_INPUT_INVALID", false)
	}
	for _, program := range append(append([]Program{}, input.InputValidators...), input.AcceptedReferences...) {
		if !program.valid() {
			return out, failure("VALIDATION_PROGRAM_INVALID", false)
		}
	}
	for i, c := range input.Cases {
		if c.Ordinal != i+1 || !c.Input.valid() || !c.Answer.valid() || c.Checker.Validate() != nil {
			return out, failure("VALIDATION_CASE_INVALID", false)
		}
	}
	if !a.Snapshot(ctx).Qualified {
		return out, failure("RUNTIME_NOT_READY", false)
	}
	ledger, ok := a.ledger.(StepLedger)
	if !ok {
		return out, failure("VALIDATION_LEDGER_INVALID", false)
	}
	if e := ledger.BeginStep(ctx, input.JobID, input.FencingToken, "exact-programs:"+string(input.ItemID)); e != nil {
		return out, failure("ATTEMPT_ALREADY_DISPATCHED", false)
	}
	out.ValidatorsPassed = len(input.InputValidators) > 0
	out.ReferencesPassed = true
	for i, p := range input.InputValidators {
		program, verdict, code, e := a.prepareProgram(ctx, string(input.FencingToken)+"/validator/"+decimal(i+1)+"/compile", p)
		if e != nil {
			return out, e
		}
		for _, test := range input.Cases {
			evidence := ProgramCaseEvidence{SourceSHA256: p.File.SHA256, Ordinal: test.Ordinal, Verdict: verdict, DiagnosticCode: code}
			if verdict == contract.VerdictAC {
				data, e := a.read(ctx, test.Input)
				if e != nil {
					return out, e
				}
				r, e := a.runProgram(ctx, string(input.FencingToken)+"/validator/"+decimal(i+1)+"/case/"+decimal(test.Ordinal), program, data, validatorLimits())
				if e != nil {
					return out, e
				}
				evidence.Status = r.Status
				evidence.ExitCode = r.ExitStatus
				evidence.CPUTimeNS = r.CPUTimeNS
				evidence.WallTimeNS = r.WallTimeNS
				evidence.MemoryBytes = r.MemoryBytes
				evidence.Passed = !infrastructure(r) && r.Status == restclient.NonzeroExit && r.ExitStatus == 42
				if evidence.Passed {
					evidence.Verdict = contract.VerdictAC
				} else {
					evidence.Verdict = contract.VerdictIE
					evidence.DiagnosticCode = "INPUT_VALIDATOR_FAILED"
				}
			}
			if !evidence.Passed {
				out.ValidatorsPassed = false
			}
			out.ValidatorCaseCount++
			if sink != nil {
				if e := sink(ctx, ValidationEvidence{Kind: "VALIDATOR", Case: evidence}); e != nil {
					return out, failure("VALIDATION_EVIDENCE_FAILED", true)
				}
			} else {
				out.ValidatorCases = append(out.ValidatorCases, evidence)
			}
		}
	}
	for i, p := range input.AcceptedReferences {
		program, verdict, code, e := a.prepareProgram(ctx, string(input.FencingToken)+"/reference/"+decimal(i+1)+"/compile", p)
		if e != nil {
			return out, e
		}
		for _, test := range input.Cases {
			evidence := ProgramCaseEvidence{SourceSHA256: p.File.SHA256, Ordinal: test.Ordinal, Verdict: verdict, DiagnosticCode: code}
			if verdict == contract.VerdictAC {
				data, e := a.read(ctx, test.Input)
				if e != nil {
					return out, e
				}
				r, e := a.runReference(ctx, string(input.FencingToken)+"/reference/"+decimal(i+1)+"/case/"+decimal(test.Ordinal), program, data, test, input.Limits)
				if e != nil {
					return out, e
				}
				evidence.Verdict = r.Verdict
				evidence.Status = r.SandboxStatus
				evidence.ExitCode = r.ExitCode
				evidence.CPUTimeNS = r.CPUTimeNS
				evidence.WallTimeNS = r.WallTimeNS
				evidence.MemoryBytes = r.MemoryBytes
				evidence.Passed = r.Verdict == contract.VerdictAC
				if !evidence.Passed {
					evidence.DiagnosticCode = "ACCEPTED_REFERENCE_FAILED"
				}
			}
			if !evidence.Passed {
				out.ReferencesPassed = false
			}
			out.ReferenceCaseCount++
			if sink != nil {
				if e := sink(ctx, ValidationEvidence{Kind: "REFERENCE", Case: evidence}); e != nil {
					return out, failure("VALIDATION_EVIDENCE_FAILED", true)
				}
			} else {
				out.ReferenceCases = append(out.ReferenceCases, evidence)
			}
		}
	}
	return out, nil
}

func (a *Adapter) runProgram(ctx context.Context, id string, p programArtifact, input []byte, l Limits) (r restclient.Result, err error) {
	if e := a.verifyOperation(ctx); e != nil {
		return r, e
	}
	s := a.factory.NewSession()
	defer func() {
		if e := s.Close(); e != nil {
			a.failClosed()
			err = failure("SANDBOX_CLEANUP_FAILED", true)
		}
	}()
	in, e := s.Upload(ctx, input)
	if e != nil {
		return r, transportFailure(e, false)
	}
	program, e := s.Upload(ctx, p.data)
	if e != nil {
		return r, transportFailure(e, false)
	}
	return a.runOne(ctx, s, id, command(p.argv(), in, map[string]restclient.FileID{p.name(): program}, l))
}
func (a *Adapter) runReference(ctx context.Context, id string, p programArtifact, input []byte, test Case, l Limits) (r CaseResult, err error) {
	if e := a.verifyOperation(ctx); e != nil {
		return r, e
	}
	if p.language == LanguageID {
		return a.runCase(ctx, id, p.data, input, test, l)
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
		return r, transportFailure(e, false)
	}
	program, e := s.Upload(ctx, p.data)
	if e != nil {
		return r, transportFailure(e, false)
	}
	result, e := a.runOne(ctx, s, id+"/run", command(p.argv(), stdin, map[string]restclient.FileID{p.name(): program}, l))
	if e != nil {
		return r, e
	}
	r = CaseResult{TestCaseID: test.TestCaseID, Ordinal: test.Ordinal, Verdict: contestantVerdict(result), CPUTimeNS: result.CPUTimeNS, WallTimeNS: result.WallTimeNS, MemoryBytes: result.MemoryBytes, ExitCode: result.ExitStatus, SandboxStatus: result.Status}
	if r.Verdict != contract.VerdictAC {
		return r, nil
	}
	output, ok := result.CachedFiles["stdout"]
	if !ok {
		r.Verdict = contract.VerdictIE
		return r, nil
	}
	answer, e := a.read(ctx, test.Answer)
	if e != nil {
		return r, e
	}
	r.Verdict, r.CheckerStatus, e = a.check(ctx, s, id+"/checker", output, stdin, answer, test.Checker)
	return r, e
}
