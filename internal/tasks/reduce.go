package tasks

import (
	"regexp"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
)

var diagnosticPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

const maxSafe = uint64(9007199254740991)

// Reduce derives authoritative aggregates from this attempt's ordered facts.
// Adapter aggregates, timestamps, scores, messages and raw logs are ignored.
func Reduce(expected []judgeruntime.Case, out judgeruntime.Outcome, now time.Time) (Final, error) {
	f := Final{Result: contract.JudgeResult{Verdict: contract.VerdictAC, TotalTestCount: contract.SafeInt(len(expected)), JudgedAt: contract.UTC(now)}, Cases: make([]CaseFact, 0, len(expected))}
	if len(expected) < 1 || len(expected) > 65536 || len(out.Cases) > len(expected) {
		return Final{}, ErrInvalid
	}
	for i, c := range expected {
		if c.Ordinal != i+1 || c.TestCaseID.Validate() != nil {
			return Final{}, ErrInvalid
		}
	}
	diagnostic := ""
	if out.Result.DiagnosticCode != nil {
		diagnostic = *out.Result.DiagnosticCode
		if !diagnosticPattern.MatchString(diagnostic) {
			return Final{}, ErrInvalid
		}
		f.Result.DiagnosticCode = &diagnostic
	}
	infrastructure := out.Error != nil || out.Result.Verdict == contract.VerdictIE
	if out.Result.Verdict == contract.VerdictCE {
		if len(out.Cases) != 0 {
			return Final{}, ErrInvalid
		}
		f.Result.Verdict = contract.VerdictCE
		log := "Compilation failed."
		if diagnostic != "" {
			log = "Compilation failed (" + diagnostic + ")."
		}
		f.Result.CompileLog = &log
	} else {
		failed := false
		for i, c := range out.Cases {
			if c.TestCaseID != expected[i].TestCaseID || c.Ordinal != i+1 || c.MemoryBytes > maxSafe || c.CPUTimeNS > maxSafe || c.WallTimeNS > maxSafe {
				return Final{}, ErrInvalid
			}
			switch c.Verdict {
			case contract.VerdictAC, contract.VerdictWA, contract.VerdictTLE, contract.VerdictMLE, contract.VerdictRE, contract.VerdictOLE, contract.VerdictIE:
			default:
				return Final{}, ErrInvalid
			}
			cpu, wall, memory := contract.SafeInt(ceilMS(c.CPUTimeNS)), contract.SafeInt(ceilMS(c.WallTimeNS)), contract.SafeInt(c.MemoryBytes)
			exit, sandbox, checker := c.ExitCode, string(c.SandboxStatus), string(c.CheckerStatus)
			if len(sandbox) > 64 || len(checker) > 64 {
				return Final{}, ErrInvalid
			}
			f.Cases = append(f.Cases, CaseFact{TestCaseID: c.TestCaseID, Ordinal: c.Ordinal, Verdict: string(c.Verdict), CPUTimeMS: &cpu, WallTimeMS: &wall, MemoryBytes: &memory, ExitCode: &exit, SandboxStatus: &sandbox, CheckerStatus: &checker})
			if f.Result.TimeMs == nil || cpu > *f.Result.TimeMs {
				f.Result.TimeMs = &cpu
			}
			if f.Result.MemoryBytes == nil || memory > *f.Result.MemoryBytes {
				f.Result.MemoryBytes = &memory
			}
			if c.Verdict == contract.VerdictAC {
				f.Result.PassedTestCount++
			} else if !failed {
				f.Result.Verdict = c.Verdict
				failed = true
			}
		}
		if !failed && len(out.Cases) != len(expected) {
			if !infrastructure {
				return Final{}, ErrInvalid
			}
			f.Result.Verdict = contract.VerdictIE
		}
	}
	if infrastructure {
		f.Result.Verdict = contract.VerdictIE
		f.Result.CompileLog = nil
	}
	for i := len(f.Cases); i < len(expected); i++ {
		f.Cases = append(f.Cases, CaseFact{TestCaseID: expected[i].TestCaseID, Ordinal: i + 1, Verdict: "SKIPPED"})
	}
	if f.Result.Verdict == contract.VerdictIE {
		code := diagnostic
		if out.Error != nil {
			code = out.Error.Code
		}
		if code == "" {
			code = "JUDGE_EXECUTION_FAILED"
		}
		if !diagnosticPattern.MatchString(code) {
			return Final{}, ErrInvalid
		}
		f.Result.DiagnosticCode = &code
		f.Error = &contract.TaskError{Code: code, Message: "Controlled execution failed", Retryable: false}
	} else if out.Error != nil {
		return Final{}, ErrInvalid
	}
	if f.Result.Validate() != nil {
		return Final{}, ErrInvalid
	}
	return f, nil
}
func ceilMS(ns uint64) uint64 {
	return ns/uint64(time.Millisecond) + boolUint(ns%uint64(time.Millisecond) != 0)
}
func boolUint(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}
