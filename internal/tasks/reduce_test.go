package tasks

import (
	"testing"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
)

func expectedCases(n int) []judgeruntime.Case {
	result := make([]judgeruntime.Case, n)
	for i := range result {
		id, _ := contract.NewUUID()
		result[i] = judgeruntime.Case{TestCaseID: id, Ordinal: i + 1}
	}
	return result
}
func TestReducerUsesOrderedFactsAndExactCeiling(t *testing.T) {
	expected := expectedCases(3)
	out := judgeruntime.Outcome{Result: contract.JudgeResult{Verdict: contract.VerdictAC, PassedTestCount: 999, TotalTestCount: 999}}
	for i, verdict := range []contract.JudgeVerdict{contract.VerdictWA, contract.VerdictTLE, contract.VerdictAC} {
		out.Cases = append(out.Cases, judgeruntime.CaseResult{TestCaseID: expected[i].TestCaseID, Ordinal: i + 1, Verdict: verdict, CPUTimeNS: uint64(i+1)*1000000 + 1, MemoryBytes: uint64((i + 1) * 100)})
	}
	final, err := Reduce(expected, out, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if final.Result.Verdict != contract.VerdictWA || final.Result.PassedTestCount != 1 || final.Result.TotalTestCount != 3 || *final.Result.TimeMs != 4 || *final.Result.MemoryBytes != 300 || final.Result.Score != nil {
		t.Fatalf("incorrect ordered aggregates: %+v", final.Result)
	}
	out.Cases[1].Ordinal = 1
	if _, err := Reduce(expected, out, time.Now()); err != ErrInvalid {
		t.Fatal("accepted mismatched case order")
	}
}
func TestReducerSafeCEAndInterruptedFacts(t *testing.T) {
	expected := expectedCases(2)
	raw := "credential /private/answer SECRET"
	code := "COMPILATION_FAILED"
	final, err := Reduce(expected, judgeruntime.Outcome{Result: contract.JudgeResult{Verdict: contract.VerdictCE, CompileLog: &raw, DiagnosticCode: &code}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if final.Result.TimeMs != nil || final.Result.MemoryBytes != nil || final.Result.PassedTestCount != 0 || *final.Result.CompileLog != "Compilation failed (COMPILATION_FAILED)." || len(final.Cases) != 2 || final.Cases[0].Verdict != "SKIPPED" {
		t.Fatal("CE did not preserve safe null resources/skipped facts")
	}
	code = "JUDGE_INTERRUPTED"
	final, err = Reduce(expected, judgeruntime.Outcome{Result: contract.JudgeResult{Verdict: contract.VerdictIE, DiagnosticCode: &code}, Error: &contract.TaskError{Code: code, Message: raw, Retryable: true}}, time.Now())
	if err != nil || final.Error == nil || final.Error.Retryable || final.Error.Message != "Controlled execution failed" || final.Result.Verdict != contract.VerdictIE {
		t.Fatal("interruption was not a bounded immutable IE")
	}
}
func TestReducerRejectsPartialACAndWrongArtifactCase(t *testing.T) {
	expected := expectedCases(2)
	out := judgeruntime.Outcome{Result: contract.JudgeResult{Verdict: contract.VerdictAC}}
	out.Cases = []judgeruntime.CaseResult{{TestCaseID: expected[0].TestCaseID, Ordinal: 1, Verdict: contract.VerdictAC}}
	if _, err := Reduce(expected, out, time.Now()); err != ErrInvalid {
		t.Fatal("partial execution reported AC")
	}
	other, _ := contract.NewUUID()
	out.Cases[0].TestCaseID = other
	if _, err := Reduce(expected, out, time.Now()); err != ErrInvalid {
		t.Fatal("borrowed another test case")
	}
}

func TestDefinitiveInfrastructureIEOverridesUserVerdict(t *testing.T) {
	for _, verdict := range []contract.JudgeVerdict{contract.VerdictWA, contract.VerdictAC, contract.VerdictCE} {
		t.Run(string(verdict), func(t *testing.T) {
			expected := expectedCases(2)
			code := "SANDBOX_CLEANUP_FAILED"
			out := judgeruntime.Outcome{Result: contract.JudgeResult{Verdict: verdict}, Error: &contract.TaskError{Code: code, Message: "private diagnostic", Retryable: true}}
			if verdict != contract.VerdictCE {
				out.Cases = []judgeruntime.CaseResult{{TestCaseID: expected[0].TestCaseID, Ordinal: 1, Verdict: verdict, CPUTimeNS: 1, MemoryBytes: 100}}
			}
			final, err := Reduce(expected, out, time.Now())
			if err != nil || final.Result.Verdict != contract.VerdictIE || final.Error == nil || final.Error.Code != code || final.Error.Retryable || final.Result.CompileLog != nil || len(final.Cases) != 2 {
				t.Fatal("definitive infrastructure failure did not override user verdict")
			}
			if verdict == contract.VerdictAC && final.Result.PassedTestCount != 1 {
				t.Fatal("IE lost executed AC fact")
			}
			if verdict == contract.VerdictCE && (final.Result.TimeMs != nil || final.Result.MemoryBytes != nil) {
				t.Fatal("unexecuted IE invented resources")
			}
		})
	}
}
