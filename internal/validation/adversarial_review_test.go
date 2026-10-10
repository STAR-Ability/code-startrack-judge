package validation

import (
	"context"
	"errors"
	"testing"

	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
)

type reviewOversizedAmbiguousMature struct{ mockMature }

func (m *reviewOversizedAmbiguousMature) Verify(ctx context.Context, input MatureInput) (MatureOutcome, error) {
	out, _ := m.mockMature.Verify(ctx, input)
	out.RawLog = make([]byte, MaxPrivateLogBytes+1)
	return out, &judgeruntime.Failure{Code: "TRANSPORT_UNCERTAIN", Ambiguous: true}
}

func TestReviewOversizedPartialMatureLogPreservesAmbiguousRecovery(t *testing.T) {
	engine := &mockEngine{}
	v, err := New(Options{Engine: engine, Mature: &reviewOversizedAmbiguousMature{}, ControlFlowOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	report, err := v.Validate(context.Background(), request(t, noop))
	var failure *judgeruntime.Failure
	if !errors.As(err, &failure) || !failure.Ambiguous || !report.FinishedAt.IsZero() || engine.called {
		t.Fatal("oversized partial diagnostics turned ambiguous execution into a terminal validation run")
	}
}

type reviewIgnoredMalformedEventEngine struct{ mockEngine }

func (m *reviewIgnoredMalformedEventEngine) ValidateProgramsWithEvidence(ctx context.Context, input judgeruntime.ValidationInput, sink judgeruntime.ValidationEvidenceFunc) (judgeruntime.ValidationOutcome, error) {
	// A malformed helper event must remain fatal even if a helper mistakenly
	// ignores the callback's rejection and later reports complete valid totals.
	_ = sink(ctx, judgeruntime.ValidationEvidence{Kind: "UNRECOGNIZED"})
	return m.mockEngine.ValidateProgramsWithEvidence(ctx, input, sink)
}

func TestReviewMalformedEventCannotBeOverwrittenByLaterCompleteEvidence(t *testing.T) {
	v, err := New(Options{Engine: &reviewIgnoredMalformedEventEngine{}, Mature: &mockMature{}, ControlFlowOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	report, err := v.Validate(context.Background(), request(t, noop))
	if err == nil && report.Results.AllPassed() {
		t.Fatal("malformed helper event disappeared behind later successful evidence")
	}
}
