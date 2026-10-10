// SPDX-License-Identifier: Apache-2.0

package validation

import (
	"context"
	"strings"
	"testing"

	"github.com/STAR-Ability/code-startrack-judge/internal/packages"
	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
)

type clientFixture struct {
	snapshot judgeruntime.Snapshot
	input    judgeruntime.MatureInput
	called   bool
	lose     bool
}

func (c *clientFixture) Snapshot(context.Context) judgeruntime.Snapshot { return c.snapshot }
func (c *clientFixture) RunMature(_ context.Context, input judgeruntime.MatureInput) (judgeruntime.MatureOutcome, error) {
	c.input, c.called = input, true
	if c.lose {
		c.snapshot.MatureReady = false
	}
	return judgeruntime.MatureOutcome{Completed: true, Parts: []judgeruntime.MaturePartOutcome{{Part: "STATEMENT", NotRun: true}}, RawLog: []byte("private diagnostics")}, nil
}

func clientInput(t *testing.T) MatureInput {
	t.Helper()
	return MatureInput{JobID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", FencingToken: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", StepName: "problemtools:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", Identity: mockIdentity(), Candidate: candidate(t), FixedTimeLimitSeconds: "1.25"}
}
func newClientFixture() *clientFixture {
	return &clientFixture{snapshot: judgeruntime.Snapshot{Qualified: true, SandboxReady: true, ToolchainReady: true, MatureReady: true, Identity: mockIdentity(), ProblemtoolsVersion: ProblemtoolsVersion, ProblemtoolsRevision: packages.CheckerRevision, HelperProfile: HelperProfile}}
}

func TestMatureClientRequiresInstalledHelperQualification(t *testing.T) {
	fixture := newClientFixture()
	fixture.snapshot.MatureReady = false
	client, err := NewMatureClient(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if client.Snapshot(context.Background()).Qualified {
		t.Fatal("generic sandbox qualification implied mature helper readiness")
	}
	if _, err := client.Verify(context.Background(), clientInput(t)); err != ErrUnavailable || fixture.called {
		t.Fatal("unqualified mature helper dispatched")
	}
}

func TestMatureClientPreservesFenceItemSkippedPartsAndPrivateLog(t *testing.T) {
	fixture := newClientFixture()
	client, _ := NewMatureClient(fixture)
	input := clientInput(t)
	out, err := client.Verify(context.Background(), input)
	if err != nil || !out.Completed || len(out.Parts) != 1 || !out.Parts[0].NotRun || out.Parts[0].Passed || string(out.RawLog) != "private diagnostics" || fixture.input.JobID != input.JobID || fixture.input.FencingToken != input.FencingToken || string(fixture.input.ItemID) != strings.TrimPrefix(input.StepName, "problemtools:") || fixture.input.Identity != input.Identity {
		t.Fatal("mature scheduler evidence or owning identity changed")
	}
}

func TestMatureClientRejectsChangedTimeOrItemBeforeDispatch(t *testing.T) {
	for _, alter := range []func(*MatureInput){func(input *MatureInput) { input.FixedTimeLimitSeconds = "1.250" }, func(input *MatureInput) { input.StepName = "other:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" }} {
		fixture := newClientFixture()
		client, _ := NewMatureClient(fixture)
		input := clientInput(t)
		alter(&input)
		if _, err := client.Verify(context.Background(), input); err != ErrInvalid || fixture.called {
			t.Fatal("mature input drift dispatched")
		}
	}
}

func TestMatureClientIdentityLossRequiresCountedRecovery(t *testing.T) {
	fixture := newClientFixture()
	fixture.lose = true
	client, _ := NewMatureClient(fixture)
	_, err := client.Verify(context.Background(), clientInput(t))
	failure, ok := err.(*judgeruntime.Failure)
	if !ok || !failure.Ambiguous || !fixture.called {
		t.Fatal("post-dispatch mature identity loss became terminal proof")
	}
}
