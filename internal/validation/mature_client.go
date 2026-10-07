// SPDX-License-Identifier: Apache-2.0

package validation

import (
	"bytes"
	"context"
	"strings"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/packages"
	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
)

// MatureRuntime is the authenticated private scheduler, optionally wrapped by
// the application's database/storage readiness gates. It never exposes native
// execution commands or the go-judge credential to validation orchestration.
type MatureRuntime interface {
	Snapshot(context.Context) judgeruntime.Snapshot
	RunMature(context.Context, judgeruntime.MatureInput) (judgeruntime.MatureOutcome, error)
}

type MatureClient struct{ runtime MatureRuntime }

func NewMatureClient(runtime MatureRuntime) (*MatureClient, error) {
	if runtime == nil {
		return nil, ErrInvalid
	}
	return &MatureClient{runtime: runtime}, nil
}

func (m *MatureClient) Snapshot(ctx context.Context) MatureSnapshot {
	if m == nil || m.runtime == nil || ctx == nil || ctx.Err() != nil {
		return MatureSnapshot{}
	}
	snapshot := m.runtime.Snapshot(ctx)
	if !snapshot.Qualified || !snapshot.SandboxReady || !snapshot.ToolchainReady || !snapshot.MatureReady || snapshot.Identity.Validate() != nil || snapshot.ProblemtoolsVersion != ProblemtoolsVersion || snapshot.ProblemtoolsRevision != packages.CheckerRevision || snapshot.HelperProfile != HelperProfile {
		return MatureSnapshot{}
	}
	return MatureSnapshot{Qualified: true, Identity: snapshot.Identity, ProblemtoolsVersion: ProblemtoolsVersion, ProblemtoolsRevision: packages.CheckerRevision, HelperProfile: HelperProfile}
}

func (m *MatureClient) Verify(ctx context.Context, input MatureInput) (out MatureOutcome, err error) {
	if m == nil || m.runtime == nil || ctx == nil || input.JobID.Validate() != nil || input.FencingToken.Validate() != nil || input.Identity.Validate() != nil || verifyCandidate(input.Candidate) != nil {
		return out, ErrInvalid
	}
	item := contract.UUID(strings.TrimPrefix(input.StepName, "problemtools:"))
	if item.Validate() != nil || input.StepName != "problemtools:"+strings.ToLower(string(item)) || input.FixedTimeLimitSeconds != fixedSeconds(input.Candidate.Manifest.Limits.TimeLimitMS) {
		return out, ErrInvalid
	}
	before := m.Snapshot(ctx)
	if !before.Qualified || before.Identity != input.Identity {
		return out, ErrUnavailable
	}
	result, err := m.runtime.RunMature(ctx, judgeruntime.MatureInput{JobID: input.JobID, ItemID: item, FencingToken: input.FencingToken, Identity: input.Identity, Manifest: *input.Candidate.Manifest})
	out = MatureOutcome{Identity: input.Identity, Completed: result.Completed, RawLog: bytes.Clone(result.RawLog)}
	for _, part := range result.Parts {
		out.Parts = append(out.Parts, PartOutcome{Part: part.Part, Passed: part.Passed, Errors: part.Errors, Warnings: part.Warnings, NotRun: part.NotRun})
	}
	if err != nil {
		return out, err
	}
	// Identity/readiness loss after dispatch leaves the durable reservation spent.
	// The owning lease must count recovery; a changed runtime cannot seal evidence.
	after := m.Snapshot(ctx)
	if !after.Qualified || after.Identity != before.Identity {
		return out, &judgeruntime.Failure{Code: "MATURE_IDENTITY_CHANGED", Ambiguous: true}
	}
	return out, nil
}
