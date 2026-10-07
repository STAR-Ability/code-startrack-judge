package main

import (
	"context"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/admission"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
)

type scheduler interface {
	Snapshot(context.Context) judgeruntime.Snapshot
	Execute(context.Context, judgeruntime.TaskInput, judgeruntime.ProgressFunc) (judgeruntime.Outcome, error)
	ValidatePrograms(context.Context, judgeruntime.ValidationInput) (judgeruntime.ValidationOutcome, error)
	ValidateProgramsWithEvidence(context.Context, judgeruntime.ValidationInput, judgeruntime.ValidationEvidenceFunc) (judgeruntime.ValidationOutcome, error)
	RunMature(context.Context, judgeruntime.MatureInput) (judgeruntime.MatureOutcome, error)
}
type runtimeRegistration interface {
	RegisterRuntime(context.Context, admission.RuntimeIdentity, bool) error
	RuntimeReady(context.Context, admission.RuntimeIdentity, bool) (bool, error)
}
type controlledRuntime struct {
	process    context.Context
	client     scheduler
	repository runtimeRegistration
	database   func(context.Context) bool
	storage    func(context.Context) error
}

func measured(snapshot judgeruntime.Snapshot) bool {
	return snapshot.Qualified && snapshot.SandboxReady && snapshot.ToolchainReady && snapshot.Identity.Validate() == nil && snapshot.Languages.Validate() == nil && len(snapshot.Languages.Languages) == 1 && snapshot.Languages.Languages[0].LanguageID == judgeruntime.LanguageID && snapshot.Languages.Languages[0].CompilerVersion == snapshot.Identity.CompilerVersion
}

func unavailableSnapshot() judgeruntime.Snapshot {
	return judgeruntime.Snapshot{Languages: contract.LanguageCapabilities{Languages: contract.Array[contract.LanguageCapability]{}, CapabilityVersion: "unavailable"}}
}

// Snapshot only reads readiness. Language profile allocation belongs to Run;
// health/language reads never install configuration or trigger execution.
func (runtime *controlledRuntime) Snapshot(ctx context.Context) judgeruntime.Snapshot {
	if runtime.process.Err() != nil || ctx.Err() != nil {
		return unavailableSnapshot()
	}
	probe, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	snapshot := runtime.client.Snapshot(probe)
	if !measured(snapshot) || runtime.storage == nil || runtime.storage(probe) != nil || !runtime.database(probe) {
		return unavailableSnapshot()
	}
	ready, err := runtime.repository.RuntimeReady(probe, runtimeIdentity(snapshot.Identity), snapshot.Languages.Languages[0].AnalysisSupported)
	if err != nil || !ready || probe.Err() != nil || runtime.process.Err() != nil {
		return unavailableSnapshot()
	}
	return snapshot
}

func (runtime *controlledRuntime) Run(ctx context.Context) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		probe, cancel := context.WithTimeout(ctx, 2*time.Second)
		snapshot := runtime.client.Snapshot(probe)
		if measured(snapshot) && runtime.storage != nil && runtime.storage(probe) == nil && runtime.database(probe) {
			// Errors retain execution unavailability; registration never falls back
			// to a fabricated compiler, image, language profile or mock executor.
			_ = runtime.repository.RegisterRuntime(probe, runtimeIdentity(snapshot.Identity), snapshot.Languages.Languages[0].AnalysisSupported)
		}
		cancel()
		timer := time.NewTimer(10 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (runtime *controlledRuntime) Execute(ctx context.Context, task judgeruntime.TaskInput, progress judgeruntime.ProgressFunc) (judgeruntime.Outcome, error) {
	if !measured(runtime.Snapshot(ctx)) {
		return judgeruntime.Outcome{}, &judgeruntime.Failure{Code: "RUNTIME_NOT_READY"}
	}
	return runtime.client.Execute(ctx, task, progress)
}
func (runtime *controlledRuntime) ValidatePrograms(ctx context.Context, input judgeruntime.ValidationInput) (judgeruntime.ValidationOutcome, error) {
	if !measured(runtime.Snapshot(ctx)) {
		return judgeruntime.ValidationOutcome{}, &judgeruntime.Failure{Code: "RUNTIME_NOT_READY"}
	}
	return runtime.client.ValidatePrograms(ctx, input)
}

func (runtime *controlledRuntime) ValidateProgramsWithEvidence(ctx context.Context, input judgeruntime.ValidationInput, sink judgeruntime.ValidationEvidenceFunc) (judgeruntime.ValidationOutcome, error) {
	if !measured(runtime.Snapshot(ctx)) {
		return judgeruntime.ValidationOutcome{}, &judgeruntime.Failure{Code: "RUNTIME_NOT_READY"}
	}
	return runtime.client.ValidateProgramsWithEvidence(ctx, input, sink)
}

func (runtime *controlledRuntime) RunMature(ctx context.Context, input judgeruntime.MatureInput) (judgeruntime.MatureOutcome, error) {
	if !measured(runtime.Snapshot(ctx)) {
		return judgeruntime.MatureOutcome{}, &judgeruntime.Failure{Code: "RUNTIME_NOT_READY"}
	}
	return runtime.client.RunMature(ctx, input)
}
