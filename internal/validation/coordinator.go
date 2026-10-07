// SPDX-License-Identifier: Apache-2.0

package validation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/packages"
	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
	"github.com/STAR-Ability/code-startrack-judge/internal/runtime/restclient"
)

func qualified(snapshot judgeruntime.Snapshot, mature MatureSnapshot) bool {
	return snapshot.Qualified && snapshot.SandboxReady && snapshot.ToolchainReady && snapshot.Identity.Validate() == nil && mature.Qualified && mature.Identity == snapshot.Identity && mature.ProblemtoolsVersion == ProblemtoolsVersion && mature.ProblemtoolsRevision == packages.CheckerRevision && mature.HelperProfile == HelperProfile
}
func (v *Validator) Ready(ctx context.Context) bool {
	return v != nil && !v.options.ControlFlowOnly && qualified(v.options.Engine.Snapshot(ctx), v.options.Mature.Snapshot(ctx))
}
func fixedSeconds(ms int64) string {
	if ms%1000 == 0 {
		return strconv.FormatInt(ms/1000, 10)
	}
	return strconv.FormatInt(ms/1000, 10) + "." + strings.TrimRight(fmt.Sprintf("%03d", ms%1000), "0")
}
func skipped() Checkpoint {
	return Checkpoint{Evidence: []Evidence{{Check: "NOT_RUN", Summary: "Required check not run because an earlier qualification or technical check failed."}}}
}
func initialResults() Results {
	return Results{Structure: skipped(), Statement: skipped(), TestData: skipped(), Validators: skipped(), ReferenceSolutions: skipped()}
}
func safeError() contract.TaskError {
	return contract.TaskError{Code: "PACKAGE_VALIDATION_FAILED", Message: "Required isolated package validation failed; private evidence is retained.", Retryable: false}
}
func checkpoints(r *Results) map[string]*Checkpoint {
	return map[string]*Checkpoint{"STRUCTURE": &r.Structure, "STATEMENT": &r.Statement, "TEST_DATA": &r.TestData, "VALIDATORS": &r.Validators, "REFERENCES": &r.ReferenceSolutions}
}
func markSkipped(part *Checkpoint) {
	part.Passed = false
	part.Evidence = append(part.Evidence, skipped().Evidence...)
}

func verifyCandidate(a *packages.Artifact) error {
	if a == nil || !a.ManifestReady || a.Manifest == nil || a.Source != a.Manifest.Source || packages.VerifyFiles(*a.Manifest, a.NormalizedFiles) != nil {
		return ErrInvalid
	}
	manifest, err := a.Manifest.CanonicalJSON()
	if err != nil || !bytes.Equal(manifest, a.ManifestJSON) || canonical.HashBytes(manifest) != a.ManifestSHA256 || canonical.HashBytes(a.SourceArchive) != a.SourceSHA256 || canonical.HashBytes(a.NormalizedArchive) != a.NormalizedSHA256 {
		return ErrInvalid
	}
	normalized := make([]packages.File, 0, len(a.NormalizedFiles)+1)
	normalized = append(normalized, a.NormalizedFiles...)
	normalized = append(normalized, packages.File{Path: packages.ReservedManifestPath, Data: a.ManifestJSON})
	if packages.VerifyArchive(a.NormalizedArchive, normalized) != nil || packages.VerifyArchive(a.SourceArchive, a.SourceFiles) != nil {
		return ErrInvalid
	}
	bySource := map[string]packages.File{}
	for _, file := range a.SourceFiles {
		if packages.ValidateSourcePath(file.Path) != nil {
			return ErrInvalid
		}
		bySource[file.Path] = file
	}
	var originals int
	for _, file := range a.Manifest.Files {
		if file.OriginalPath != nil {
			originals++
			original, ok := bySource[*file.OriginalPath]
			if !ok || file.SourceSHA256 == nil || file.SourceSizeBytes == nil || canonical.HashBytes(original.Data) != *file.SourceSHA256 || int64(len(original.Data)) != *file.SourceSizeBytes {
				return ErrInvalid
			}
		}
	}
	if originals != len(a.SourceFiles) {
		return ErrInvalid
	}
	return nil
}

// Validate dispatches no host subprocess. Real terminal proof requires both
// independently qualified helpers, the exact sealed bytes and a private event
// journal. Ambiguous transport or journal failures return an error without a
// terminal run so the owning durable lease controls counted recovery.
func (v *Validator) Validate(ctx context.Context, request Request) (report Report, err error) {
	if v == nil || ctx == nil || request.JobID.Validate() != nil || request.ItemID.Validate() != nil || request.FencingToken.Validate() != nil || request.RecordEvidence == nil || verifyCandidate(request.Candidate) != nil {
		return report, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	snapshot := v.options.Engine.Snapshot(ctx)
	matureSnapshot := v.options.Mature.Snapshot(ctx)
	if !v.options.ControlFlowOnly && !qualified(snapshot, matureSnapshot) {
		return report, ErrUnavailable
	}
	if snapshot.Identity.Validate() != nil {
		return report, ErrUnavailable
	}
	a := request.Candidate
	m := a.Manifest
	report = Report{Status: "RUNNING", Results: initialResults(), Errors: contract.Array[contract.TaskError]{}, Adaptations: append([]packages.Adaptation(nil), m.Adaptations...), StartedAt: time.Now().UTC()}
	if !v.options.ControlFlowOnly {
		config := struct {
			Identity     judgeruntime.FrozenIdentity `json:"identity"`
			Helper       string                      `json:"helperProfile"`
			Problemtools string                      `json:"problemtoolsVersion"`
			Adapter      string                      `json:"adapterVersion"`
			Threads      int                         `json:"threads"`
			Filters      string                      `json:"filters"`
			Parts        string                      `json:"parts"`
		}{snapshot.Identity, HelperProfile, ProblemtoolsVersion, packages.AdapterVersion, 1, "NONE", "ALL"}
		encoded, e := json.Marshal(config)
		if e != nil {
			return Report{}, ErrInvalid
		}
		encoded, e = canonical.Canonicalize(encoded)
		if e != nil {
			return Report{}, ErrInvalid
		}
		report.Context = Context{ProblemtoolsVersion: ProblemtoolsVersion, AdapterVersion: packages.AdapterVersion, ToolchainVersion: snapshot.Identity.CompilerVersion, ImageDigest: snapshot.Identity.WorkerImageDigest, ConfigSHA256: canonical.HashBytes(encoded), SourceSHA256: a.SourceSHA256, NormalizedSHA256: a.NormalizedSHA256}
	}
	defer func() {
		if err == nil {
			report.FinishedAt = time.Now().UTC()
			report.Status = "FAILED"
			if report.Results.AllPassed() && len(report.Errors) == 0 {
				report.Status = "PASSED"
			}
			if v.options.ControlFlowOnly {
				report.Status = "PORTABLE_ONLY"
				report.Context = Context{}
				report.Errors = append(report.Errors, contract.TaskError{Code: "PORTABLE_VALIDATION_ONLY", Message: "Portable control-flow fixtures cannot establish execution qualification.", Retryable: false})
			}
		}
	}()
	input := MatureInput{JobID: request.JobID, FencingToken: request.FencingToken, StepName: "problemtools:" + strings.ToLower(string(request.ItemID)), Identity: snapshot.Identity, Candidate: a, FixedTimeLimitSeconds: fixedSeconds(m.Limits.TimeLimitMS)}
	mature, e := v.options.Mature.Verify(ctx, input)
	// Preserve bounded private partial diagnostics even when uncertainty leaves
	// this run unfinished. Log bounds must not convert ambiguity into a terminal.
	if len(mature.RawLog) <= MaxPrivateLogBytes {
		report.RawLog = bytes.Clone(mature.RawLog)
	}
	if e != nil {
		var failure *judgeruntime.Failure
		if ctx.Err() != nil || errors.As(e, &failure) && failure.Ambiguous {
			return report, e
		}
	}
	if len(mature.RawLog) > MaxPrivateLogBytes {
		report.Errors = append(report.Errors, safeError())
		return report, nil
	}
	if e != nil {
		report.Errors = append(report.Errors, safeError())
		return report, nil
	}
	if mature.Identity != snapshot.Identity || !mature.Completed || len(mature.Parts) != 5 {
		report.Errors = append(report.Errors, safeError())
		return report, nil
	}
	parts := checkpoints(&report.Results)
	seen := map[string]bool{}
	for _, part := range mature.Parts {
		checkpoint, ok := parts[part.Part]
		if !ok || seen[part.Part] || part.Errors < 0 || part.Errors > 1000000 || part.Warnings < 0 || part.Warnings > 1000000 || part.Passed != (part.Errors == 0 && !part.NotRun) {
			report.Results = initialResults()
			report.Errors = append(report.Errors, safeError())
			return report, nil
		}
		seen[part.Part] = true
		subject := a.NormalizedSHA256
		*checkpoint = Checkpoint{Passed: part.Passed, Evidence: []Evidence{{Check: "PROBLEMTOOLS_" + part.Part, SubjectSHA256: &subject, Summary: fmt.Sprintf("Pinned mature check completed with %d errors and %d warnings; raw diagnostics remain private.", part.Errors, part.Warnings)}}}
		if part.NotRun {
			checkpoint.Evidence[0].Summary = fmt.Sprintf("Pinned mature check stopped before every required step completed, with %d errors and %d warnings; raw diagnostics remain private.", part.Errors, part.Warnings)
			markSkipped(checkpoint)
		}
		if !part.Passed {
			report.Errors = append(report.Errors, safeError())
		}
	}
	if !report.Results.AllPassed() {
		markSkipped(&report.Results.Validators)
		markSkipped(&report.Results.ReferenceSolutions)
		return report, nil
	}
	exact, e := judgeruntime.ValidationFromManifest(request.JobID, request.ItemID, request.FencingToken, snapshot.Identity, *m)
	if e != nil {
		return Report{}, ErrInvalid
	}
	validatorTracker := newTracker(exact.InputValidators, len(m.Tests), true, m.ExecutionProfiles.Validator)
	referenceTracker := newTracker(exact.AcceptedReferences, len(m.Tests), false, m.Limits)
	evidenceHash := sha256.New()
	var evidenceCount uint64
	var evidenceFailure error
	outcome, e := v.options.Engine.ValidateProgramsWithEvidence(ctx, exact, func(eventCtx context.Context, event judgeruntime.ValidationEvidence) error {
		tracker := validatorTracker
		switch event.Kind {
		case "VALIDATOR":
		case "REFERENCE":
			tracker = referenceTracker
		default:
			evidenceFailure = ErrInvalid
			return ErrInvalid
		}
		if tracker.accept(event.Case) != nil {
			evidenceFailure = ErrInvalid
			return ErrInvalid
		}
		if e := request.RecordEvidence(eventCtx, event); e != nil {
			evidenceFailure = e
			return e
		}
		line, e := json.Marshal(event)
		if e != nil {
			evidenceFailure = ErrInvalid
			return ErrInvalid
		}
		evidenceHash.Write(line)
		evidenceHash.Write([]byte{'\n'})
		evidenceCount++
		return nil
	})
	report.ProgramEvidenceSHA256 = hex.EncodeToString(evidenceHash.Sum(nil))
	report.ProgramEvidenceCount = evidenceCount
	if evidenceFailure != nil {
		return report, &judgeruntime.Failure{Code: "VALIDATION_EVIDENCE_UNCERTAIN", Ambiguous: true}
	}
	compact, _ := json.Marshal(struct {
		SHA256  string                         `json:"programEvidenceSha256"`
		Count   uint64                         `json:"programEvidenceCount"`
		Outcome judgeruntime.ValidationOutcome `json:"outcome"`
	}{report.ProgramEvidenceSHA256, evidenceCount, outcome})
	if len(compact) > 65536 {
		markSkipped(&report.Results.Validators)
		markSkipped(&report.Results.ReferenceSolutions)
		report.Errors = append(report.Errors, safeError())
		return report, nil
	}
	report.RawLog = append(append(report.RawLog, []byte("\nSTARTRACK_EXACT_PROGRAM_EVIDENCE\n")...), compact...)
	if e != nil {
		var failure *judgeruntime.Failure
		if ctx.Err() != nil || errors.As(e, &failure) && failure.Ambiguous {
			return report, e
		}
		markSkipped(&report.Results.Validators)
		markSkipped(&report.Results.ReferenceSolutions)
		report.Errors = append(report.Errors, safeError())
		return report, nil
	}
	validatorComplete := validatorTracker.complete(outcome.ValidatorCaseCount, outcome.ValidatorsPassed)
	referenceComplete := referenceTracker.complete(outcome.ReferenceCaseCount, outcome.ReferencesPassed)
	report.Results.Validators.Passed = validatorComplete && validatorTracker.passed
	report.Results.ReferenceSolutions.Passed = referenceComplete && referenceTracker.passed
	for _, item := range []struct {
		checkpoint *Checkpoint
		tracker    *caseTracker
		complete   bool
		check      string
	}{{&report.Results.Validators, validatorTracker, validatorComplete, "EXACT_INPUT_VALIDATORS"}, {&report.Results.ReferenceSolutions, referenceTracker, referenceComplete, "EXACT_ACCEPTED_REFERENCES"}} {
		hash := report.ProgramEvidenceSHA256
		item.checkpoint.Evidence = append(item.checkpoint.Evidence, Evidence{Check: item.check, SubjectSHA256: &hash, Summary: fmt.Sprintf("Exact frozen-profile evidence: %d of %d required program/case checks retained.", item.tracker.count, item.tracker.expected)})
		if !item.complete || !item.tracker.passed {
			report.Errors = append(report.Errors, safeError())
		}
	}
	if !v.options.ControlFlowOnly {
		final := v.options.Engine.Snapshot(ctx)
		if final.Identity != snapshot.Identity || !qualified(final, v.options.Mature.Snapshot(ctx)) {
			return report, ErrUnavailable
		}
	}
	if report.Results.Validate() != nil {
		return Report{}, ErrInvalid
	}
	return report, nil
}

type caseTracker struct {
	counts       map[string][]uint32
	multiplicity map[string]uint32
	expected     uint64
	count        uint64
	passed       bool
	validator    bool
	limits       packages.ExecutionLimits
}

func newTracker(programs []judgeruntime.Program, tests int, validator bool, limits packages.ExecutionLimits) *caseTracker {
	t := &caseTracker{counts: map[string][]uint32{}, multiplicity: map[string]uint32{}, expected: uint64(len(programs)) * uint64(tests), passed: len(programs) > 0, validator: validator, limits: limits}
	for _, program := range programs {
		t.multiplicity[program.File.SHA256]++
		if t.counts[program.File.SHA256] == nil {
			t.counts[program.File.SHA256] = make([]uint32, tests)
		}
	}
	return t
}
func (t *caseTracker) accept(e judgeruntime.ProgramCaseEvidence) error {
	counts, exists := t.counts[e.SourceSHA256]
	if !exists || e.Ordinal < 1 || e.Ordinal > len(counts) || counts[e.Ordinal-1] >= t.multiplicity[e.SourceSHA256] || e.Verdict.Validate() != nil {
		return ErrInvalid
	}
	if e.Passed {
		if e.Verdict != contract.VerdictAC || e.CPUTimeNS > uint64(t.limits.TimeLimitMS)*uint64(time.Millisecond) || e.WallTimeNS > uint64(t.limits.WallLimitMS)*uint64(time.Millisecond) || e.MemoryBytes > uint64(t.limits.MemoryLimitBytes) {
			return ErrInvalid
		}
		if t.validator && (e.Status != restclient.NonzeroExit || e.ExitCode != 42) || !t.validator && (e.Status != restclient.Accepted || e.ExitCode != 0) {
			return ErrInvalid
		}
	} else {
		t.passed = false
	}
	counts[e.Ordinal-1]++
	t.count++
	return nil
}
func (t *caseTracker) complete(count uint64, passed bool) bool {
	if t.count != t.expected || count != t.count || passed != t.passed {
		return false
	}
	for hash, counts := range t.counts {
		for _, count := range counts {
			if count != t.multiplicity[hash] {
				return false
			}
		}
	}
	return true
}
