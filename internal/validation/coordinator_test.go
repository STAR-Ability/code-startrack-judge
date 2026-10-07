// SPDX-License-Identifier: Apache-2.0

package validation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/packages"
	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
	"github.com/STAR-Ability/code-startrack-judge/internal/runtime/restclient"
)

func mockIdentity() judgeruntime.FrozenIdentity {
	return judgeruntime.FrozenIdentity{LanguageConfigVersion: judgeruntime.CompilerConfigVersion, CompilerVersion: judgeruntime.CompilerVersion, ToolchainDigest: judgeruntime.CPP17ToolchainDigest, WorkerImageDigest: "sha256:" + strings.Repeat("1", 64), SandboxVersion: judgeruntime.SandboxVersion, CheckerDigest: strings.Repeat("2", 64)}
}
func candidate(t *testing.T) *packages.Artifact {
	t.Helper()
	a, err := packages.Adapt(packages.PinnedSource("problems/portable-fixture"), []packages.File{
		{Path: "problem.yaml", Data: []byte("name: Portable fixture\n")}, {Path: ".timelimit", Data: []byte("1.250")}, {Path: "problem_statement/problem.md", Data: []byte("Synthetic statement")},
		{Path: "data/sample/1.in", Data: []byte("sample")}, {Path: "data/sample/1.ans", Data: []byte("sample")}, {Path: "data/secret/2.in", Data: []byte("private")}, {Path: "data/secret/2.ans", Data: []byte("private")},
		{Path: "input_validators/main.py", Data: []byte("inert validator")}, {Path: "submissions/accepted/main.cpp", Data: []byte("inert reference")},
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

type mockMature struct {
	parts  []PartOutcome
	called bool
	input  MatureInput
	err    error
}

func (m *mockMature) Snapshot(context.Context) MatureSnapshot {
	return MatureSnapshot{Qualified: true, Identity: mockIdentity(), ProblemtoolsVersion: ProblemtoolsVersion, ProblemtoolsRevision: packages.CheckerRevision, HelperProfile: HelperProfile}
}
func (m *mockMature) Verify(_ context.Context, input MatureInput) (MatureOutcome, error) {
	m.called = true
	m.input = input
	parts := m.parts
	if parts == nil {
		for _, part := range []string{"STRUCTURE", "STATEMENT", "TEST_DATA", "VALIDATORS", "REFERENCES"} {
			parts = append(parts, PartOutcome{Part: part, Passed: true})
		}
	}
	return MatureOutcome{Identity: mockIdentity(), Completed: true, Parts: parts, RawLog: []byte("PRIVATE_TOOL_DIAGNOSTICS")}, m.err
}

type mockEngine struct {
	called       bool
	input        judgeruntime.ValidationInput
	badReference bool
	missing      bool
	duplicate    bool
	err          error
}

func (*mockEngine) Snapshot(context.Context) judgeruntime.Snapshot {
	return judgeruntime.Snapshot{Qualified: true, SandboxReady: true, ToolchainReady: true, Identity: mockIdentity()}
}
func (m *mockEngine) ValidateProgramsWithEvidence(ctx context.Context, input judgeruntime.ValidationInput, sink judgeruntime.ValidationEvidenceFunc) (out judgeruntime.ValidationOutcome, err error) {
	m.called = true
	m.input = input
	out.ValidatorsPassed = true
	out.ReferencesPassed = true
	for _, kind := range []string{"VALIDATOR", "REFERENCE"} {
		programs := input.InputValidators
		if kind == "REFERENCE" {
			programs = input.AcceptedReferences
		}
		for _, program := range programs {
			for _, test := range input.Cases {
				if m.missing && kind == "REFERENCE" && test.Ordinal == 2 {
					continue
				}
				e := judgeruntime.ProgramCaseEvidence{SourceSHA256: program.File.SHA256, Ordinal: test.Ordinal, Passed: true, Verdict: contract.VerdictAC, Status: restclient.Accepted, CPUTimeNS: 1000, WallTimeNS: 2000, MemoryBytes: 4096}
				if kind == "VALIDATOR" {
					e.Status = restclient.NonzeroExit
					e.ExitCode = 42
				}
				if m.badReference && kind == "REFERENCE" && test.Ordinal == 2 {
					e.Passed = false
					e.Verdict = contract.VerdictWA
					out.ReferencesPassed = false
				}
				event := judgeruntime.ValidationEvidence{Kind: kind, Case: e}
				if err := sink(ctx, event); err != nil {
					return out, err
				}
				if m.duplicate {
					if err := sink(ctx, event); err != nil {
						return out, err
					}
				}
				if kind == "VALIDATOR" {
					out.ValidatorCaseCount++
				} else {
					out.ReferenceCaseCount++
				}
			}
		}
	}
	return out, m.err
}
func request(t *testing.T, sink judgeruntime.ValidationEvidenceFunc) Request {
	return Request{JobID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", ItemID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", FencingToken: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", Candidate: candidate(t), RecordEvidence: sink}
}
func noop(context.Context, judgeruntime.ValidationEvidence) error { return nil }

func TestMatureIncompletePartWithNoErrorsRemainsNotRun(t *testing.T) {
	engine := &mockEngine{}
	mature := &mockMature{parts: []PartOutcome{{Part: "STRUCTURE", Passed: true}, {Part: "STATEMENT", NotRun: true}, {Part: "TEST_DATA", NotRun: true}, {Part: "VALIDATORS", NotRun: true}, {Part: "REFERENCES", NotRun: true}}}
	v, err := New(Options{Engine: engine, Mature: mature})
	if err != nil {
		t.Fatal(err)
	}
	report, err := v.Validate(context.Background(), request(t, noop))
	if err != nil || report.Status != "FAILED" || report.Results.Statement.Passed || engine.called {
		t.Fatal("incomplete mature steps became acceptance proof")
	}
	found := false
	for _, evidence := range report.Results.Statement.Evidence {
		found = found || evidence.Check == "NOT_RUN"
	}
	if !found || report.Results.Validate() != nil {
		t.Fatal("skipped statement evidence was not preserved")
	}
}

func TestPortableControlFlowCannotSupplyValidationProof(t *testing.T) {
	engine := &mockEngine{}
	mature := &mockMature{}
	v, err := New(Options{Engine: engine, Mature: mature, ControlFlowOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	var records uint64
	req := request(t, func(context.Context, judgeruntime.ValidationEvidence) error { records++; return nil })
	report, err := v.Validate(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "PORTABLE_ONLY" || report.Context != (Context{}) || v.Ready(context.Background()) || len(report.Errors) != 1 || report.Errors[0].Code != "PORTABLE_VALIDATION_ONLY" {
		t.Fatal("mock control flow became persistable qualification")
	}
	if !report.Results.AllPassed() || report.Results.Validate() != nil || records != 4 || report.ProgramEvidenceCount != 4 || !shaPattern.MatchString(report.ProgramEvidenceSHA256) {
		t.Fatal("complete mock event journal was not reconciled")
	}
	if mature.input.JobID != req.JobID || mature.input.FencingToken != req.FencingToken || mature.input.StepName != "problemtools:"+string(req.ItemID) || mature.input.FixedTimeLimitSeconds != "1.25" || engine.input.JobID != req.JobID || engine.input.ItemID != req.ItemID || engine.input.FencingToken != req.FencingToken {
		t.Fatal("owning job, fence, item or exact limit changed at dispatch")
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(format, report), "PRIVATE_TOOL") {
			t.Fatal("private raw diagnostics leaked from formatted report")
		}
	}
}

func TestProductionDefaultFailsClosedWithoutMatureHelper(t *testing.T) {
	engine := &mockEngine{}
	v, err := New(Options{Engine: engine})
	if err != nil {
		t.Fatal(err)
	}
	report, err := v.Validate(context.Background(), request(t, noop))
	if !errors.Is(err, ErrUnavailable) || report.Status != "" || engine.called || v.Ready(context.Background()) {
		t.Fatal("unqualified default dispatched or invented run")
	}
}

func TestMatureFailureAndMissingCheckpointNeverSuppressed(t *testing.T) {
	for _, fixture := range []struct {
		name  string
		parts []PartOutcome
	}{{"statement-error", []PartOutcome{{Part: "STRUCTURE", Passed: true}, {Part: "STATEMENT", Errors: 1}, {Part: "TEST_DATA", Passed: true}, {Part: "VALIDATORS", Passed: true}, {Part: "REFERENCES", Passed: true}}}, {"missing-category", []PartOutcome{{Part: "STRUCTURE", Passed: true}}}, {"truthy-despite-error", []PartOutcome{{Part: "STRUCTURE", Passed: true, Errors: 1}, {Part: "STATEMENT", Passed: true}, {Part: "TEST_DATA", Passed: true}, {Part: "VALIDATORS", Passed: true}, {Part: "REFERENCES", Passed: true}}}} {
		t.Run(fixture.name, func(t *testing.T) {
			engine := &mockEngine{}
			v, _ := New(Options{Engine: engine, Mature: &mockMature{parts: fixture.parts}, ControlFlowOnly: true})
			report, err := v.Validate(context.Background(), request(t, noop))
			if err != nil {
				t.Fatal(err)
			}
			if engine.called || report.Results.AllPassed() || report.Results.Validators.Passed || report.Results.ReferenceSolutions.Passed || len(report.Errors) < 2 || report.Results.Validate() != nil {
				t.Fatal("mature failure hidden or skipped program checks passed")
			}
		})
	}
}

func TestExactReferenceFailureIncompleteAndDuplicateEvidence(t *testing.T) {
	for name, engine := range map[string]*mockEngine{"bad-reference": {badReference: true}, "missing-case": {missing: true}, "duplicate-case": {duplicate: true}} {
		t.Run(name, func(t *testing.T) {
			v, _ := New(Options{Engine: engine, Mature: &mockMature{}, ControlFlowOnly: true})
			report, err := v.Validate(context.Background(), request(t, noop))
			if name == "duplicate-case" {
				var failure *judgeruntime.Failure
				if !errors.As(err, &failure) || !failure.Ambiguous || !report.FinishedAt.IsZero() {
					t.Fatal("duplicate helper evidence became terminal proof")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if report.Results.ReferenceSolutions.Passed || report.Results.AllPassed() || len(report.Errors) < 2 {
				t.Fatal("reference failure/incomplete evidence passed")
			}
		})
	}
}

func TestAmbiguousTransportAndJournalFailureDoNotCreateTerminalRun(t *testing.T) {
	v, _ := New(Options{Engine: &mockEngine{err: &judgeruntime.Failure{Code: "TRANSPORT_UNCERTAIN", Ambiguous: true}}, Mature: &mockMature{}, ControlFlowOnly: true})
	report, err := v.Validate(context.Background(), request(t, noop))
	var failure *judgeruntime.Failure
	if !errors.As(err, &failure) || !failure.Ambiguous || !report.FinishedAt.IsZero() {
		t.Fatal("uncertain transport became terminal run")
	}
	v, _ = New(Options{Engine: &mockEngine{}, Mature: &mockMature{}, ControlFlowOnly: true})
	report, err = v.Validate(context.Background(), request(t, func(context.Context, judgeruntime.ValidationEvidence) error {
		return errors.New("private journal failure")
	}))
	if !errors.As(err, &failure) || !failure.Ambiguous || !report.FinishedAt.IsZero() {
		t.Fatal("unretained event journal became terminal proof")
	}
}

func TestSealedByteTamperingStopsBeforeDispatch(t *testing.T) {
	for name, tamper := range map[string]func(*packages.Artifact){"manifest": func(a *packages.Artifact) { a.ManifestJSON = append(a.ManifestJSON, ' ') }, "source-archive": func(a *packages.Artifact) { a.SourceArchive[512] ^= 1 }, "normalized-file": func(a *packages.Artifact) { a.NormalizedFiles[0].Data = append(a.NormalizedFiles[0].Data, 'x') }, "checker": func(a *packages.Artifact) { a.Manifest.Checker.CaseSensitive = true }} {
		t.Run(name, func(t *testing.T) {
			engine := &mockEngine{}
			mature := &mockMature{}
			v, _ := New(Options{Engine: engine, Mature: mature, ControlFlowOnly: true})
			req := request(t, noop)
			tamper(req.Candidate)
			if _, err := v.Validate(context.Background(), req); !errors.Is(err, ErrInvalid) || engine.called || mature.called {
				t.Fatal("tampered immutable bytes dispatched")
			}
		})
	}
}
