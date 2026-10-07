package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/admission"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
	"github.com/STAR-Ability/code-startrack-judge/internal/testutil/judgetask"
)

type syntheticScheduler struct {
	snapshot  judgeruntime.Snapshot
	executes  atomic.Int64
	validates atomic.Int64
	mature    atomic.Int64
	inspected chan struct{}
}

func (scheduler *syntheticScheduler) Snapshot(context.Context) judgeruntime.Snapshot {
	if scheduler.inspected != nil {
		select {
		case scheduler.inspected <- struct{}{}:
		default:
		}
	}
	return scheduler.snapshot
}
func (scheduler *syntheticScheduler) Execute(context.Context, judgeruntime.TaskInput, judgeruntime.ProgressFunc) (judgeruntime.Outcome, error) {
	scheduler.executes.Add(1)
	return judgeruntime.Outcome{}, nil
}
func (scheduler *syntheticScheduler) ValidatePrograms(context.Context, judgeruntime.ValidationInput) (judgeruntime.ValidationOutcome, error) {
	scheduler.validates.Add(1)
	return judgeruntime.ValidationOutcome{}, nil
}
func (scheduler *syntheticScheduler) ValidateProgramsWithEvidence(context.Context, judgeruntime.ValidationInput, judgeruntime.ValidationEvidenceFunc) (judgeruntime.ValidationOutcome, error) {
	scheduler.validates.Add(1)
	return judgeruntime.ValidationOutcome{}, nil
}
func (scheduler *syntheticScheduler) RunMature(context.Context, judgeruntime.MatureInput) (judgeruntime.MatureOutcome, error) {
	scheduler.mature.Add(1)
	return judgeruntime.MatureOutcome{}, nil
}

type syntheticRegistration struct {
	ready        atomic.Bool
	registered   atomic.Int64
	checked      atomic.Int64
	registration chan struct{}
}

func (registration *syntheticRegistration) RegisterRuntime(context.Context, admission.RuntimeIdentity, bool) error {
	registration.registered.Add(1)
	registration.ready.Store(true)
	select {
	case registration.registration <- struct{}{}:
	default:
	}
	return nil
}
func (registration *syntheticRegistration) RuntimeReady(context.Context, admission.RuntimeIdentity, bool) (bool, error) {
	registration.checked.Add(1)
	return registration.ready.Load(), nil
}
func syntheticSnapshot() judgeruntime.Snapshot {
	i := judgetask.Identity()
	return judgeruntime.Snapshot{Qualified: true, SandboxReady: true, ToolchainReady: true, Identity: judgeruntime.FrozenIdentity{LanguageConfigVersion: i.LanguageConfigVersion, CompilerVersion: i.CompilerVersion, ToolchainDigest: i.ToolchainDigest, WorkerImageDigest: i.WorkerImageDigest, SandboxVersion: i.SandboxVersion, CheckerDigest: i.CheckerDigest}, Languages: contract.LanguageCapabilities{CapabilityVersion: "synthetic-unit-fixture", Languages: contract.Array[contract.LanguageCapability]{{LanguageID: "cpp17", DisplayName: "C++17", LanguageFamily: "CPP", CompilerVersion: i.CompilerVersion, SourceFilename: "main.cpp", AnalysisSupported: true}}}}
}

func TestRuntimeReadsNeverRegisterAndFailClosed(t *testing.T) {
	process, cancel := context.WithCancel(context.Background())
	defer cancel()
	scheduler := &syntheticScheduler{snapshot: syntheticSnapshot()}
	registration := &syntheticRegistration{}
	runtime := &controlledRuntime{process: process, client: scheduler, repository: registration, database: func(context.Context) bool { return true }, storage: func(context.Context) error { return nil }}
	if measured(runtime.Snapshot(context.Background())) || registration.registered.Load() != 0 || registration.checked.Load() != 1 {
		t.Fatal("readiness read registered or accepted an absent immutable profile")
	}
	if _, err := runtime.Execute(context.Background(), judgeruntime.TaskInput{}, nil); err == nil || scheduler.executes.Load() != 0 {
		t.Fatal("execution passed an unavailable profile")
	}
	if _, err := runtime.ValidatePrograms(context.Background(), judgeruntime.ValidationInput{}); err == nil || scheduler.validates.Load() != 0 {
		t.Fatal("package validation passed an unavailable profile")
	}
	if _, err := runtime.ValidateProgramsWithEvidence(context.Background(), judgeruntime.ValidationInput{}, func(context.Context, judgeruntime.ValidationEvidence) error { return nil }); err == nil || scheduler.validates.Load() != 0 {
		t.Fatal("private evidence validation passed an unavailable profile")
	}
	if _, err := runtime.RunMature(context.Background(), judgeruntime.MatureInput{}); err == nil || scheduler.mature.Load() != 0 {
		t.Fatal("mature validation passed an unavailable profile")
	}
	registration.ready.Store(true)
	if !measured(runtime.Snapshot(context.Background())) || registration.registered.Load() != 0 {
		t.Fatal("registered runtime was unavailable or read created configuration")
	}
	runtime.storage = func(context.Context) error { return errors.New("private storage diagnostic") }
	if measured(runtime.Snapshot(context.Background())) {
		t.Fatal("failed private storage passed execution readiness")
	}
	if _, err := runtime.RunMature(context.Background(), judgeruntime.MatureInput{}); err == nil || scheduler.mature.Load() != 0 {
		t.Fatal("mature validation dispatched with unavailable private storage")
	}
	runtime.storage = func(context.Context) error { return nil }
	scheduler.snapshot.Languages.Languages[0].CompilerVersion = "different compiler"
	if measured(runtime.Snapshot(context.Background())) {
		t.Fatal("language identity mismatch passed readiness")
	}
	scheduler.snapshot = syntheticSnapshot()
	cancel()
	if measured(runtime.Snapshot(context.Background())) {
		t.Fatal("draining runtime passed readiness")
	}
}

func TestRuntimeInitializerRequiresMeasuredIsolationAndDatabase(t *testing.T) {
	for _, unavailable := range []string{"none", "isolation", "database", "identity", "storage"} {
		t.Run(unavailable, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			scheduler := &syntheticScheduler{snapshot: syntheticSnapshot(), inspected: make(chan struct{}, 1)}
			if unavailable == "isolation" {
				scheduler.snapshot.Qualified = false
			}
			if unavailable == "identity" {
				scheduler.snapshot.Identity.WorkerImageDigest = "invalid"
			}
			registration := &syntheticRegistration{registration: make(chan struct{}, 1)}
			runtime := &controlledRuntime{process: ctx, client: scheduler, repository: registration, database: func(context.Context) bool { return unavailable != "database" }, storage: func(context.Context) error {
				if unavailable == "storage" {
					return errors.New("private storage failure")
				}
				return nil
			}}
			done := make(chan struct{})
			go func() { defer close(done); _ = runtime.Run(ctx) }()
			if unavailable == "none" {
				select {
				case <-registration.registration:
				case <-time.After(time.Second):
					t.Fatal("measured profile not initialized")
				}
			} else {
				select {
				case <-scheduler.inspected:
				case <-time.After(time.Second):
					t.Fatal("runtime not inspected")
				}
			}
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("initializer did not stop")
			}
			want := int64(0)
			if unavailable == "none" {
				want = 1
			}
			if registration.registered.Load() != want {
				t.Fatal("unmeasured runtime registered an immutable profile")
			}
		})
	}
}
