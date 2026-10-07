package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/runtime/restclient"
)

type AttemptLedger interface {
	Begin(context.Context, contract.UUID, contract.UUID) error
}
type StepLedger interface {
	BeginStep(context.Context, contract.UUID, contract.UUID, string) error
}

type Options struct {
	Client            *restclient.Client
	Factory           SessionFactory // Explicit mock seam; production uses Client.
	Reader            BlobReader
	Identity          FrozenIdentity
	Checker           []byte
	Grader            []byte
	MatureRunner      MatureRunner // Trusted orchestration seam; never untrusted execution.
	BridgeDigest      string
	Verifier          IsolationVerifier
	Ledger            AttemptLedger
	AnalysisSupported bool
}

func (Options) String() string     { return "runtime options [private bytes redacted]" }
func (o Options) GoString() string { return o.String() }

type Adapter struct {
	factory           SessionFactory
	reader            BlobReader
	identity          FrozenIdentity
	checker           []byte
	grader            []byte
	matureRunner      MatureRunner
	bridgeDigest      string
	verifier          IsolationVerifier
	ledger            AttemptLedger
	analysisSupported bool
	mu                sync.RWMutex
	qualifiedInstance string
	qualifiedAt       time.Time
	toolchainReady    bool
	matureReady       bool
	faulted           bool
	qualificationMu   sync.Mutex
}

func (a *Adapter) String() string   { return "runtime adapter [private bytes redacted]" }
func (a *Adapter) GoString() string { return a.String() }

func New(o Options) (*Adapter, error) {
	if err := o.Identity.Validate(); err != nil {
		return nil, err
	}
	if o.Reader == nil || o.Verifier == nil || o.Ledger == nil || len(o.Checker) == 0 || len(o.Checker) > MaxFileBytes || !bytesMatch(o.Checker, BlobRef{SHA256: o.Identity.CheckerDigest, SizeBytes: int64(len(o.Checker))}) {
		return nil, failure("RUNTIME_CONFIGURATION_INVALID", false)
	}
	factory := o.Factory
	if factory == nil && o.Client != nil {
		factory = restFactory{o.Client}
	}
	if factory == nil {
		return nil, failure("RUNTIME_CONFIGURATION_INVALID", false)
	}
	if len(o.Grader) != 0 && !bytesMatch(o.Grader, BlobRef{SHA256: GraderSourceSHA256, SizeBytes: int64(len(o.Grader))}) {
		return nil, failure("RUNTIME_GRADER_INVALID", false)
	}
	runner := o.MatureRunner
	if runner == nil {
		if len(o.Grader) > 0 && !digestPattern.MatchString(o.BridgeDigest) {
			return nil, failure("RUNTIME_HELPER_IDENTITY_INVALID", false)
		}
		runner = StdioMatureRunner{BridgeSHA256: o.BridgeDigest}
	}
	return &Adapter{factory: factory, reader: o.Reader, identity: o.Identity, checker: bytes.Clone(o.Checker), grader: bytes.Clone(o.Grader), matureRunner: runner, bridgeDigest: o.BridgeDigest, verifier: o.Verifier, ledger: o.Ledger, analysisSupported: o.AnalysisSupported}, nil
}

func (a *Adapter) Identity() FrozenIdentity { return a.identity }

// LanguageConfiguration returns server-owned frozen templates for registration.
// Consumers must retain the complete identity and never reactivate another
// image under this same configuration version.
func (a *Adapter) LanguageConfiguration() LanguageConfiguration {
	return LanguageConfiguration{
		LanguageID: LanguageID, ConfigVersion: a.identity.LanguageConfigVersion, DisplayName: "C++17", LanguageFamily: "CPP", CompilerVersion: a.identity.CompilerVersion, SourceFilename: "main.cpp",
		CompileTemplate: Template{Argv: CompileTemplate()}, RunTemplate: Template{Argv: []string{"/w/main"}}, CompileLimits: compilerLimits(), ToolchainDigest: a.identity.ToolchainDigest, AnalysisSupported: a.analysisSupported,
	}
}

type LanguageConfiguration struct {
	LanguageID        string   `json:"languageId"`
	ConfigVersion     string   `json:"configVersion"`
	DisplayName       string   `json:"displayName"`
	LanguageFamily    string   `json:"languageFamily"`
	CompilerVersion   string   `json:"compilerVersion"`
	SourceFilename    string   `json:"sourceFilename"`
	CompileTemplate   Template `json:"compileTemplate"`
	RunTemplate       Template `json:"runTemplate"`
	CompileLimits     Limits   `json:"compileLimits"`
	ToolchainDigest   string   `json:"toolchainDigest"`
	AnalysisSupported bool     `json:"analysisSupported"`
}
type Template struct {
	Argv []string `json:"argv"`
}

func CompileTemplate() []string {
	return []string{"/usr/bin/g++", "-std=c++17", "-O2", "-pipe", "-DONLINE_JUDGE", "main.cpp", "-o", "main"}
}
func compilerLimits() Limits {
	return Limits{CPUTimeNS: uint64(60 * time.Second), WallTimeNS: uint64(120 * time.Second), MemoryBytes: 1 << 30, OutputBytes: 8 << 20, Processes: 128}
}
func CompilerLimits() Limits  { return compilerLimits() }
func checkerLimits() Limits   { l := compilerLimits(); l.Processes = 32; return l }
func validatorLimits() Limits { l := compilerLimits(); l.Processes = 64; return l }

// Snapshot remeasures the live instance. Evidence expires and never transfers
// to a restarted sandbox. A missing/failing verifier fails closed immediately.
func (a *Adapter) Snapshot(ctx context.Context) Snapshot {
	s := Snapshot{Identity: a.identity, Languages: contract.LanguageCapabilities{Languages: contract.Array[contract.LanguageCapability]{}, CapabilityVersion: "unavailable"}}
	a.mu.RLock()
	faulted := a.faulted
	a.mu.RUnlock()
	if faulted {
		return s
	}
	instance, err := a.verifier.Verify(ctx, a.identity)
	if err != nil || instance == "" {
		a.invalidate()
		return s
	}
	a.mu.RLock()
	s.ToolchainReady = a.toolchainReady
	s.MatureReady = a.matureReady
	s.Qualified = a.qualifiedInstance == instance && time.Since(a.qualifiedAt) < 30*time.Second
	a.mu.RUnlock()
	s.SandboxReady = s.Qualified
	if !s.Qualified {
		a.invalidate()
		s.ToolchainReady = false
		s.MatureReady = false
		return s
	}
	if s.MatureReady {
		s.ProblemtoolsVersion = ProblemtoolsVersion
		s.ProblemtoolsRevision = ProblemtoolsRevision
		s.HelperProfile = MatureHelperProfile
	}
	s.Languages.Languages = contract.Array[contract.LanguageCapability]{{LanguageID: LanguageID, DisplayName: "C++17", LanguageFamily: "CPP", CompilerVersion: a.identity.CompilerVersion, SourceFilename: "main.cpp", AnalysisSupported: a.analysisSupported}}
	raw, _ := json.Marshal(a.LanguageConfiguration())
	s.Languages.CapabilityVersion, _ = canonical.HashJSON(raw)
	return s
}
func (a *Adapter) invalidate() {
	a.mu.Lock()
	a.qualifiedInstance = ""
	a.toolchainReady = false
	a.matureReady = false
	a.mu.Unlock()
}
func (a *Adapter) failClosed() {
	a.mu.Lock()
	a.faulted = true
	a.qualifiedInstance = ""
	a.toolchainReady = false
	a.matureReady = false
	a.mu.Unlock()
}

// Qualify measures the current compiler and executes the mature checker. The
// caller's IsolationVerifier additionally proves the Linux security profile.
// Full adversarial/Linux regression is a separate release acceptance gate.
func (a *Adapter) Qualify(ctx context.Context) (err error) {
	a.qualificationMu.Lock()
	defer a.qualificationMu.Unlock()
	a.mu.RLock()
	faulted := a.faulted
	a.mu.RUnlock()
	if faulted {
		return failure("RUNTIME_CLEANUP_FAULT", false)
	}
	defer func() {
		if err != nil {
			a.invalidate()
		}
	}()
	instance, err := a.verifier.Verify(ctx, a.identity)
	if err != nil || instance == "" {
		return failure("SANDBOX_ISOLATION_UNVERIFIED", false)
	}
	ctx = context.WithValue(ctx, qualificationContextKey{}, instance)
	version, err := a.compilerVersion(ctx)
	if err != nil || version != a.identity.CompilerVersion {
		return failure("COMPILER_IDENTITY_MISMATCH", false)
	}
	pythonVersion, e := a.toolVersion(ctx, []string{"/usr/local/bin/python3", "--version"})
	if e != nil || pythonVersion != "Python 3.11.15" {
		return failure("VALIDATOR_TOOLCHAIN_IDENTITY_MISMATCH", false)
	}
	canary := []byte("#include <cstdio>\n#if __cplusplus < 201703L\n#error C++17 required\n#endif\nint main(){std::puts(\"startrack-cpp17\");}\n")
	exe, verdict, _, e := a.compile(ctx, "qualification/cpp17-compile", canary)
	if e != nil || verdict != contract.VerdictAC {
		return failure("CPP17_COMPILE_PROBE_FAILED", false)
	}
	if e = a.probeExecutable(ctx, exe); e != nil {
		return e
	}
	for _, fixture := range []struct {
		out, answer []byte
		want        contract.JudgeVerdict
	}{{[]byte("Token\n"), []byte("token\n"), contract.VerdictAC}, {[]byte("wrong\n"), []byte("expected\n"), contract.VerdictWA}} {
		verdict, _, err := a.checkBytes(ctx, "qualification/checker", fixture.out, nil, fixture.answer, DefaultChecker())
		if err != nil || verdict != fixture.want {
			return failure("CHECKER_QUALIFICATION_FAILED", false)
		}
	}
	if len(a.grader) > 0 {
		if verifier, ok := a.matureRunner.(interface{ Verify(context.Context) error }); ok {
			if e := verifier.Verify(ctx); e != nil {
				return e
			}
		}
		response, e := a.matureRunBytes(ctx, "qualification/grader", []string{"/usr/local/bin/python3", "-I", "/w/default_grader.py"}, []byte("AC 1\n"), map[string][]byte{"default_grader.py": a.grader}, checkerLimits())
		if e != nil || response.WaitStatus != 0 {
			return failure("GRADER_QUALIFICATION_FAILED", false)
		}
		data, e := decodeMatureBytes(response.StdoutBase64, 8192)
		if e != nil || !bytes.Equal(data, []byte("AC 1.000000\n")) {
			return failure("GRADER_QUALIFICATION_FAILED", false)
		}
		bridge, e := a.bridgeBytes(ctx)
		if e != nil {
			return e
		}
		response, e = a.matureRunBytes(ctx, "qualification/problemtools-identity", []string{"/usr/local/bin/python3", "-I", "/w/problemtools-bridge.py", "--identity"}, nil, map[string][]byte{"problemtools-bridge.py": bridge}, checkerLimits())
		if e != nil || response.WaitStatus != 0 {
			return failure("MATURE_IDENTITY_PROBE_FAILED", false)
		}
		data, e = decodeMatureBytes(response.StdoutBase64, 8192)
		var report struct {
			ProblemtoolsVersion  string `json:"problemtoolsVersion"`
			ProblemtoolsRevision string `json:"problemtoolsRevision"`
			HelperProfile        string `json:"helperProfile"`
		}
		if e != nil || strictDecode(bytes.TrimSpace(data), &report) != nil || report.ProblemtoolsVersion != ProblemtoolsVersion || report.ProblemtoolsRevision != ProblemtoolsRevision || report.HelperProfile != MatureHelperProfile {
			return failure("MATURE_IDENTITY_PROBE_FAILED", false)
		}
	}
	nowInstance, err := a.verifier.Verify(ctx, a.identity)
	if err != nil || nowInstance != instance {
		return failure("SANDBOX_INSTANCE_CHANGED", false)
	}
	a.mu.Lock()
	a.qualifiedInstance = instance
	a.qualifiedAt = time.Now()
	a.toolchainReady = true
	a.matureReady = len(a.grader) > 0
	a.mu.Unlock()
	return nil
}

func (a *Adapter) compilerVersion(ctx context.Context) (version string, err error) {
	return a.toolVersion(ctx, []string{"/usr/bin/g++", "--version"})
}
func (a *Adapter) toolVersion(ctx context.Context, args []string) (version string, err error) {
	s := a.factory.NewSession()
	defer func() {
		if e := s.Close(); e != nil {
			a.failClosed()
			err = failure("SANDBOX_CLEANUP_FAILED", true)
		}
	}()
	empty, e := s.Upload(ctx, nil)
	if e != nil {
		return "", transportFailure(e, false)
	}
	cmd := command(args, empty, nil, compilerLimits())
	result, e := a.runOne(ctx, s, "qualification/compiler-version", cmd)
	if e != nil {
		return "", e
	}
	if result.Status != restclient.Accepted || result.ExitStatus != 0 || infrastructure(result) {
		return "", failure("COMPILER_PROBE_FAILED", false)
	}
	id, ok := result.CachedFiles["stdout"]
	if !ok {
		return "", failure("COMPILER_PROBE_FAILED", false)
	}
	data, e := s.Download(ctx, id, 8<<20)
	if e != nil {
		return "", transportFailure(e, false)
	}
	line, _, _ := bytes.Cut(data, []byte{'\n'})
	if !utf8.Valid(line) || len(line) > 512 {
		return "", failure("COMPILER_PROBE_FAILED", false)
	}
	return string(line), nil
}

func (a *Adapter) probeExecutable(ctx context.Context, exe []byte) (err error) {
	s := a.factory.NewSession()
	defer func() {
		if e := s.Close(); e != nil {
			a.failClosed()
			err = failure("SANDBOX_CLEANUP_FAILED", true)
		}
	}()
	empty, e := s.Upload(ctx, nil)
	if e != nil {
		return transportFailure(e, false)
	}
	binary, e := s.Upload(ctx, exe)
	if e != nil {
		return transportFailure(e, false)
	}
	limits := Limits{CPUTimeNS: uint64(time.Second), WallTimeNS: uint64(2 * time.Second), MemoryBytes: 64 << 20, OutputBytes: 8192, Processes: 32}
	r, e := a.runOne(ctx, s, "qualification/cpp17-run", command([]string{"/w/main"}, empty, map[string]restclient.FileID{"main": binary}, limits))
	if e != nil || infrastructure(r) || r.Status != restclient.Accepted || r.ExitStatus != 0 {
		return failure("CPP17_RUNTIME_PROBE_FAILED", false)
	}
	id, ok := r.CachedFiles["stdout"]
	if !ok {
		return failure("CPP17_RUNTIME_PROBE_FAILED", false)
	}
	data, e := s.Download(ctx, id, 8192)
	if e != nil || !bytes.Equal(data, []byte("startrack-cpp17\n")) {
		return failure("CPP17_RUNTIME_PROBE_FAILED", false)
	}
	return nil
}

func (a *Adapter) validate(t TaskInput) error {
	if t.TaskID.Validate() != nil || t.FencingToken.Validate() != nil || t.LanguageID != LanguageID || t.Identity != a.identity || len(t.Source) == 0 || len(t.Source) > MaxSourceBytes || !utf8.Valid(t.Source) || !bytesMatch(t.Source, BlobRef{SHA256: t.SourceSHA256, SizeBytes: int64(len(t.Source))}) || len(t.Cases) == 0 || len(t.Cases) > 4096 {
		return failure("TASK_INPUT_INVALID", false)
	}
	if e := t.Limits.Validate(); e != nil {
		return e
	}
	ids := map[contract.UUID]bool{}
	var global []byte
	for i, c := range t.Cases {
		if c.Ordinal != i+1 || c.TestCaseID.Validate() != nil || ids[c.TestCaseID] || !c.Input.valid() || !c.Answer.valid() {
			return failure("TASK_CASE_INVALID", false)
		}
		if e := c.Checker.Validate(); e != nil {
			return e
		}
		raw, _ := json.Marshal(c.Checker)
		if i == 0 {
			global = raw
		} else if !bytes.Equal(global, raw) {
			return failure("TASK_CHECKER_MISMATCH", false)
		}
		ids[c.TestCaseID] = true
	}
	return nil
}

// Execute dispatches one attempt exactly once. onProgress's first Compiling
// event acknowledges the controlled adapter after the durable dispatch fence.
// An ambiguous REST error stops this attempt; callers must stop heartbeats and
// await counted lease recovery rather than call Execute again with its token.
func (a *Adapter) Execute(ctx context.Context, t TaskInput, onProgress ProgressFunc) (out Outcome, err error) {
	dispatched := false
	defer func() {
		var f *Failure
		if err != nil && dispatched && errors.As(err, &f) && !f.Ambiguous {
			out.Result.Verdict = contract.VerdictIE
			out.Result.TotalTestCount = contract.SafeInt(len(t.Cases))
			out.Result.JudgedAt = contract.UTC(time.Now())
			if out.Cases == nil {
				out.Cases = []CaseResult{}
			}
			a.setDiagnostic(&out, f.Code)
			err = nil
		}
	}()
	if e := a.validate(t); e != nil {
		return out, e
	}
	if !a.Snapshot(ctx).Qualified {
		return out, failure("RUNTIME_NOT_READY", false)
	}
	if e := a.ledger.Begin(ctx, t.TaskID, t.FencingToken); e != nil {
		return out, failure("ATTEMPT_ALREADY_DISPATCHED", false)
	}
	dispatched = true
	progress := func(status string, ordinal int) error {
		if onProgress == nil {
			return nil
		}
		return onProgress(ctx, Progress{Type: "progress", Status: status, Ordinal: ordinal})
	}
	if e := progress("Compiling", 0); e != nil {
		return out, failure("DISPATCH_ACK_FAILED", true)
	}
	executable, compileVerdict, code, e := a.compile(ctx, string(t.FencingToken)+"/compile", t.Source)
	if e != nil {
		return out, e
	}
	out.Result = contract.JudgeResult{Verdict: compileVerdict, TotalTestCount: contract.SafeInt(len(t.Cases)), JudgedAt: contract.UTC(time.Now())}
	out.Cases = []CaseResult{}
	if compileVerdict != contract.VerdictAC {
		a.setDiagnostic(&out, code)
		return out, nil
	}
	if e := progress("Compiled", 0); e != nil {
		return out, failure("PROGRESS_ACK_FAILED", true)
	}
	for _, test := range t.Cases {
		if e := progress("Judging", test.Ordinal); e != nil {
			return out, failure("PROGRESS_ACK_FAILED", true)
		}
		input, e := a.read(ctx, test.Input)
		if e != nil {
			return out, e
		}
		caseResult, e := a.runCase(ctx, string(t.FencingToken)+"/case/"+decimal(test.Ordinal), executable, input, test, t.Limits)
		if e != nil {
			var f *Failure
			if errors.As(e, &f) && !f.Ambiguous && caseResult.Ordinal > 0 {
				caseResult.Verdict = contract.VerdictIE
				a.appendCase(&out, caseResult)
			}
			return out, e
		}
		a.appendCase(&out, caseResult)
		if caseResult.Verdict != contract.VerdictAC {
			if caseResult.Verdict == contract.VerdictIE {
				a.setDiagnostic(&out, "CHECKER_OR_SANDBOX_FAILED")
			}
			break
		}
		out.Result.PassedTestCount++
	}
	out.Result.JudgedAt = contract.UTC(time.Now())
	return out, nil
}
func (a *Adapter) appendCase(out *Outcome, c CaseResult) {
	out.Cases = append(out.Cases, c)
	cpu := c.CPUTimeNS / uint64(time.Millisecond)
	if c.CPUTimeNS%uint64(time.Millisecond) != 0 {
		cpu++
	}
	cpuMS := contract.SafeInt(cpu)
	memory := contract.SafeInt(c.MemoryBytes)
	if out.Result.TimeMs == nil || cpuMS > *out.Result.TimeMs {
		out.Result.TimeMs = &cpuMS
	}
	if out.Result.MemoryBytes == nil || memory > *out.Result.MemoryBytes {
		out.Result.MemoryBytes = &memory
	}
	out.Result.Verdict = c.Verdict
}
func (a *Adapter) setDiagnostic(out *Outcome, code string) {
	if code == "" {
		return
	}
	out.Result.DiagnosticCode = &code
	if out.Result.Verdict == contract.VerdictCE {
		log := "Compilation failed (" + code + ")."
		out.Result.CompileLog = &log
	}
	if out.Result.Verdict == contract.VerdictIE {
		out.Error = &contract.TaskError{Code: code, Message: "Controlled execution failed", Retryable: false}
	}
}
func decimal(n int) string { // Case ordinals are service-generated and bounded.
	if n < 10 {
		return string(rune('0' + n))
	}
	raw, _ := json.Marshal(n)
	return string(raw)
}

func (a *Adapter) read(ctx context.Context, r BlobRef) ([]byte, error) {
	reader := a.reader
	if scoped, ok := ctx.Value(blobReaderContextKey{}).(BlobReader); ok {
		reader = scoped
	}
	data, e := reader.ReadBlob(ctx, r.SHA256, r.SizeBytes, MaxFileBytes)
	if e != nil || !bytesMatch(data, r) {
		return nil, failure("PRIVATE_INPUT_INTEGRITY_FAILED", false)
	}
	return data, nil
}

type blobReaderContextKey struct{}
type qualificationContextKey struct{}

func (a *Adapter) verifyOperation(ctx context.Context) error {
	a.mu.RLock()
	faulted := a.faulted
	a.mu.RUnlock()
	if faulted {
		return failure("RUNTIME_CLEANUP_FAULT", false)
	}
	expected, _ := ctx.Value(qualificationContextKey{}).(string)
	if expected == "" {
		a.mu.RLock()
		expected = a.qualifiedInstance
		a.mu.RUnlock()
	}
	instance, e := a.verifier.Verify(ctx, a.identity)
	if e != nil || expected == "" || instance != expected {
		a.invalidate()
		return failure("SANDBOX_INSTANCE_UNVERIFIED", false)
	}
	return nil
}

// MissingBlobReader is used by the isolated scheduler. Each authorized IPC
// request supplies its own verified ephemeral blob scope; there is no global
// business-object-store credential in the judger process.
type MissingBlobReader struct{}

func (MissingBlobReader) ReadBlob(context.Context, string, int64, int64) ([]byte, error) {
	return nil, failure("PRIVATE_INPUT_MISSING", false)
}

func command(args []string, stdin restclient.FileID, copyIn map[string]restclient.FileID, l Limits) restclient.Command {
	return restclient.Command{Args: args, Env: []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "HOME=/w", "TMPDIR=/w"}, Files: []restclient.File{{ID: stdin}, {Collector: "stdout", LimitBytes: int64(l.OutputBytes), CollectPipe: true}, {Collector: "stderr", LimitBytes: int64(l.OutputBytes), CollectPipe: true}}, CopyIn: copyIn, CopyOutCached: []restclient.Output{{Name: "stdout"}, {Name: "stderr"}}, CPULimitNS: l.CPUTimeNS, ClockLimitNS: l.WallTimeNS, MemoryLimitBytes: l.MemoryBytes, StackLimitBytes: l.MemoryBytes, ProcessLimit: l.Processes, CopyOutMaxBytes: l.OutputBytes, StrictMemoryLimit: true, DataSegmentLimit: false, AddressSpaceLimit: false}
}
func (a *Adapter) runOne(ctx context.Context, s Session, id string, c restclient.Command) (restclient.Result, error) {
	if e := a.verifyOperation(ctx); e != nil {
		return restclient.Result{}, e
	}
	values, e := s.Run(ctx, restclient.Request{RequestID: id, Commands: []restclient.Command{c}})
	if e != nil {
		return restclient.Result{}, transportFailure(e, true)
	}
	if len(values) != 1 || values[0].MemoryBytes > uint64(contract.MaxSafeInteger) {
		return restclient.Result{}, failure("SANDBOX_RESULT_INVALID", true)
	}
	return values[0], nil
}
func transportFailure(e error, dispatch bool) error {
	if errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
		return failure("SANDBOX_OPERATION_INTERRUPTED", dispatch)
	}
	var r *restclient.Error
	if errors.As(e, &r) && (r.Kind == restclient.TransportError || r.Kind == restclient.UnavailableError || r.Kind == restclient.ProtocolError || r.CleanupFailed) {
		return failure("SANDBOX_OPERATION_UNCERTAIN", dispatch)
	}
	return failure("SANDBOX_OPERATION_FAILED", false)
}
func infrastructure(r restclient.Result) bool {
	return r.HasError || r.FileErrorCount > 0 || r.Status == restclient.InternalError || r.Status == restclient.JudgementFailed || r.Status == restclient.Invalid || r.Status == restclient.FileError || r.Status == restclient.InvalidInteraction
}

func (a *Adapter) compile(ctx context.Context, id string, source []byte) (exe []byte, verdict contract.JudgeVerdict, code string, err error) {
	if e := a.verifyOperation(ctx); e != nil {
		return nil, "", "", e
	}
	s := a.factory.NewSession()
	defer func() {
		if e := s.Close(); e != nil {
			a.failClosed()
			err = failure("SANDBOX_CLEANUP_FAILED", true)
		}
	}()
	stdin, e := s.Upload(ctx, nil)
	if e != nil {
		return nil, "", "", transportFailure(e, false)
	}
	src, e := s.Upload(ctx, source)
	if e != nil {
		return nil, "", "", transportFailure(e, false)
	}
	cmd := command(CompileTemplate(), stdin, map[string]restclient.FileID{"main.cpp": src}, compilerLimits())
	cmd.CopyOutCached = append(cmd.CopyOutCached, restclient.Output{Name: "main", Optional: true})
	cmd.CopyOutMaxBytes = MaxFileBytes
	r, e := a.runOne(ctx, s, id, cmd)
	if e != nil {
		return nil, "", "", e
	}
	verdict, code = compilerVerdict(r)
	if verdict != contract.VerdictAC {
		return nil, verdict, code, nil
	}
	binary, ok := r.CachedFiles["main"]
	if !ok {
		return nil, contract.VerdictIE, "COMPILER_EXECUTABLE_MISSING", nil
	}
	exe, e = s.Download(ctx, binary, MaxFileBytes)
	if e != nil {
		return nil, "", "", transportFailure(e, false)
	}
	if len(exe) < 4 || !bytes.Equal(exe[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		return nil, contract.VerdictIE, "COMPILER_EXECUTABLE_INVALID", nil
	}
	return exe, contract.VerdictAC, "", nil
}

func compilerVerdict(r restclient.Result) (contract.JudgeVerdict, string) {
	if !r.HasError && r.FileErrorCount > 0 && len(r.FileErrorTypes) == r.FileErrorCount {
		resourceOnly := true
		for _, kind := range r.FileErrorTypes {
			if kind != restclient.CopyOutSizeExceeded {
				resourceOnly = false
			}
		}
		if resourceOnly {
			return contract.VerdictCE, "COMPILER_RESOURCE_LIMIT"
		}
	}
	if infrastructure(r) {
		return contract.VerdictIE, "COMPILER_INFRASTRUCTURE_FAILED"
	}
	switch r.Status {
	case restclient.Accepted:
		if r.ExitStatus == 0 {
			return contract.VerdictAC, ""
		}
	case restclient.NonzeroExit:
		if r.ExitStatus != 127 && r.ExitStatus != 126 {
			return contract.VerdictCE, "COMPILER_REJECTED_SOURCE"
		}
	case restclient.TimeLimit, restclient.MemoryLimit, restclient.OutputLimit:
		return contract.VerdictCE, "COMPILER_RESOURCE_LIMIT"
	}
	return contract.VerdictIE, "COMPILER_INFRASTRUCTURE_FAILED"
}
func contestantVerdict(r restclient.Result) contract.JudgeVerdict {
	if !r.HasError && r.FileErrorCount > 0 && len(r.FileErrorTypes) == r.FileErrorCount {
		sizeOnly := true
		for _, kind := range r.FileErrorTypes {
			if kind != restclient.CopyOutSizeExceeded {
				sizeOnly = false
			}
		}
		if sizeOnly {
			return contract.VerdictOLE
		}
	}
	if infrastructure(r) {
		return contract.VerdictIE
	}
	switch r.Status {
	case restclient.Accepted:
		if r.ExitStatus == 0 {
			return contract.VerdictAC
		}
		return contract.VerdictRE
	case restclient.TimeLimit:
		return contract.VerdictTLE
	case restclient.MemoryLimit:
		return contract.VerdictMLE
	case restclient.OutputLimit:
		return contract.VerdictOLE
	case restclient.NonzeroExit, restclient.Signalled, restclient.DangerousSyscall:
		return contract.VerdictRE
	}
	return contract.VerdictIE
}
func checkerVerdict(r restclient.Result) contract.JudgeVerdict {
	if infrastructure(r) || r.Status != restclient.NonzeroExit {
		return contract.VerdictIE
	}
	if r.ExitStatus == 42 {
		return contract.VerdictAC
	}
	if r.ExitStatus == 43 {
		return contract.VerdictWA
	}
	return contract.VerdictIE
}

func (a *Adapter) runCase(ctx context.Context, id string, exe, input []byte, test Case, limits Limits) (result CaseResult, err error) {
	if e := a.verifyOperation(ctx); e != nil {
		return result, e
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
		return result, transportFailure(e, false)
	}
	executable, e := s.Upload(ctx, exe)
	if e != nil {
		return result, transportFailure(e, false)
	}
	r, e := a.runOne(ctx, s, id+"/run", command([]string{"/w/main"}, stdin, map[string]restclient.FileID{"main": executable}, limits))
	if e != nil {
		return result, e
	}
	result = CaseResult{TestCaseID: test.TestCaseID, Ordinal: test.Ordinal, Verdict: contestantVerdict(r), CPUTimeNS: r.CPUTimeNS, WallTimeNS: r.WallTimeNS, MemoryBytes: r.MemoryBytes, ExitCode: r.ExitStatus, SandboxStatus: r.Status}
	if result.Verdict != contract.VerdictAC {
		return result, nil
	}
	output, ok := r.CachedFiles["stdout"]
	if !ok {
		result.Verdict = contract.VerdictIE
		return result, nil
	}
	// Answer is resolved/uploaded only after the contestant has exited.
	answer, e := a.read(ctx, test.Answer)
	if e != nil {
		return result, e
	}
	result.Verdict, result.CheckerStatus, e = a.check(ctx, s, id+"/checker", output, stdin, answer, test.Checker)
	return result, e
}

func (a *Adapter) check(ctx context.Context, s Session, id string, output, input restclient.FileID, answer []byte, c CheckerConfig) (contract.JudgeVerdict, restclient.Status, error) {
	if e := a.verifyOperation(ctx); e != nil {
		return "", "", e
	}
	checker, e := s.Upload(ctx, a.checker)
	if e != nil {
		return "", "", transportFailure(e, false)
	}
	ans, e := s.Upload(ctx, answer)
	if e != nil {
		return "", "", transportFailure(e, false)
	}
	r, e := a.runOne(ctx, s, id, command(c.args(), output, map[string]restclient.FileID{"default_validator": checker, "input": input, "answer": ans}, checkerLimits()))
	if e != nil {
		return "", "", e
	}
	return checkerVerdict(r), r.Status, nil
}
func (a *Adapter) checkBytes(ctx context.Context, id string, output, input, answer []byte, c CheckerConfig) (v contract.JudgeVerdict, status restclient.Status, err error) {
	s := a.factory.NewSession()
	defer func() {
		if e := s.Close(); e != nil {
			a.failClosed()
			err = failure("SANDBOX_CLEANUP_FAILED", true)
		}
	}()
	out, e := s.Upload(ctx, output)
	if e != nil {
		return "", "", transportFailure(e, false)
	}
	in, e := s.Upload(ctx, input)
	if e != nil {
		return "", "", transportFailure(e, false)
	}
	return a.check(ctx, s, id, out, in, answer, c)
}
