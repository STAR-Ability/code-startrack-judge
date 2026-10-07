package runtime

import (
	"bytes"
	"context"
	"encoding/base32"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/runtime/restclient"
)

type memoryBlobs map[string][]byte

func (m memoryBlobs) ReadBlob(ctx context.Context, digest string, size, max int64) ([]byte, error) {
	data, ok := m[digest]
	if !ok || int64(len(data)) != size || size > max || ctx.Err() != nil {
		return nil, errors.New("private lookup failed")
	}
	return bytes.Clone(data), nil
}

type testVerifier struct {
	mu       sync.Mutex
	instance string
	fail     bool
}

func (v *testVerifier) Verify(context.Context, FrozenIdentity) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.fail {
		return "", errors.New("qualification failure")
	}
	return v.instance, nil
}

type recordedRequest struct {
	request restclient.Request
	inputs  map[string][]byte
	stdin   []byte
}
type mockFactory struct {
	mu            sync.Mutex
	next          uint64
	data          map[restclient.FileID][]byte
	requests      []recordedRequest
	closed        int
	compileStatus restclient.Status
	runStatus     restclient.Status
	checkerExits  []int
	checkerCount  int
	runError      error
}
type mockSession struct {
	factory *mockFactory
	ids     map[restclient.FileID]bool
	closed  bool
}

func (f *mockFactory) NewSession() Session {
	return &mockSession{factory: f, ids: map[restclient.FileID]bool{}}
}
func (s *mockSession) upload(data []byte) restclient.FileID {
	s.factory.next++
	n := s.factory.next
	raw := []byte{byte(n >> 32), byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	id := restclient.FileID(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw))
	s.factory.data[id] = bytes.Clone(data)
	s.ids[id] = true
	return id
}
func (s *mockSession) Upload(ctx context.Context, data []byte) (restclient.FileID, error) {
	s.factory.mu.Lock()
	defer s.factory.mu.Unlock()
	if s.closed || ctx.Err() != nil {
		return "", errors.New("closed")
	}
	return s.upload(data), nil
}
func (s *mockSession) Run(ctx context.Context, req restclient.Request) ([]restclient.Result, error) {
	f := s.factory
	f.mu.Lock()
	defer f.mu.Unlock()
	if s.closed || ctx.Err() != nil {
		return nil, context.Canceled
	}
	c := req.Commands[0]
	record := recordedRequest{request: req, inputs: map[string][]byte{}, stdin: bytes.Clone(f.data[c.Files[0].ID])}
	for name, id := range c.CopyIn {
		if !s.ids[id] {
			return nil, errors.New("foreign cache")
		}
		record.inputs[name] = bytes.Clone(f.data[id])
	}
	f.requests = append(f.requests, record)
	r := restclient.Result{Status: restclient.Accepted, CPUTimeNS: 1, WallTimeNS: 2, MemoryBytes: 12345, CachedFiles: map[string]restclient.FileID{}}
	out := []byte{0xff, 0x00, 'A'}
	if strings.Contains(req.RequestID, "qualification") {
		switch {
		case c.Args[0] == "/usr/bin/g++" && c.Args[1] == "--version":
			out = []byte(CompilerVersion + "\nversion prose\n")
		case c.Args[0] == "/usr/local/bin/python3":
			out = []byte("Python 3.11.15\n")
		case c.Args[0] == "/w/main":
			out = []byte("startrack-cpp17\n")
		case c.Args[0] == "/usr/local/bin/startrack-checker-launcher":
			r.Status = restclient.NonzeroExit
			r.ExitStatus = 42
			if string(record.stdin) == "wrong\n" {
				r.ExitStatus = 43
			}
		}
	} else {
		switch c.Args[0] {
		case "/usr/bin/g++":
			if f.compileStatus != "" {
				r.Status = f.compileStatus
				if r.Status == restclient.NonzeroExit {
					r.ExitStatus = 1
				}
			}
		case "/w/main":
			if f.runError != nil {
				return nil, f.runError
			}
			if f.runStatus != "" {
				r.Status = f.runStatus
			}
		case "/usr/local/bin/startrack-checker-launcher":
			r.Status = restclient.NonzeroExit
			r.ExitStatus = 42
			if f.checkerCount < len(f.checkerExits) {
				r.ExitStatus = f.checkerExits[f.checkerCount]
			}
			f.checkerCount++
		case "/usr/local/bin/python3":
			r.Status = restclient.NonzeroExit
			r.ExitStatus = 42
		}
	}
	for _, output := range c.CopyOutCached {
		contents := []byte{}
		if output.Name == "stdout" {
			contents = out
		}
		if output.Name == "main" {
			contents = []byte{0x7f, 'E', 'L', 'F', 1, 2, 3}
		}
		r.CachedFiles[output.Name] = s.upload(contents)
	}
	return []restclient.Result{r}, nil
}
func (s *mockSession) Download(ctx context.Context, id restclient.FileID, max int64) ([]byte, error) {
	s.factory.mu.Lock()
	defer s.factory.mu.Unlock()
	data := s.factory.data[id]
	if s.closed || !s.ids[id] || int64(len(data)) > max || ctx.Err() != nil {
		return nil, errors.New("download failed")
	}
	return bytes.Clone(data), nil
}
func (s *mockSession) Close() error {
	s.factory.mu.Lock()
	defer s.factory.mu.Unlock()
	if !s.closed {
		s.factory.closed++
		s.closed = true
	}
	for id := range s.ids {
		delete(s.factory.data, id)
	}
	return nil
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	directory, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(directory, 0700); e != nil {
		t.Fatal(e)
	}
	return directory
}
func testAdapter(t *testing.T) (*Adapter, *mockFactory, *testVerifier, memoryBlobs) {
	t.Helper()
	checker := []byte{0x7f, 'E', 'L', 'F', 'c', 'h', 'e', 'c', 'k'}
	identity := FrozenIdentity{LanguageConfigVersion: CompilerConfigVersion, CompilerVersion: CompilerVersion, ToolchainDigest: CPP17ToolchainDigest, WorkerImageDigest: "sha256:" + strings.Repeat("1", 64), SandboxVersion: SandboxVersion, CheckerDigest: canonical.HashBytes(checker)}
	directory := privateTempDir(t)
	ledger, e := NewFileLedger(directory)
	if e != nil {
		t.Fatal(e)
	}
	factory := &mockFactory{data: map[restclient.FileID][]byte{}}
	verifier := &testVerifier{instance: "boot:pid:start:profile"}
	blobs := memoryBlobs{}
	a, e := New(Options{Factory: factory, Reader: blobs, Identity: identity, Checker: checker, Verifier: verifier, Ledger: ledger, AnalysisSupported: true})
	if e != nil {
		t.Fatal(e)
	}
	if e = a.Qualify(context.Background()); e != nil {
		t.Fatal(e)
	}
	return a, factory, verifier, blobs
}
func testTask(a *Adapter, blobs memoryBlobs, count int) TaskInput {
	source := []byte("int main(){return 0;}\n")
	task := TaskInput{TaskID: "11111111-1111-4111-8111-111111111111", FencingToken: "22222222-2222-4222-8222-222222222222", LanguageID: LanguageID, Identity: a.Identity(), Source: source, SourceSHA256: canonical.HashBytes(source), Limits: Limits{CPUTimeNS: uint64(time.Second), WallTimeNS: uint64(2 * time.Second), MemoryBytes: 128 << 20, OutputBytes: 8 << 20, Processes: 32}, Cases: []Case{}}
	for i := 1; i <= count; i++ {
		in := []byte(fmt.Sprintf("private-input-%d\xff\x00", i))
		ans := []byte(fmt.Sprintf("private-answer-%d", i))
		ir := BlobRef{SHA256: canonical.HashBytes(in), SizeBytes: int64(len(in))}
		ar := BlobRef{SHA256: canonical.HashBytes(ans), SizeBytes: int64(len(ans))}
		blobs[ir.SHA256] = in
		blobs[ar.SHA256] = ans
		task.Cases = append(task.Cases, Case{TestCaseID: contract.UUID(fmt.Sprintf("33333333-3333-4333-8333-%012d", i)), Ordinal: i, Input: ir, Answer: ar, Checker: DefaultChecker()})
	}
	return task
}

func TestRoleVerdictMatrix(t *testing.T) {
	for _, tc := range []struct {
		status                  restclient.Status
		exit                    int
		user, compiler, checker contract.JudgeVerdict
	}{
		{restclient.Accepted, 0, contract.VerdictAC, contract.VerdictAC, contract.VerdictIE},
		{restclient.NonzeroExit, 1, contract.VerdictRE, contract.VerdictCE, contract.VerdictIE},
		{restclient.NonzeroExit, 42, contract.VerdictRE, contract.VerdictCE, contract.VerdictAC},
		{restclient.NonzeroExit, 43, contract.VerdictRE, contract.VerdictCE, contract.VerdictWA},
		{restclient.NonzeroExit, 127, contract.VerdictRE, contract.VerdictIE, contract.VerdictIE},
		{restclient.Signalled, 9, contract.VerdictRE, contract.VerdictIE, contract.VerdictIE},
		{restclient.TimeLimit, 0, contract.VerdictTLE, contract.VerdictCE, contract.VerdictIE},
		{restclient.MemoryLimit, 0, contract.VerdictMLE, contract.VerdictCE, contract.VerdictIE},
		{restclient.OutputLimit, 0, contract.VerdictOLE, contract.VerdictCE, contract.VerdictIE},
		{restclient.DangerousSyscall, 0, contract.VerdictRE, contract.VerdictIE, contract.VerdictIE},
		{restclient.FileError, 0, contract.VerdictIE, contract.VerdictIE, contract.VerdictIE},
		{restclient.InternalError, 0, contract.VerdictIE, contract.VerdictIE, contract.VerdictIE},
		{restclient.JudgementFailed, 0, contract.VerdictIE, contract.VerdictIE, contract.VerdictIE},
		{restclient.WrongAnswer, 0, contract.VerdictIE, contract.VerdictIE, contract.VerdictIE},
	} {
		t.Run(string(tc.status)+fmt.Sprint(tc.exit), func(t *testing.T) {
			r := restclient.Result{Status: tc.status, ExitStatus: tc.exit}
			compiler, _ := compilerVerdict(r)
			if contestantVerdict(r) != tc.user || compiler != tc.compiler || checkerVerdict(r) != tc.checker {
				t.Fatalf("role classification mismatch for %s", tc.status)
			}
		})
	}
	resource := restclient.Result{Status: restclient.FileError, FileErrorCount: 1, FileErrorTypes: []restclient.FileErrorType{restclient.CopyOutSizeExceeded}}
	verdict, _ := compilerVerdict(resource)
	if verdict != contract.VerdictCE || contestantVerdict(resource) != contract.VerdictOLE || checkerVerdict(resource) != contract.VerdictIE {
		t.Fatal("resource exhaustion misclassified")
	}
}

func TestOrderedCasesPrivateRolesAndExactBinaryStdin(t *testing.T) {
	a, f, _, blobs := testAdapter(t)
	task := testTask(a, blobs, 3)
	f.checkerExits = []int{42, 43, 42}
	var progress []Progress
	out, e := a.Execute(context.Background(), task, func(_ context.Context, p Progress) error { progress = append(progress, p); return nil })
	if e != nil {
		t.Fatal(e)
	}
	if out.Result.Verdict != contract.VerdictWA || out.Result.PassedTestCount != 1 || out.Result.TotalTestCount != 3 || len(out.Cases) != 2 || out.Result.TimeMs == nil || *out.Result.TimeMs != 1 || out.Result.MemoryBytes == nil || *out.Result.MemoryBytes != 12345 {
		t.Fatalf("incorrect first-failure aggregation: %+v", out.Result)
	}
	if len(progress) != 4 || progress[0].Status != "Compiling" || progress[1].Status != "Compiled" || progress[2].Ordinal != 1 || progress[3].Ordinal != 2 {
		t.Fatal("progress/order mismatch")
	}
	for _, record := range f.requests {
		if strings.Contains(record.request.RequestID, "qualification") {
			continue
		}
		cmd := record.request.Commands[0]
		if cmd.Args[0] == "/w/main" {
			if len(record.inputs) != 1 || record.inputs["main"] == nil {
				t.Fatal("contestant saw non-executable copy-in")
			}
			for _, value := range record.inputs {
				if bytes.Contains(value, []byte("private-answer")) {
					t.Fatal("answer copied into user role")
				}
			}
			if !bytes.Contains(record.stdin, []byte{0xff, 0x00}) {
				t.Fatal("binary input changed")
			}
		}
		if cmd.Args[0] == "/usr/local/bin/startrack-checker-launcher" {
			if !bytes.Equal(record.stdin, []byte{0xff, 0x00, 'A'}) {
				t.Fatal("checker stdin bytes changed")
			}
			if len(record.inputs) != 3 || record.inputs["answer"] == nil || record.inputs["input"] == nil {
				t.Fatal("checker private files missing")
			}
			if cmd.Args[4] != "/w/feedback" {
				t.Fatal("checker protocol mismatch")
			}
		}
	}
	if len(f.data) != 0 {
		t.Fatal("sandbox cache not reclaimed")
	}
	if _, e = a.Execute(context.Background(), task, nil); e == nil {
		t.Fatal("same fence executed twice")
	}
}

func TestFailedAcknowledgmentPreventsCompilation(t *testing.T) {
	a, f, _, blobs := testAdapter(t)
	task := testTask(a, blobs, 1)
	before := len(f.requests)
	_, e := a.Execute(context.Background(), task, func(context.Context, Progress) error { return errors.New("lease lost") })
	if e == nil || len(f.requests) != before {
		t.Fatal("compiler ran after failed durable RUNNING acknowledgment")
	}
}
func TestAmbiguousTransportIsNeverRetried(t *testing.T) {
	a, f, _, blobs := testAdapter(t)
	task := testTask(a, blobs, 1)
	f.runError = &restclient.Error{Kind: restclient.TransportError, Retryable: true}
	_, e := a.Execute(context.Background(), task, nil)
	var failure *Failure
	if !errors.As(e, &failure) || !failure.Ambiguous {
		t.Fatal("ambiguous operation lost")
	}
	before := len(f.requests)
	if _, e = a.Execute(context.Background(), task, nil); e == nil || len(f.requests) != before {
		t.Fatal("uncertain fence retried")
	}
}
func TestReadinessDoesNotSurviveSandboxRestart(t *testing.T) {
	a, f, v, blobs := testAdapter(t)
	task := testTask(a, blobs, 1)
	v.mu.Lock()
	v.instance = "different-process"
	v.mu.Unlock()
	snapshot := a.Snapshot(context.Background())
	if snapshot.Qualified || snapshot.SandboxReady || len(snapshot.Languages.Languages) != 0 {
		t.Fatal("stale process qualification reused")
	}
	before := len(f.requests)
	if _, e := a.Execute(context.Background(), task, nil); e == nil || len(f.requests) != before {
		t.Fatal("unqualified runtime executed task")
	}
}
func TestSourceAndPrivateBlobIntegrityGate(t *testing.T) {
	a, f, _, blobs := testAdapter(t)
	task := testTask(a, blobs, 1)
	task.Source[0] = 'X'
	before := len(f.requests)
	if _, e := a.Execute(context.Background(), task, nil); e == nil || len(f.requests) != before {
		t.Fatal("modified source dispatched")
	}
	task = testTask(a, blobs, 1)
	blobs[task.Cases[0].Input.SHA256] = []byte("modified private bytes")
	out, e := a.Execute(context.Background(), task, nil)
	if e != nil || out.Result.Verdict != contract.VerdictIE || out.Error == nil {
		t.Fatal("modified hidden input did not fail as definitive IE")
	}
}
func TestCompilerCEHasNoUserMeasurementsOrRawLog(t *testing.T) {
	a, f, _, blobs := testAdapter(t)
	task := testTask(a, blobs, 2)
	f.compileStatus = restclient.NonzeroExit
	out, e := a.Execute(context.Background(), task, nil)
	if e != nil {
		t.Fatal(e)
	}
	if out.Result.Verdict != contract.VerdictCE || out.Result.PassedTestCount != 0 || out.Result.TimeMs != nil || out.Result.MemoryBytes != nil || len(out.Cases) != 0 || out.Result.CompileLog == nil || strings.Contains(*out.Result.CompileLog, "private") {
		t.Fatal("compile failure projection incorrect")
	}
}
func TestCompilerCheckerAndUserFailureSemantics(t *testing.T) {
	for _, status := range []restclient.Status{restclient.TimeLimit, restclient.MemoryLimit, restclient.OutputLimit} {
		t.Run(string(status), func(t *testing.T) {
			a, f, _, blobs := testAdapter(t)
			task := testTask(a, blobs, 1)
			f.runStatus = status
			out, e := a.Execute(context.Background(), task, nil)
			if e != nil || out.Result.Verdict != contestantVerdict(restclient.Result{Status: status}) {
				t.Fatal("user resource failure incorrect")
			}
		})
	}
	a, f, _, blobs := testAdapter(t)
	f.checkerExits = []int{44}
	out, e := a.Execute(context.Background(), testTask(a, blobs, 1), nil)
	if e != nil || out.Result.Verdict != contract.VerdictIE || out.Error == nil {
		t.Fatal("checker failure blamed on user")
	}
}
func TestCheckerTolerancesAreBoundedTypedArguments(t *testing.T) {
	for _, value := range []string{"0", "0.0001", "1e-6", "1"} {
		c := DefaultChecker()
		c.FloatAbsoluteTolerance = &value
		if c.Validate() != nil {
			t.Fatalf("valid tolerance %s rejected", value)
		}
	}
	for _, value := range []string{"NaN", "-1", "1.01", "0;cat /answer", "1e99999"} {
		c := DefaultChecker()
		c.FloatRelativeTolerance = &value
		if c.Validate() == nil {
			t.Fatalf("invalid tolerance accepted")
		}
	}
}
