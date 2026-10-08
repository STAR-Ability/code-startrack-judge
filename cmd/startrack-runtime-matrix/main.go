// SPDX-License-Identifier: Apache-2.0
// This fixed Linux qualification tool executes synthetic programs through the
// real typed adapter. It has no user-command, path, URL, or template interface.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	goruntime "runtime"
	"sync/atomic"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/processguard"
	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
	"github.com/STAR-Ability/code-startrack-judge/internal/runtime/restclient"
)

type matrixControl struct {
	Token             string `json:"token"`
	WorkerImageDigest string `json:"workerImageDigest"`
	CheckerDigest     string `json:"checkerDigest"`
	BridgeDigest      string `json:"bridgeDigest"`
}

func (matrixControl) String() string     { return "private runtime matrix control [credential redacted]" }
func (c matrixControl) GoString() string { return c.String() }

type caseEvidence struct {
	Name          string                `json:"name"`
	Expected      contract.JudgeVerdict `json:"expected"`
	Actual        contract.JudgeVerdict `json:"actual"`
	Passed        bool                  `json:"passed"`
	ExecutedCases int                   `json:"executedCases"`
	CPUTimeNS     uint64                `json:"cpuTimeNs"`
	MemoryBytes   uint64                `json:"memoryBytes"`
}
type defaultCheckerEvidence struct {
	judgeruntime.DefaultCheckerQualification
	PrivateLog privateLogEvidence `json:"privateLog"`
}
type matrixReport struct {
	Version                      int                         `json:"version"`
	Environment                  string                      `json:"environment"`
	Identity                     judgeruntime.FrozenIdentity `json:"identity"`
	Passed                       bool                        `json:"passed"`
	Cases                        []caseEvidence              `json:"cases"`
	Mature                       []matureEvidence            `json:"mature"`
	DefaultChecker               defaultCheckerEvidence      `json:"defaultChecker"`
	Statement                    statementEvidence           `json:"statement"`
	LargeStatement               largeStatementEvidence      `json:"largeStatement"`
	Workspace                    workspaceEvidence           `json:"workspace"`
	MatureDuplicateFenceRejected bool                        `json:"matureDuplicateFenceRejected"`
	DuplicateFenceRejected       bool                        `json:"duplicateFenceRejected"`
	OpenedSessions               int64                       `json:"openedSessions"`
	CleanedSessions              int64                       `json:"cleanedSessions"`
	SpoolRemoved                 bool                        `json:"spoolRemoved"`
	FailureCode                  string                      `json:"failureCode,omitempty"`
}
type matrixBlobs struct {
	files   map[string][]byte
	corrupt string
}

func (b *matrixBlobs) ReadBlob(ctx context.Context, sha string, size, max int64) ([]byte, error) {
	raw, exists := b.files[sha]
	if !exists || ctx.Err() != nil || int64(len(raw)) != size || size > max {
		return nil, errors.New("private fixture lookup failed")
	}
	if sha == b.corrupt {
		return []byte("corrupted private answer"), nil
	}
	return bytes.Clone(raw), nil
}
func (b *matrixBlobs) add(raw []byte) judgeruntime.BlobRef {
	sha := canonical.HashBytes(raw)
	b.files[sha] = bytes.Clone(raw)
	return judgeruntime.BlobRef{SHA256: sha, SizeBytes: int64(len(raw))}
}

type matrixFactory struct {
	client  *restclient.Client
	opened  atomic.Int64
	cleaned atomic.Int64
}

func (f *matrixFactory) NewSession() judgeruntime.Session {
	f.opened.Add(1)
	return &matrixSession{Session: f.client.NewSession(), factory: f}
}

type matrixSession struct {
	judgeruntime.Session
	factory *matrixFactory
	closed  bool
}

func (s *matrixSession) Close() error {
	e := s.Session.Close()
	if e == nil && !s.closed {
		s.closed = true
		s.factory.cleaned.Add(1)
	}
	return e
}

func main() {
	if processguard.Harden() != nil {
		os.Stderr.WriteString("runtime matrix process hardening unavailable\n")
		os.Exit(1)
	}
	if len(os.Args) != 1 || goruntime.GOOS != "linux" || goruntime.GOARCH != "amd64" || os.Geteuid() != 20001 {
		os.Stderr.WriteString("runtime matrix environment invalid\n")
		os.Exit(1)
	}
	control, e := readControl()
	if e != nil {
		os.Stderr.WriteString("runtime matrix control invalid\n")
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	report, e := runMatrix(ctx, control)
	if e != nil {
		report.Passed = false
		report.FailureCode = "RUNTIME_MATRIX_FAILED"
	}
	if json.NewEncoder(os.Stdout).Encode(report) != nil || e != nil || !report.Passed {
		os.Exit(1)
	}
}
func readControl() (control matrixControl, err error) {
	raw, e := io.ReadAll(io.LimitReader(os.Stdin, 4097))
	if e != nil || len(raw) > 4096 || canonical.ValidateJSON(raw) != nil {
		return control, errors.New("invalid matrix control")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&control) != nil || !errors.Is(d.Decode(new(any)), io.EOF) {
		return control, errors.New("invalid matrix control")
	}
	return control, nil
}
func fixedFile(path string, max int64) ([]byte, error) {
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 || info.Size() > max {
		return nil, errors.New("fixed matrix tool unavailable")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, errors.New("fixed matrix tool unavailable")
	}
	defer f.Close()
	raw, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(raw)) > max {
		return nil, errors.New("fixed matrix tool unavailable")
	}
	return raw, nil
}
func runMatrix(ctx context.Context, control matrixControl) (report matrixReport, err error) {
	report.Version, report.Environment = 1, "linux/amd64"
	report.Cases = []caseEvidence{}
	identity := judgeruntime.FrozenIdentity{LanguageConfigVersion: judgeruntime.CompilerConfigVersion, CompilerVersion: judgeruntime.CompilerVersion, ToolchainDigest: judgeruntime.CPP17ToolchainDigest, WorkerImageDigest: control.WorkerImageDigest, SandboxVersion: judgeruntime.SandboxVersion, CheckerDigest: control.CheckerDigest}
	report.Identity = identity
	if identity.Validate() != nil {
		return report, errors.New("matrix identity invalid")
	}
	client, e := restclient.New(restclient.Options{Token: control.Token})
	if e != nil {
		return report, errors.New("matrix transport invalid")
	}
	checker, e := fixedFile("/opt/startrack/libexec/default_validator", judgeruntime.MaxFileBytes)
	if e != nil {
		return report, e
	}
	grader, e := fixedFile("/opt/startrack/libexec/default_grader", judgeruntime.MaxFileBytes)
	if e != nil {
		return report, e
	}
	directory, e := os.MkdirTemp("/run/startrack-judger/tmp", "matrix-")
	if e != nil {
		return report, errors.New("matrix spool unavailable")
	}
	defer func() {
		if !report.SpoolRemoved {
			if os.RemoveAll(directory) != nil {
				err = errors.New("matrix spool cleanup failed")
			} else {
				report.SpoolRemoved = true
			}
		}
	}()
	ledger, e := judgeruntime.NewFileLedger(directory)
	if e != nil {
		return report, e
	}
	blobs := &matrixBlobs{files: map[string][]byte{}}
	factory := &matrixFactory{client: client}
	adapter, e := judgeruntime.New(judgeruntime.Options{Factory: factory, Reader: blobs, Identity: identity, Checker: checker, Grader: grader, BridgeDigest: control.BridgeDigest, Verifier: judgeruntime.LinuxMeasurementVerifier{}, Ledger: ledger})
	if e != nil {
		return report, e
	}
	if e := adapter.Qualify(ctx); e != nil || !adapter.Snapshot(ctx).MatureReady {
		return report, errors.New("matrix runtime unqualified")
	}
	limits := judgeruntime.Limits{CPUTimeNS: uint64(500 * time.Millisecond), WallTimeNS: uint64(time.Second), MemoryBytes: 64 << 20, OutputBytes: 8192, Processes: 32}
	fixtures := []struct {
		name, source string
		answer       []byte
		checker      judgeruntime.CheckerConfig
		verdict      contract.JudgeVerdict
		limits       judgeruntime.Limits
		corrupt      bool
	}{
		{"AC", sumProgram, []byte("5\n"), judgeruntime.DefaultChecker(), contract.VerdictAC, limits, false},
		{"WA", printProgram("6"), []byte("5\n"), judgeruntime.DefaultChecker(), contract.VerdictWA, limits, false},
		{"CE", "int main( {", []byte("5\n"), judgeruntime.DefaultChecker(), contract.VerdictCE, limits, false},
		{"TLE", busyProgram, []byte("5\n"), judgeruntime.DefaultChecker(), contract.VerdictTLE, limits, false},
		{"WALL_TLE", sleepProgram, []byte("5\n"), judgeruntime.DefaultChecker(), contract.VerdictTLE, limits, false},
		{"MLE", memoryProgram, []byte("5\n"), judgeruntime.DefaultChecker(), contract.VerdictMLE, func() judgeruntime.Limits { l := limits; l.MemoryBytes = 16 << 20; return l }(), false},
		{"OLE", outputProgram, []byte("5\n"), judgeruntime.DefaultChecker(), contract.VerdictOLE, limits, false},
		{"RE", signalProgram, []byte("5\n"), judgeruntime.DefaultChecker(), contract.VerdictRE, limits, false},
		{"IE_PRIVATE_ANSWER_INTEGRITY", sumProgram, []byte("5\n"), judgeruntime.DefaultChecker(), contract.VerdictIE, limits, true},
		{"CHECKER_CASE_INSENSITIVE", printProgram("Token"), []byte("token\n"), judgeruntime.DefaultChecker(), contract.VerdictAC, limits, false},
		{"CHECKER_CASE_SENSITIVE", printProgram("Token"), []byte("token\n"), func() judgeruntime.CheckerConfig {
			c := judgeruntime.DefaultChecker()
			c.CaseSensitive = true
			return c
		}(), contract.VerdictWA, limits, false},
		{"CHECKER_FLOAT_ABSOLUTE", printProgram("1.005"), []byte("1.0\n"), func() judgeruntime.CheckerConfig {
			c := judgeruntime.DefaultChecker()
			v := "0.01"
			c.FloatAbsoluteTolerance = &v
			return c
		}(), contract.VerdictAC, limits, false},
		{"BINARY_STDIO", binaryProgram, []byte{0xff, 0, 'A'}, func() judgeruntime.CheckerConfig {
			c := judgeruntime.DefaultChecker()
			c.CaseSensitive = true
			return c
		}(), contract.VerdictAC, limits, false},
	}
	for i, fixture := range fixtures {
		if e := adapter.Qualify(ctx); e != nil {
			return report, errors.New("matrix runtime refresh failed")
		}
		input := blobs.add([]byte("2 3\n"))
		answer := blobs.add(fixture.answer)
		task := judgeruntime.TaskInput{TaskID: matrixUUID(i*4 + 1), FencingToken: matrixUUID(i*4 + 2), LanguageID: judgeruntime.LanguageID, Identity: identity, Source: []byte(fixture.source), SourceSHA256: canonical.HashBytes([]byte(fixture.source)), Limits: fixture.limits, Cases: []judgeruntime.Case{{TestCaseID: matrixUUID(i*4 + 3), Ordinal: 1, Input: input, Answer: answer, Checker: fixture.checker}, {TestCaseID: matrixUUID(i*4 + 4), Ordinal: 2, Input: input, Answer: answer, Checker: fixture.checker}}}
		blobs.corrupt = ""
		if fixture.corrupt {
			blobs.corrupt = answer.SHA256
		}
		out, e := adapter.Execute(ctx, task, func(context.Context, judgeruntime.Progress) error { return nil })
		ev := caseEvidence{Name: fixture.name, Expected: fixture.verdict, Actual: out.Result.Verdict, ExecutedCases: len(out.Cases)}
		for _, c := range out.Cases {
			if c.CPUTimeNS > ev.CPUTimeNS {
				ev.CPUTimeNS = c.CPUTimeNS
			}
			if c.MemoryBytes > ev.MemoryBytes {
				ev.MemoryBytes = c.MemoryBytes
			}
		}
		wantCases := 1
		if fixture.verdict == contract.VerdictCE {
			wantCases = 0
		}
		if fixture.verdict == contract.VerdictAC {
			wantCases = 2
		}
		ev.Passed = e == nil && out.Result.Verdict == fixture.verdict && out.Result.TotalTestCount == 2 && len(out.Cases) == wantCases && out.Result.Validate() == nil
		if fixture.verdict == contract.VerdictAC {
			ev.Passed = ev.Passed && out.Result.PassedTestCount == 2
		} else {
			ev.Passed = ev.Passed && out.Result.PassedTestCount == 0
		}
		if len(out.Cases) > 0 {
			wantMS := ev.CPUTimeNS / uint64(time.Millisecond)
			if ev.CPUTimeNS%uint64(time.Millisecond) != 0 {
				wantMS++
			}
			ev.Passed = ev.Passed && out.Result.TimeMs != nil && uint64(*out.Result.TimeMs) == wantMS && out.Result.MemoryBytes != nil && uint64(*out.Result.MemoryBytes) == ev.MemoryBytes
		}
		report.Cases = append(report.Cases, ev)
		if !ev.Passed {
			return report, errors.New("real native verdict matrix mismatch")
		}
		if i == 0 {
			before := factory.opened.Load()
			_, duplicate := adapter.Execute(ctx, task, nil)
			report.DuplicateFenceRejected = duplicate != nil && factory.opened.Load() == before
			if !report.DuplicateFenceRejected {
				return report, errors.New("matrix fence reused")
			}
		}
	}
	blobs.corrupt = ""
	if adapter.Qualify(ctx) != nil {
		return report, errors.New("default checker matrix refresh failed")
	}
	checkerRegression, checkerErr := adapter.QualifyDefaultChecker(ctx)
	checkerLog, logErr := retainMatrixLog("DEFAULT_CHECKER_REGRESSIONS", checkerRegression.RawLog)
	report.DefaultChecker = defaultCheckerEvidence{DefaultCheckerQualification: checkerRegression, PrivateLog: checkerLog}
	if checkerErr != nil || logErr != nil || !checkerRegression.Passed {
		return report, errors.New("pinned default checker matrix mismatch")
	}
	if e := runMatureMatrix(ctx, adapter, blobs, factory, &report); e != nil {
		return report, e
	}
	if e := runWorkspaceMatrix(ctx, adapter, blobs, &report); e != nil {
		return report, e
	}
	if adapter.Qualify(ctx) != nil {
		return report, errors.New("matrix final runtime refresh failed")
	}
	report.OpenedSessions, report.CleanedSessions = factory.opened.Load(), factory.cleaned.Load()
	if report.OpenedSessions != report.CleanedSessions || !adapter.Snapshot(ctx).Qualified {
		return report, errors.New("matrix cleanup or readiness failed")
	}
	if os.RemoveAll(directory) != nil {
		return report, errors.New("matrix spool cleanup failed")
	}
	report.SpoolRemoved = true
	if _, e := os.Lstat(filepath.Clean(directory)); !errors.Is(e, os.ErrNotExist) {
		return report, errors.New("matrix spool retained")
	}
	report.Passed = true
	return report, nil
}
func matrixUUID(n int) contract.UUID {
	return contract.UUID(fmt.Sprintf("00000000-0000-4000-8000-%012d", n))
}
func printProgram(value string) string {
	return "#include <cstdio>\nint main(){std::puts(\"" + value + "\");}\n"
}

const sumProgram = "#include <cstdio>\nint main(){long a,b;if(std::scanf(\"%ld %ld\",&a,&b)!=2)return 1;std::printf(\"%ld\\n\",a+b);}\n"
const busyProgram = "int main(){volatile unsigned long x=0;for(;;)x++;}\n"
const sleepProgram = "#include <unistd.h>\nint main(){sleep(10);}\n"
const memoryProgram = "#include <fcntl.h>\n#include <sys/mman.h>\n#include <unistd.h>\nint main(){const int n=64<<20;int fd=open(\"/w/matrix-memory\",O_RDWR|O_CREAT|O_EXCL,0600);if(fd<0)return 71;if(ftruncate(fd,n)!=0)return 72;void* mapped=mmap(nullptr,n,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);if(mapped==MAP_FAILED)return 73;close(fd);volatile char* p=(volatile char*)mapped;for(int i=0;i<n;i+=4096)p[i]=1;}\n"
const outputProgram = "#include <unistd.h>\nint main(){char p[8192]={};for(;;)if(write(1,p,sizeof(p))<0)return 0;}\n"
const signalProgram = "#include <csignal>\nint main(){std::raise(SIGSEGV);}\n"
const binaryProgram = "#include <unistd.h>\nint main(){unsigned char p[]={255,0,65};return write(1,p,sizeof(p))==3?0:1;}\n"
