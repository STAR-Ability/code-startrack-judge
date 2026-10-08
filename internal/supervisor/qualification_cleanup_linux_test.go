//go:build linux

package supervisor

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const cleanupTestNonce = "0123456789abcdef0123456789abcdef"

var cleanupTestModes = []string{"compiler", "inspect-a", "inspect-b", "cpu", "wall", "memory", "output", "fork", "dirty", "inspect"}

// This trusted test executable supplies actual live /proc identities and exact
// argv, without executing a compiler or workload. No production binary contains
// this helper. The cgroup directories below are explicitly ordinary unit files.
func init() {
	if os.Getenv("STARTRACK_QUALIFICATION_CLEANUP_TEST_HELPER") == "1" {
		ready := os.NewFile(3, "cleanup-test-ready")
		if ready == nil {
			os.Exit(97)
		}
		if _, err := ready.Write([]byte{'R'}); err != nil {
			os.Exit(97)
		}
		_ = ready.Close()
		time.Sleep(time.Minute)
		os.Exit(0)
	}
}

func cleanupTestArgs(mode, nonce string) []string {
	if mode == "compiler" {
		return []string{"/usr/bin/g++", "-std=c++17", "-O0", "/w/probe-" + nonce + ".cpp", "-o", "/w/probe"}
	}
	return []string{"/w/probe", mode, nonce}
}

func cleanupTestCmdline(args []string) []byte {
	return []byte(strings.Join(args, "\x00") + "\x00")
}

type cleanupTestChild struct {
	cmd    *exec.Cmd
	reaped bool
}

func cleanupTestStart(t *testing.T, mode string) *cleanupTestChild {
	t.Helper()
	return cleanupTestStartNonce(t, mode, cleanupTestNonce)
}

func cleanupTestStartNonce(t *testing.T, mode, nonce string) *cleanupTestChild {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary)
	cmd.Args = cleanupTestArgs(mode, nonce)
	cmd.Env = []string{"STARTRACK_QUALIFICATION_CLEANUP_TEST_HELPER=1"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	cmd.ExtraFiles = []*os.File{writer}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	child := &cleanupTestChild{cmd: cmd}
	t.Cleanup(func() { child.reap() })
	_ = writer.Close()
	if err := reader.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var ready [1]byte
	if _, err := io.ReadFull(reader, ready[:]); err != nil || ready[0] != 'R' {
		t.Fatalf("trusted helper did not finish startup: %v", err)
	}
	actual, err := qualificationRead(fmt.Sprintf("/proc/%d/cmdline", cmd.Process.Pid))
	if err != nil || string(actual) != string(cleanupTestCmdline(cmd.Args)) {
		t.Fatalf("ready helper did not retain its fixed test argv: %v", err)
	}
	return child
}

func (child *cleanupTestChild) reap() {
	if !child.reaped {
		_ = child.cmd.Process.Kill()
		_ = child.cmd.Wait()
		child.reaped = true
	}
}

func cleanupTestWrite(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
}

func cleanupTestGroup(t *testing.T, path string, pids ...int) qualificationGroup {
	t.Helper()
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	var roster strings.Builder
	for _, pid := range pids {
		fmt.Fprintln(&roster, pid)
	}
	cleanupTestWrite(t, filepath.Join(path, "cgroup.procs"), roster.String())
	cleanupTestWrite(t, filepath.Join(path, "pids.current"), strconv.Itoa(len(pids))+"\n")
	cleanupTestWrite(t, filepath.Join(path, "memory.max"), "536870912\n")
	cleanupTestWrite(t, filepath.Join(path, "pids.max"), "32\n")
	cleanupTestWrite(t, filepath.Join(path, "cpu.stat"), "usage_usec 1\nuser_usec 1\nsystem_usec 0\n")
	identity, err := qualificationGroupIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

type cleanupTestFixture struct {
	q           *qualificationCleanup
	directory   string
	groups      []string
	roots       map[string]*cleanupTestChild
	descendants []*cleanupTestChild
}

func cleanupTestObserved(t *testing.T) *cleanupTestFixture {
	t.Helper()
	f := &cleanupTestFixture{q: newQualificationCleanup(cleanupTestNonce), directory: t.TempDir(), roots: map[string]*cleanupTestChild{}}
	t.Cleanup(f.q.close)
	for _, mode := range cleanupTestModes {
		child := cleanupTestStart(t, mode)
		f.roots[mode] = child
		members := []int{child.cmd.Process.Pid}
		if mode == "fork" {
			// These real test children model two additional members of the
			// execution group; their actual identities must also be captured.
			for range 2 {
				descendant := cleanupTestStart(t, "fork")
				f.descendants = append(f.descendants, descendant)
				members = append(members, descendant.cmd.Process.Pid)
			}
		}
		path := filepath.Join(f.directory, mode)
		cleanupTestGroup(t, path, members...)
		f.groups = append(f.groups, path)
		owned := f.q.observe(path, child.cmd.Process.Pid, cleanupTestCmdline(child.cmd.Args))
		if !owned || f.q.failed || !f.q.modes[mode] {
			t.Fatalf("positive observation for %s did not bind the ready live root and group: failed=%t groups=%d processes=%d", mode, f.q.failed, len(f.q.groups), len(f.q.processes))
		}
	}
	if len(f.q.groups) != 10 || len(f.q.processes) != 12 || f.q.forkPeak != 3 {
		t.Fatalf("incomplete positive witnesses: groups=%d processes=%d fork=%d", len(f.q.groups), len(f.q.processes), f.q.forkPeak)
	}
	return f
}

func (f *cleanupTestFixture) drain(t *testing.T, keep ...*cleanupTestChild) {
	t.Helper()
	retained := map[*cleanupTestChild]bool{}
	for _, child := range keep {
		retained[child] = true
	}
	for _, child := range f.roots {
		if !retained[child] {
			child.reap()
		}
	}
	for _, child := range f.descendants {
		if !retained[child] {
			child.reap()
		}
	}
	for _, path := range f.groups {
		cleanupTestWrite(t, filepath.Join(path, "cgroup.procs"), "")
		cleanupTestWrite(t, filepath.Join(path, "pids.current"), "0\n")
	}
}

func cleanupTestClone(original *qualificationCleanup) *qualificationCleanup {
	copy := newQualificationCleanup(original.nonce)
	copy.forkPeak, copy.failed = original.forkPeak, original.failed
	copy.failure, copy.errorClass = original.failure, original.errorClass
	copy.cpu, copy.memory, copy.pids = original.cpu, original.memory, original.pids
	copy.compiler = original.compiler
	for key, value := range original.processes {
		copy.processes[key] = value
	}
	for key, value := range original.groups {
		copy.groups[key] = value
	}
	// Clones borrow descriptors; the original fixture alone closes them.
	for key, value := range original.descriptors {
		copy.descriptors[key] = value
	}
	for key, value := range original.modes {
		copy.modes[key] = value
	}
	return copy
}

func TestQualificationCleanupModeProtocol(t *testing.T) {
	q := newQualificationCleanup(cleanupTestNonce)
	for _, mode := range cleanupTestModes {
		if got := q.mode(cleanupTestCmdline(cleanupTestArgs(mode, cleanupTestNonce))); got != mode {
			t.Fatalf("expected %q, got %q", mode, got)
		}
	}
	invalid := [][]byte{
		cleanupTestCmdline(cleanupTestArgs("cpu", "stale-nonce")),
		[]byte("/w/probe\x00cpu\x00"),
		[]byte("/w/probe\x00cpu\x00" + cleanupTestNonce),
		cleanupTestCmdline([]string{"/w/probe", "cpu", cleanupTestNonce, "extra"}),
		cleanupTestCmdline([]string{"/w/probe-extra", "cpu", cleanupTestNonce}),
		cleanupTestCmdline([]string{"/w/probe", "cpu-extra", cleanupTestNonce}),
		cleanupTestCmdline([]string{"/usr/bin/g++", "-std=c++17", "-O2", "/w/probe-" + cleanupTestNonce + ".cpp", "-o", "/w/probe"}),
		cleanupTestCmdline(cleanupTestArgs("compiler", "stale-nonce")),
	}
	for index, args := range invalid {
		if got := q.mode(args); got != "" {
			t.Fatalf("invalid protocol case %d attributed %q", index, got)
		}
	}
}

func TestQualificationCleanupRefreshIgnoresUnrelatedActiveGroup(t *testing.T) {
	f := cleanupTestObserved(t)
	f.drain(t)
	unrelated := cleanupTestStartNonce(t, "wall", "unrelated-qualification-nonce")
	cleanupTestGroup(t, filepath.Join(f.directory, "unrelated"), unrelated.cmd.Process.Pid)
	evidence, passed := f.q.proof(3, false)
	if !passed || !evidence.OwnedProcessesReaped || !evidence.OwnedGroupsDrained || evidence.StartupGlobalIdle {
		t.Fatalf("drained owned execution rejected alongside unrelated active group: %+v", evidence)
	}
}

func TestQualificationCleanupGlobalIdleIsRequiredOnlyAtStartup(t *testing.T) {
	f := cleanupTestObserved(t)
	f.drain(t)
	calls := 0
	busy := func() bool { calls++; return false }
	evidence, passed := f.q.proofWithIdle(3, false, busy)
	if !passed || calls != 0 || evidence.StartupGlobalIdle || !evidence.OwnedProcessesReaped || !evidence.OwnedGroupsDrained {
		t.Fatalf("refresh consulted unrelated global activity: calls=%d evidence=%+v", calls, evidence)
	}
	evidence, passed = f.q.proofWithIdle(3, true, busy)
	if passed || calls != 1 || evidence.StartupGlobalIdle || !evidence.OwnedProcessesReaped || !evidence.OwnedGroupsDrained {
		t.Fatalf("startup accepted global activity or claimed idle: calls=%d evidence=%+v", calls, evidence)
	}
	calls = 0
	idle := func() bool { calls++; return true }
	evidence, passed = f.q.proofWithIdle(3, true, idle)
	if !passed || calls != 1 || !evidence.StartupGlobalIdle {
		t.Fatalf("startup did not record positively observed idle: calls=%d evidence=%+v", calls, evidence)
	}
	evidence, passed = f.q.proofWithIdle(3, true, nil)
	if passed || evidence.StartupGlobalIdle {
		t.Fatal("startup accepted an unavailable global idle check")
	}
}

func TestQualificationCleanupRejectsOwnedLiveProcesses(t *testing.T) {
	for _, descendant := range []bool{false, true} {
		t.Run(fmt.Sprintf("descendant-%t", descendant), func(t *testing.T) {
			f := cleanupTestObserved(t)
			live := f.roots["cpu"]
			if descendant {
				live = f.descendants[0]
			}
			f.drain(t, live)
			evidence, passed := f.q.proof(3, false)
			if passed || evidence.OwnedProcessesReaped || evidence.FailureStage != "process_reap" {
				t.Fatalf("original live owned process accepted despite empty group facts: %+v", evidence)
			}
		})
	}
}

func TestQualificationCleanupRejectsUnreapedZombie(t *testing.T) {
	f := cleanupTestObserved(t)
	zombie := f.roots["cpu"]
	f.drain(t, zombie)
	if err := zombie.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		data, err := qualificationRead(fmt.Sprintf("/proc/%d/stat", zombie.cmd.Process.Pid))
		if err != nil {
			t.Fatal(err)
		}
		fields := strings.Fields(string(data[strings.LastIndexByte(string(data), ')')+1:]))
		if len(fields) > 0 && fields[0] == "Z" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("trusted killed child did not become an unreaped zombie")
		}
		time.Sleep(time.Millisecond)
	}
	if _, passed := f.q.proof(3, false); passed {
		t.Fatal("unreaped owned zombie accepted")
	}
	zombie.reap()
	if _, passed := f.q.proof(3, false); !passed {
		t.Fatal("reaped child still rejected")
	}
}

func TestQualificationCleanupRejectsLateUnobservedGroupMember(t *testing.T) {
	f := cleanupTestObserved(t)
	f.drain(t)
	late := cleanupTestStart(t, "fork")
	cleanupTestWrite(t, filepath.Join(f.groups[0], "cgroup.procs"), strconv.Itoa(late.cmd.Process.Pid)+"\n")
	cleanupTestWrite(t, filepath.Join(f.groups[0], "pids.current"), "1\n")
	evidence, passed := f.q.proof(3, false)
	if passed || !evidence.OwnedProcessesReaped || evidence.OwnedGroupsDrained || evidence.FailureStage != "group_drain" {
		t.Fatalf("late group member accepted after original roster exited: %+v", evidence)
	}
}

func TestQualificationCleanupRequiresCompleteModeAndForkWitnesses(t *testing.T) {
	f := cleanupTestObserved(t)
	f.drain(t)
	for _, mode := range cleanupTestModes {
		t.Run("missing-"+mode, func(t *testing.T) {
			q := cleanupTestClone(f.q)
			delete(q.modes, mode)
			evidence, passed := q.proof(3, false)
			if passed || evidence.FailureStage != "coverage" || len(evidence.MissingModes) != 1 || evidence.MissingModes[0] != mode || evidence.OwnedProcessesReaped || evidence.OwnedGroupsDrained {
				t.Fatalf("absent %s observation accepted or misclassified: %+v", mode, evidence)
			}
		})
	}
	for _, peak := range []uint64{0, 1, 4, 9} {
		t.Run(fmt.Sprintf("fork-peak-%d", peak), func(t *testing.T) {
			if _, passed := f.q.proof(peak, false); passed {
				t.Fatal("invalid or insufficient full fork witness accepted")
			}
		})
	}
	failed := cleanupTestClone(f.q)
	failed.failed = true
	if _, passed := failed.proof(3, false); passed {
		t.Fatal("failed sampler accepted")
	}
	evidence, passed := failed.proof(3, true)
	if passed || evidence.StartupGlobalIdle {
		t.Fatal("failed startup proof claimed an observed global idle state")
	}
}

func TestQualificationCleanupDiagnosticFailureRemainsBoundedAndRejects(t *testing.T) {
	f := cleanupTestObserved(t)
	f.drain(t)
	privatePath := "/private/kernel-fact-" + cleanupTestNonce
	wrapped := &os.PathError{Op: "read", Path: privatePath, Err: syscall.ESRCH}
	readFailure := &qualificationReadFailure{class: qualificationErrorClass(wrapped)}
	if errors.Is(readFailure, syscall.ESRCH) || errors.Is(readFailure, os.ErrNotExist) || strings.Contains(readFailure.Error(), privatePath) {
		t.Fatal("diagnostic classification changed disappearance predicates or exposed a path")
	}
	if f.q.rejectObservation("member_identity", readFailure) {
		t.Fatal("failed observation accepted")
	}
	f.q.rejectObservation("resource_facts", syscall.EACCES)
	evidence, passed := f.q.proof(3, false)
	if passed || evidence.FailureStage != "sampler" || evidence.SamplerFailure != "member_identity" || evidence.SamplerErrorClass != "process_gone" || evidence.OwnedProcessesReaped || evidence.OwnedGroupsDrained {
		t.Fatalf("failed sampler accepted or first failure overwritten: %+v", evidence)
	}
	data, err := json.Marshal(evidence)
	if err != nil || len(data) > 1024 || strings.Contains(string(data), privatePath) || strings.Contains(string(data), cleanupTestNonce) || strings.Contains(string(data), "read ") {
		t.Fatalf("diagnostic included private kernel details: %v", err)
	}
}

func TestQualificationCleanupAllowsHistoricalPIDIdentityReuse(t *testing.T) {
	f := cleanupTestObserved(t)
	f.drain(t)
	replacement := cleanupTestStart(t, "wall")
	current, err := qualificationIdentity(replacement.cmd.Process.Pid)
	if err != nil || current.start <= 1 {
		t.Fatalf("replacement identity unavailable: %v", err)
	}
	// Simulate a saved historical start tick at an actually live reused PID.
	// The current /proc identity remains real; forcing kernel PID reuse is avoided.
	f.q.processes[qualificationProcess{pid: current.pid, start: current.start - 1}] = true
	if _, passed := f.q.proof(3, false); !passed {
		t.Fatal("different live start ticks incorrectly treated as the original process")
	}
	f.q.processes[current] = true
	if _, passed := f.q.proof(3, false); passed {
		t.Fatal("live original start ticks accepted")
	}
}

func TestQualificationCleanupAllowsRemovedOrReplacedGroup(t *testing.T) {
	f := cleanupTestObserved(t)
	f.drain(t)
	if err := os.RemoveAll(f.groups[0]); err != nil {
		t.Fatal(err)
	}
	if _, passed := f.q.proof(3, false); !passed {
		t.Fatal("removed original group rejected")
	}
	path := f.groups[1]
	// Preserve the empty old directory until the replacement is created, so its
	// inode cannot be immediately reused by the ordinary fixture filesystem.
	if err := os.Rename(path, path+"-drained-original"); err != nil {
		t.Fatal(err)
	}
	replacement := cleanupTestStart(t, "wall")
	identity := cleanupTestGroup(t, path, replacement.cmd.Process.Pid)
	if identity == f.q.groups[path] {
		t.Fatal("fixture did not replace the directory identity")
	}
	if _, passed := f.q.proof(3, false); !passed {
		t.Fatal("replacement directory attributed to the removed original group")
	}
}

func TestQualificationCleanupRejectsRenamedOriginalWithLateMember(t *testing.T) {
	f := cleanupTestObserved(t)
	f.drain(t)
	path := f.groups[0]
	original := path + "-renamed-original"
	if err := os.Rename(path, original); err != nil {
		t.Fatal(err)
	}
	cleanupTestGroup(t, path)
	late := cleanupTestStart(t, "fork")
	cleanupTestWrite(t, filepath.Join(original, "cgroup.procs"), strconv.Itoa(late.cmd.Process.Pid)+"\n")
	cleanupTestWrite(t, filepath.Join(original, "pids.current"), "1\n")
	evidence, passed := f.q.proof(3, false)
	if passed || !evidence.OwnedProcessesReaped || evidence.OwnedGroupsDrained {
		t.Fatalf("empty replacement hid a member in the pinned original group: %+v", evidence)
	}
	cleanupTestWrite(t, filepath.Join(original, "cgroup.procs"), "")
	cleanupTestWrite(t, filepath.Join(original, "pids.current"), "0\n")
	if _, passed := f.q.proof(3, false); !passed {
		t.Fatal("drained original group rejected after rename")
	}
}

func cleanupTestPin(t *testing.T, path string) *os.File {
	t.Helper()
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	directory := os.NewFile(uintptr(fd), "cleanup-unit-group")
	t.Cleanup(func() { _ = directory.Close() })
	return directory
}

func TestQualificationCleanupRejectsMalformedGroupFacts(t *testing.T) {
	f := cleanupTestObserved(t)
	f.drain(t)
	variants := []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"nonempty-roster", func(t *testing.T, path string) {
			cleanupTestWrite(t, filepath.Join(path, "cgroup.procs"), "not-a-pid\n")
		}},
		{"nonzero-count", func(t *testing.T, path string) { cleanupTestWrite(t, filepath.Join(path, "pids.current"), "1\n") }},
		{"malformed-count", func(t *testing.T, path string) { cleanupTestWrite(t, filepath.Join(path, "pids.current"), "0 junk\n") }},
		{"missing-count", func(t *testing.T, path string) {
			if err := os.Remove(filepath.Join(path, "pids.current")); err != nil {
				t.Fatal(err)
			}
		}},
		{"oversize-fact", func(t *testing.T, path string) {
			cleanupTestWrite(t, filepath.Join(path, "cgroup.procs"), strings.Repeat(" ", 4097))
		}},
		{"symlink-fact", func(t *testing.T, path string) {
			if err := os.Remove(filepath.Join(path, "cgroup.procs")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(path, "pids.current"), filepath.Join(path, "cgroup.procs")); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, variant := range variants {
		t.Run(variant.name, func(t *testing.T) {
			q := cleanupTestClone(f.q)
			delete(q.groups, f.groups[0])
			path := filepath.Join(t.TempDir(), "group")
			q.groups[path] = cleanupTestGroup(t, path)
			q.descriptors[path] = cleanupTestPin(t, path)
			variant.mutate(t, path)
			if _, passed := q.proof(3, false); passed {
				t.Fatal("malformed kernel group facts accepted")
			}
		})
	}
}

func TestQualificationCleanupObservationRejectsUnboundRoots(t *testing.T) {
	child := cleanupTestStart(t, "wall")
	path := filepath.Join(t.TempDir(), "group")
	cleanupTestGroup(t, path, child.cmd.Process.Pid)
	for _, variant := range []string{"stale-nonce", "forged-mode", "forged-compiler", "missing-root"} {
		t.Run(variant, func(t *testing.T) {
			q := newQualificationCleanup(cleanupTestNonce)
			t.Cleanup(q.close)
			args := cleanupTestCmdline(child.cmd.Args)
			if variant == "stale-nonce" {
				args = cleanupTestCmdline(cleanupTestArgs("wall", "stale-nonce"))
			} else if variant == "forged-mode" {
				args = cleanupTestCmdline(cleanupTestArgs("cpu", cleanupTestNonce))
			} else if variant == "forged-compiler" {
				args = cleanupTestCmdline(cleanupTestArgs("compiler", cleanupTestNonce))
			} else {
				cleanupTestWrite(t, filepath.Join(path, "cgroup.procs"), "")
			}
			owned := q.observe(path, child.cmd.Process.Pid, args)
			if owned || len(q.modes) != 0 || len(q.groups) != 0 || len(q.processes) != 0 || q.cpu || q.memory || q.pids || q.compiler {
				t.Fatal("unbound root supplied owned qualification evidence")
			}
		})
	}
}

func TestQualificationCleanupObservationFailureIsSticky(t *testing.T) {
	child := cleanupTestStart(t, "cpu")
	path := filepath.Join(t.TempDir(), "group")
	cleanupTestGroup(t, path, child.cmd.Process.Pid)
	for _, fact := range []string{"invalid\n", "1\n", "-1\n", strings.Repeat(" ", 4097)} {
		q := newQualificationCleanup(cleanupTestNonce)
		t.Cleanup(q.close)
		cleanupTestWrite(t, filepath.Join(path, "cgroup.procs"), fact)
		q.observe(path, child.cmd.Process.Pid, cleanupTestCmdline(child.cmd.Args))
		if !q.failed {
			t.Fatal("malformed member facts did not fail the sampler")
		}
		cleanupTestWrite(t, filepath.Join(path, "cgroup.procs"), strconv.Itoa(child.cmd.Process.Pid)+"\n")
		q.observe(path, child.cmd.Process.Pid, cleanupTestCmdline(child.cmd.Args))
		if !q.failed || len(q.modes) != 0 || len(q.groups) != 0 || len(q.processes) != 0 {
			t.Fatal("later valid observation repaired an invalid sampler")
		}
	}
}

func TestQualificationCleanupUnrelatedCapsCannotSupplyOwnedEvidence(t *testing.T) {
	q := newQualificationCleanup(cleanupTestNonce)
	t.Cleanup(q.close)
	own := cleanupTestStart(t, "cpu")
	path := filepath.Join(t.TempDir(), "own")
	cleanupTestGroup(t, path, own.cmd.Process.Pid)
	cleanupTestWrite(t, filepath.Join(path, "memory.max"), "1073741824\n")
	cleanupTestWrite(t, filepath.Join(path, "pids.max"), "64\n")
	cleanupTestWrite(t, filepath.Join(path, "cpu.stat"), "user_usec 1\nsystem_usec 0\n")
	if !q.observe(path, own.cmd.Process.Pid, cleanupTestCmdline(own.cmd.Args)) {
		t.Fatal("real bound root with insufficient limits did not supply a snapshot")
	}
	unrelated := cleanupTestStartNonce(t, "wall", "unrelated-qualification-nonce")
	unrelatedPath := filepath.Join(t.TempDir(), "unrelated")
	cleanupTestGroup(t, unrelatedPath, unrelated.cmd.Process.Pid)
	stale := cleanupTestCmdline(cleanupTestArgs("wall", "stale-nonce"))
	if q.observe(unrelatedPath, unrelated.cmd.Process.Pid, stale) {
		t.Fatal("stale unrelated root attributed to this qualification")
	}
	forged := cleanupTestCmdline(cleanupTestArgs("cpu", cleanupTestNonce))
	if q.observe(unrelatedPath, unrelated.cmd.Process.Pid, forged) {
		t.Fatal("forged live argv attributed to this qualification")
	}
	if q.cpu || q.memory || q.pids || len(q.groups) != 1 || len(q.modes) != 1 {
		t.Fatal("unrelated valid caps substituted for insufficient owned caps")
	}
	cleanupTestWrite(t, filepath.Join(path, "memory.max"), "536870912\n")
	cleanupTestWrite(t, filepath.Join(path, "pids.max"), "32\n")
	cleanupTestWrite(t, filepath.Join(path, "cpu.stat"), "usage_usec 1\n")
	if !q.observe(path, own.cmd.Process.Pid, cleanupTestCmdline(own.cmd.Args)) || !q.cpu || !q.memory || !q.pids {
		t.Fatal("owned stable caps did not supply resource evidence")
	}
}

func TestQualificationCleanupDuplicateRosterCannotInflateForkWitness(t *testing.T) {
	q := newQualificationCleanup(cleanupTestNonce)
	t.Cleanup(q.close)
	child := cleanupTestStart(t, "fork")
	path := filepath.Join(t.TempDir(), "group")
	cleanupTestGroup(t, path, child.cmd.Process.Pid)
	cleanupTestWrite(t, filepath.Join(path, "cgroup.procs"), strings.Repeat(strconv.Itoa(child.cmd.Process.Pid)+"\n", 100))
	if !q.observe(path, child.cmd.Process.Pid, cleanupTestCmdline(child.cmd.Args)) {
		t.Fatal("duplicate roster did not yield its one actual process identity")
	}
	if len(q.processes) != 1 || q.forkPeak != 1 {
		t.Fatal("duplicate tokens supplied distinct fork process witnesses")
	}
}

func TestQualificationCleanupRejectsMalformedResourceFacts(t *testing.T) {
	child := cleanupTestStart(t, "cpu")
	for _, file := range []string{"memory.max", "pids.max", "cpu.stat"} {
		t.Run(file, func(t *testing.T) {
			q := newQualificationCleanup(cleanupTestNonce)
			t.Cleanup(q.close)
			path := filepath.Join(t.TempDir(), "group")
			cleanupTestGroup(t, path, child.cmd.Process.Pid)
			if file == "cpu.stat" {
				if err := os.Remove(filepath.Join(path, file)); err != nil {
					t.Fatal(err)
				}
			} else {
				cleanupTestWrite(t, filepath.Join(path, file), "not-a-number\n")
			}
			if q.observe(path, child.cmd.Process.Pid, cleanupTestCmdline(child.cmd.Args)) || !q.failed || q.cpu || q.memory || q.pids || len(q.modes) != 0 {
				t.Fatal("malformed or unreadable owned caps supplied evidence")
			}
		})
	}
}

func TestQualificationCleanupDirectoryDescriptorsAreCloexecAndClosed(t *testing.T) {
	f := cleanupTestObserved(t)
	var descriptors []uintptr
	for _, directory := range f.q.descriptors {
		fd := directory.Fd()
		flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFD, 0)
		if errno != 0 || flags&syscall.FD_CLOEXEC == 0 {
			t.Fatalf("owned directory descriptor was inheritable: %v", errno)
		}
		descriptors = append(descriptors, fd)
	}
	f.q.close()
	for _, fd := range descriptors {
		var facts syscall.Stat_t
		if err := syscall.Fstat(int(fd), &facts); err != syscall.EBADF {
			t.Fatalf("qualification close left a directory descriptor live: %v", err)
		}
	}
}
