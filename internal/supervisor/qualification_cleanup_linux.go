//go:build linux

package supervisor

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
)

const maxQualificationProcesses = 1024

var qualificationProbeModes = []string{"inspect-a", "inspect-b", "cpu", "wall", "memory", "output", "fork", "dirty", "inspect"}

type qualificationProcess struct {
	pid   int
	start uint64
}

type qualificationGroup struct{ device, inode uint64 }

type qualificationCleanupObservation struct {
	StartupGlobalIdle      bool `json:"startupGlobalIdle"`
	OwnedModesObserved     int  `json:"ownedModesObserved"`
	OwnedGroupsObserved    int  `json:"ownedGroupsObserved"`
	OwnedProcessesObserved int  `json:"ownedProcessesObserved"`
	ForkWitnessProcesses   int  `json:"forkWitnessProcesses"`
	OwnedProcessesReaped   bool `json:"ownedProcessesReaped"`
	OwnedGroupsDrained     bool `json:"ownedGroupsDrained"`
}

// A fresh supervisor-generated nonce binds observations to this fixed probe.
// No nonce, path, PID roster, or process bytes enter the structural evidence.
type qualificationCleanup struct {
	nonce                       string
	processes                   map[qualificationProcess]bool
	groups                      map[string]qualificationGroup
	descriptors                 map[string]*os.File
	cpu, memory, pids, compiler bool
	modes                       map[string]bool
	forkPeak                    int
	failed                      bool
}

func newQualificationCleanup(nonce string) *qualificationCleanup {
	return &qualificationCleanup{nonce: nonce, processes: map[qualificationProcess]bool{}, groups: map[string]qualificationGroup{}, descriptors: map[string]*os.File{}, modes: map[string]bool{}}
}

func (q *qualificationCleanup) mode(args []byte) string {
	for _, mode := range qualificationProbeModes {
		if string(args) == "/w/probe\x00"+mode+"\x00"+q.nonce+"\x00" {
			return mode
		}
	}
	if string(args) == "/usr/bin/g++\x00-std=c++17\x00-O0\x00/w/probe-"+q.nonce+".cpp\x00-o\x00/w/probe\x00" {
		return "compiler"
	}
	return ""
}

func qualificationRead(path string) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "qualification-kernel-fact")
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(data) > 4096 {
		return nil, fail("qualification_cleanup_fact")
	}
	return data, nil
}

func qualificationIdentity(pid int) (qualificationProcess, error) {
	data, err := qualificationRead("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return qualificationProcess{}, err
	}
	end := bytes.LastIndexByte(data, ')')
	fields := strings.Fields(string(data[end+1:]))
	before, _, ok := strings.Cut(string(data), " ")
	actual, parseErr := strconv.Atoi(before)
	if end < 0 || !ok || parseErr != nil || actual != pid || pid <= 1 || len(fields) < 20 {
		return qualificationProcess{}, fail("qualification_cleanup_fact")
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 {
		return qualificationProcess{}, fail("qualification_cleanup_fact")
	}
	// Zombies still have an identity and must be reaped before cleanup passes.
	return qualificationProcess{pid, start}, nil
}

func qualificationGroupIdentity(path string) (qualificationGroup, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return qualificationGroup{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return qualificationGroup{}, fail("qualification_cleanup_fact")
	}
	return qualificationGroup{uint64(stat.Dev), stat.Ino}, nil
}

// Observe only a nonce-bound root, and capture every process in its fresh
// execution cgroup. Recheck the root and directory identities before committing
// a snapshot; legitimate exits/rmdir races cannot assign unrelated membership.
func (q *qualificationCleanup) observe(path string, pid int, args []byte) bool {
	mode := q.mode(args)
	if mode == "" || q.failed {
		return false
	}
	root, err := qualificationIdentity(pid)
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	group, groupErr := qualificationGroupIdentity(path)
	if errors.Is(groupErr, os.ErrNotExist) {
		return false
	}
	if err != nil || groupErr != nil {
		q.failed = true
		return false
	}
	fd, openErr := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if errors.Is(openErr, os.ErrNotExist) {
		return false
	}
	if openErr != nil {
		q.failed = true
		return false
	}
	directory := os.NewFile(uintptr(fd), "qualification-owned-group")
	defer func() {
		if q.descriptors[path] != directory {
			directory.Close()
		}
	}()
	pinned, pinnedErr := directory.Stat()
	pinnedStat, pinnedOK := pinnedSys(pinned)
	if pinnedErr != nil || !pinnedOK || (qualificationGroup{uint64(pinnedStat.Dev), pinnedStat.Ino}) != group {
		q.failed = true
		return false
	}
	data, err := qualificationReadAt(directory, "cgroup.procs")
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	members := map[qualificationProcess]bool{}
	for _, value := range strings.Fields(string(data)) {
		member, parseErr := strconv.Atoi(value)
		if parseErr != nil || member <= 1 || len(members) >= 256 {
			q.failed = true
			return false
		}
		identity, readErr := qualificationIdentity(member)
		if errors.Is(readErr, os.ErrNotExist) {
			continue
		}
		if readErr != nil {
			q.failed = true
			return false
		}
		members[identity] = true
	}
	memory, memoryErr := qualificationReadAt(directory, "memory.max")
	pids, pidsErr := qualificationReadAt(directory, "pids.max")
	cpu, cpuErr := qualificationReadAt(directory, "cpu.stat")
	m, memoryParseErr := strconv.ParseUint(strings.TrimSpace(string(memory)), 10, 64)
	p, pidsParseErr := strconv.ParseUint(strings.TrimSpace(string(pids)), 10, 64)
	var compilerStatus []byte
	var compilerErr error
	if mode == "compiler" {
		compilerStatus, compilerErr = qualificationRead("/proc/" + strconv.Itoa(pid) + "/status")
	}
	after, afterErr := qualificationIdentity(pid)
	groupAfter, groupAfterErr := qualificationGroupIdentity(path)
	argsAfter, argsErr := qualificationRead("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if errors.Is(afterErr, os.ErrNotExist) || errors.Is(groupAfterErr, os.ErrNotExist) || errors.Is(argsErr, os.ErrNotExist) {
		return false
	}
	if err != nil || afterErr != nil || groupAfterErr != nil || argsErr != nil {
		q.failed = true
		return false
	}
	if after != root || groupAfter != group || !bytes.Equal(argsAfter, args) || !members[root] {
		return false
	}
	// A normal teardown can remove interfaces during sampling. Only a stable
	// still-owned snapshot may turn read/parse errors into a sticky failure.
	if memoryErr != nil || pidsErr != nil || cpuErr != nil || memoryParseErr != nil || pidsParseErr != nil || compilerErr != nil {
		q.failed = true
		return false
	}
	if len(q.groups) >= 32 && q.groups[path] != group || len(q.processes)+len(members) > maxQualificationProcesses {
		q.failed = true
		return false
	}
	if previous, exists := q.groups[path]; exists && previous != group {
		q.failed = true
		return false
	}
	if q.descriptors[path] == nil {
		q.descriptors[path] = directory
	}
	q.cpu = q.cpu || strings.Contains(string(cpu), "usage_usec")
	q.memory = q.memory || (m > 0 && m <= 512<<20)
	q.pids = q.pids || (p > 0 && p <= 32)
	q.compiler = q.compiler || mode == "compiler" && compilerBoundary(string(compilerStatus))
	q.groups[path], q.modes[mode] = group, true
	for identity := range members {
		q.processes[identity] = true
	}
	if mode == "fork" && len(members) > q.forkPeak {
		q.forkPeak = len(members)
	}
	return true
}

func (q *qualificationCleanup) proof(forkPeak uint64, startup bool) (qualificationCleanupObservation, bool) {
	return q.proofWithIdle(forkPeak, startup, executionCgroupsEmpty)
}

// The production caller always supplies the fixed kernel idle check. This
// narrow seam permits a regression that proves refresh never consults global
// activity and startup rejects it before the admission gate can succeed.
func (q *qualificationCleanup) proofWithIdle(forkPeak uint64, startup bool, globalIdle func() bool) (qualificationCleanupObservation, bool) {
	ev := qualificationCleanupObservation{OwnedModesObserved: len(q.modes), OwnedGroupsObserved: len(q.groups), OwnedProcessesObserved: len(q.processes), ForkWitnessProcesses: q.forkPeak}
	if q.failed || len(q.groups) < 10 || len(q.processes) < 10 || forkPeak <= 1 || forkPeak > 8 || uint64(q.forkPeak) < forkPeak || !q.modes["compiler"] {
		return ev, false
	}
	for _, mode := range qualificationProbeModes {
		if !q.modes[mode] {
			return ev, false
		}
	}
	for identity := range q.processes {
		current, err := qualificationIdentity(identity.pid)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || current == identity {
			return ev, false
		}
	}
	ev.OwnedProcessesReaped = true
	for path, group := range q.groups {
		directory := q.descriptors[path]
		if directory == nil {
			return ev, false
		}
		facts, statErr := directory.Stat()
		pinned, ok := pinnedSys(facts)
		if statErr != nil || !ok || (qualificationGroup{uint64(pinned.Dev), pinned.Ino}) != group {
			return ev, false
		}
		members, membersErr := qualificationReadAt(directory, "cgroup.procs")
		pids, pidsErr := qualificationReadAt(directory, "pids.current")
		// The inode-bound directory survives rename. Only kernel removal can make
		// both original cgroup interfaces disappear; other read failures reject.
		removed := func(err error) bool { return errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ENODEV) }
		if removed(membersErr) && removed(pidsErr) {
			continue
		}
		if membersErr != nil || pidsErr != nil || len(bytes.TrimSpace(members)) != 0 || strings.TrimSpace(string(pids)) != "0" {
			return ev, false
		}
		after, afterErr := directory.Stat()
		afterStat, afterOK := pinnedSys(after)
		if afterErr != nil || !afterOK || (qualificationGroup{uint64(afterStat.Dev), afterStat.Ino}) != group {
			return ev, false
		}
	}
	ev.OwnedGroupsDrained = true
	if startup {
		if globalIdle == nil || !globalIdle() {
			return ev, false
		}
		ev.StartupGlobalIdle = true
	}
	return ev, true
}

func pinnedSys(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return st, ok
}
func qualificationReadAt(directory *os.File, name string) ([]byte, error) {
	fd, err := syscall.Openat(int(directory.Fd()), name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "qualification-owned-fact")
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(data) > 4096 {
		return nil, fail("qualification_cleanup_fact")
	}
	return data, nil
}
func (q *qualificationCleanup) close() {
	for _, directory := range q.descriptors {
		directory.Close()
	}
}
