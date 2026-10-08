//go:build linux

package supervisor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
	"github.com/STAR-Ability/code-startrack-judge/internal/runtime/restclient"
)

//go:embed native/isolation-probe.cc
var isolationProbe []byte

type probeObservation struct {
	UID                       int    `json:"uid"`
	GID                       int    `json:"gid"`
	ExecutionUID              int    `json:"executionUID"`
	PeerFilesystem            bool   `json:"peerFilesystem"`
	Seccomp                   bool   `json:"seccomp"`
	CapsZero                  bool   `json:"capsZero"`
	NoNewPrivileges           bool   `json:"noNewPrivileges"`
	PrivateMounts             bool   `json:"privateMounts"`
	Readonly                  bool   `json:"readonly"`
	Filesystem                bool   `json:"filesystem"`
	Credentials               bool   `json:"credentials"`
	SiblingProc               bool   `json:"siblingProc"`
	Network                   bool   `json:"network"`
	Descriptors               bool   `json:"descriptors"`
	PIDNamespace              string `json:"pidNamespace"`
	NetNamespace              string `json:"netNamespace"`
	CapabilityBoundingBits    uint64 `json:"capabilityBoundingBits"`
	CapabilityEffectiveBits   uint64 `json:"capabilityEffectiveBits"`
	CapabilityPermittedBits   uint64 `json:"capabilityPermittedBits"`
	CapabilityInheritableBits uint64 `json:"capabilityInheritableBits"`
	CapabilityAmbientBits     uint64 `json:"capabilityAmbientBits"`
	Securebits                int    `json:"securebits"`
	SeccompFilters            int    `json:"seccompFilters"`
	DenialFailure             string `json:"denialFailure"`
	ReadonlyFailure           string `json:"readonlyFailure"`
	ReadonlyMountCount        int    `json:"readonlyMountCount"`
	ReadonlyWriteDeniedCount  int    `json:"readonlyWriteDeniedCount"`
	ReadonlyEROFSCount        int    `json:"readonlyEROFSCount"`
	ReadonlyEACCESCount       int    `json:"readonlyEACCESCount"`
	ReadonlyEPERMCount        int    `json:"readonlyEPERMCount"`
}

type qualificationResourceObservation struct {
	Fixture              string                     `json:"fixture"`
	Status               restclient.Status          `json:"status"`
	ExitStatus           int                        `json:"exitStatus"`
	CPUTimeNS            uint64                     `json:"cpuTimeNS"`
	WallTimeNS           uint64                     `json:"wallTimeNS"`
	MemoryBytes          uint64                     `json:"memoryBytes"`
	ProcessPeak          uint64                     `json:"processPeak"`
	OutputCollectedBytes int                        `json:"outputCollectedBytes"`
	FileErrorTypes       []restclient.FileErrorType `json:"fileErrorTypes"`
}

type cgroupObservation struct {
	CPU, Memory, PIDs, Compiler, Concurrent bool
	mu                                      sync.Mutex
	cleanup                                 *qualificationCleanup
}

func sampleCgroups(ctx context.Context, observation *cgroupObservation) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		paths, _ := filepath.Glob("/sys/fs/cgroup/manager/containers/*")
		inspectorGroups := map[string]bool{}
		inspectorModes := map[string]bool{}
		for _, path := range paths {
			procs, err := qualificationRead(filepath.Join(path, "cgroup.procs"))
			if err != nil || len(bytes.TrimSpace(procs)) == 0 {
				continue
			}
			observation.mu.Lock()
			for _, pid := range strings.Fields(string(procs)) {
				args, argsErr := qualificationRead("/proc/" + pid + "/cmdline")
				mode := observation.cleanup.mode(args)
				stable := false
				if argsErr == nil && mode != "" {
					id, parseErr := strconv.Atoi(pid)
					if parseErr != nil {
						observation.cleanup.rejectObservation("root_pid")
					} else {
						stable = observation.cleanup.observe(path, id, args)
					}
				}
				comm, _ := qualificationRead("/proc/" + pid + "/comm")
				name := strings.TrimSpace(string(comm))
				if name == "probe" {
					for _, inspection := range []string{"inspect-a", "inspect-b"} {
						if stable && mode == inspection {
							inspectorGroups[path] = true
							inspectorModes[inspection] = true
						}
					}
				}
			}
			observation.mu.Unlock()
		}
		observation.mu.Lock()
		observation.Concurrent = observation.Concurrent || len(inspectorGroups) >= 2 && inspectorModes["inspect-a"] && inspectorModes["inspect-b"]
		observation.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func qualificationCommand(args []string, stdin restclient.FileID, input map[string]restclient.FileID) restclient.Command {
	return restclient.Command{Args: args, Env: []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C", "LC_ALL=C", "HOME=/w", "TMPDIR=/w"}, Files: []restclient.File{{ID: stdin}, {Collector: "stdout", LimitBytes: 4096, CollectPipe: true}, {Collector: "stderr", LimitBytes: 4096, CollectPipe: true}}, CopyIn: input, CopyOutCached: []restclient.Output{{Name: "stdout"}, {Name: "stderr"}}, CPULimitNS: uint64(time.Second), ClockLimitNS: uint64(3 * time.Second), MemoryLimitBytes: 128 << 20, StackLimitBytes: 128 << 20, ProcessLimit: 16, CopyOutMaxBytes: 4 << 20, StrictMemoryLimit: true}
}

func qualify(ctx context.Context, s settings, runtimePID int, startup bool, publication *qualificationPublication) (result error) {
	managerPID, err := awaitManager(ctx, runtimePID)
	if err != nil {
		return err
	}
	client, err := restclient.New(restclient.Options{Token: s.runtimeToken})
	if err != nil {
		return fail("qualification_client")
	}
	session := client.NewSession()
	closed := false
	defer func() {
		if !closed {
			if session.Close() != nil {
				result = errors.Join(result, fail("qualification_cache_cleanup"))
			}
		}
	}()
	var stdin restclient.FileID
	for {
		stdin, err = session.Upload(ctx, []byte{})
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return fail("qualification_runtime")
		case <-time.After(100 * time.Millisecond):
		}
	}
	if err != nil {
		return fail("qualification_runtime")
	}
	source, err := session.Upload(ctx, isolationProbe)
	if err != nil {
		return fail("qualification_source")
	}
	for _, version := range []struct {
		args     []string
		expected string
	}{
		{[]string{"/usr/bin/g++", "--version"}, judgeruntime.CompilerVersion},
		{[]string{"/usr/local/bin/python3", "--version"}, "Python 3.11.15"},
	} {
		results, e := session.Run(ctx, restclient.Request{RequestID: "supervisor-qualification-version", Commands: []restclient.Command{qualificationCommand(version.args, stdin, nil)}})
		if e != nil || len(results) != 1 || results[0].Status != restclient.Accepted || results[0].ExitStatus != 0 || results[0].HasError || results[0].FileErrorCount != 0 {
			for _, r := range results {
				fmt.Fprintf(os.Stderr, "supervisor qualification_toolchain status=%s exit=%d error=%t files=%d types=%v\n", r.Status, r.ExitStatus, r.HasError, r.FileErrorCount, r.FileErrorTypes)
			}
			recordPrivateToolchainError(ctx, s, stdin, version.args)
			return fail("qualification_toolchain")
		}
		output, e := session.Download(ctx, results[0].CachedFiles["stdout"], 4096)
		first, _, _ := strings.Cut(string(output), "\n")
		if e != nil || first != version.expected {
			return fail("qualification_toolchain")
		}
	}
	for _, artifact := range []struct{ path, digest string }{{"/opt/startrack/libexec/default_validator", s.checkerDigest}, {"/opt/startrack/libexec/problemtools-bridge.py", s.bridgeDigest}} {
		file, e := os.ReadFile(artifact.path)
		sum := sha256.Sum256(file)
		if e != nil || hex.EncodeToString(sum[:]) != artifact.digest {
			return fail("qualification_artifact_identity")
		}
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return fail("qualification_nonce")
	}
	nonce := hex.EncodeToString(random[:])
	observation := &cgroupObservation{cleanup: newQualificationCleanup(nonce)}
	defer observation.cleanup.close()
	cleanupEvidence := qualificationCleanupObservation{}
	var forkPeak uint64
	sampleCtx, stopSampling := context.WithCancel(ctx)
	samplingDone := make(chan struct{})
	go func() { defer close(samplingDone); sampleCgroups(sampleCtx, observation) }()
	defer func() { stopSampling(); <-samplingDone }()
	sourceName := "probe-" + nonce + ".cpp"
	compile := qualificationCommand([]string{"/usr/bin/g++", "-std=c++17", "-O0", "/w/" + sourceName, "-o", "/w/probe"}, stdin, map[string]restclient.FileID{sourceName: source})
	compile.CPULimitNS, compile.ClockLimitNS, compile.MemoryLimitBytes, compile.StackLimitBytes, compile.ProcessLimit = uint64(10*time.Second), uint64(20*time.Second), 512<<20, 512<<20, 32
	compile.CopyOutCached = append(compile.CopyOutCached, restclient.Output{Name: "probe"})
	compiled, err := session.Run(ctx, restclient.Request{RequestID: "supervisor-qualification-compile", Commands: []restclient.Command{compile}})
	if err != nil || len(compiled) != 1 || compiled[0].Status != restclient.Accepted || compiled[0].ExitStatus != 0 || compiled[0].HasError || compiled[0].FileErrorCount != 0 {
		return fail("qualification_compiler")
	}
	binary := compiled[0].CachedFiles["probe"]
	if binary == "" {
		return fail("qualification_binary")
	}
	command := func(mode string) restclient.Command {
		return qualificationCommand([]string{"/w/probe", mode, nonce}, stdin, map[string]restclient.FileID{"probe": binary})
	}
	inspected, err := session.Run(ctx, restclient.Request{RequestID: "supervisor-qualification-concurrent", Commands: []restclient.Command{command("inspect-a"), command("inspect-b")}})
	if err != nil || len(inspected) != 2 {
		return fail("qualification_inspection")
	}
	seenUIDs := map[int]bool{}
	seenPIDNamespaces := map[string]bool{}
	seenNetNamespaces := map[string]bool{}
	checks := map[string]bool{}
	observations := []probeObservation{}
	resources := []qualificationResourceObservation{}
	observationsWritten := false
	// Even a failed fixed synthetic probe retains its bounded nonsecret facts.
	// The readiness measurement is written only after every invariant passes.
	defer func() {
		if len(observations) > 0 && !observationsWritten {
			if err := writeProbeObservations(s, managerPID, observations, resources, cleanupEvidence); err != nil {
				result = errors.Join(result, err)
			}
		}
	}()
	for _, result := range inspected {
		if result.Status != restclient.Accepted || result.ExitStatus != 0 || result.HasError || result.FileErrorCount != 0 {
			return fail("qualification_inspection")
		}
		data, e := session.Download(ctx, result.CachedFiles["stdout"], 4096)
		var measured probeObservation
		if e != nil || json.Unmarshal(data, &measured) != nil {
			return fail("qualification_observation")
		}
		observations = append(observations, measured)
		if measured.UID != 1000 || measured.GID != 1000 || measured.ExecutionUID < 1000 || seenUIDs[measured.ExecutionUID] {
			return fail("qualification_execution_identity")
		}
		seenUIDs[measured.ExecutionUID] = true
		if measured.PIDNamespace == "" || measured.NetNamespace == "" || seenPIDNamespaces[measured.PIDNamespace] || seenNetNamespaces[measured.NetNamespace] {
			return fail("qualification_namespaces")
		}
		seenPIDNamespaces[measured.PIDNamespace], seenNetNamespaces[measured.NetNamespace] = true, true
		if !measured.Seccomp || measured.SeccompFilters < 3 || !measured.CapsZero || measured.Securebits != 47 || measured.DenialFailure != "" || measured.CapabilityEffectiveBits != 0 || measured.CapabilityPermittedBits != 0 || measured.CapabilityInheritableBits != 0 || measured.CapabilityAmbientBits != 0 || !measured.NoNewPrivileges || !measured.PrivateMounts || !measured.Readonly || !measured.Filesystem || !measured.Credentials || !measured.SiblingProc || !measured.Network || !measured.Descriptors || !measured.PeerFilesystem {
			return fail("qualification_boundary")
		}
		if measured.ReadonlyFailure != "" || measured.ReadonlyMountCount != 9 || measured.ReadonlyWriteDeniedCount != 9 || measured.ReadonlyEROFSCount+measured.ReadonlyEACCESCount+measured.ReadonlyEPERMCount != 9 {
			return fail("qualification_readonly_observations")
		}
		for _, count := range []int{measured.ReadonlyEROFSCount, measured.ReadonlyEACCESCount, measured.ReadonlyEPERMCount} {
			if count < 0 || count > 9 {
				return fail("qualification_readonly_observations")
			}
		}
	}
	for _, key := range []string{"seccomp", "namespaces", "network_denied", "filesystem_isolation", "credential_isolation", "sibling_proc_denied", "unique_execution_uids"} {
		checks[key] = true
	}
	for _, fixture := range []struct {
		mode                        string
		status                      restclient.Status
		cpu, clock, memory, process uint64
	}{
		{"cpu", restclient.TimeLimit, uint64(100 * time.Millisecond), uint64(2 * time.Second), 128 << 20, 16},
		{"wall", restclient.TimeLimit, uint64(100 * time.Millisecond), uint64(200 * time.Millisecond), 128 << 20, 16},
		{"memory", restclient.MemoryLimit, uint64(time.Second), uint64(3 * time.Second), 32 << 20, 16},
		{"output", restclient.OutputLimit, uint64(time.Second), uint64(3 * time.Second), 128 << 20, 16},
		{"fork", restclient.Accepted, uint64(time.Second), uint64(3 * time.Second), 128 << 20, 8},
		{"dirty", restclient.Accepted, uint64(time.Second), uint64(3 * time.Second), 128 << 20, 16},
	} {
		c := command(fixture.mode)
		c.CPULimitNS, c.ClockLimitNS, c.MemoryLimitBytes, c.StackLimitBytes, c.ProcessLimit = fixture.cpu, fixture.clock, fixture.memory, fixture.memory, fixture.process
		results, e := session.Run(ctx, restclient.Request{RequestID: "supervisor-qualification-" + fixture.mode, Commands: []restclient.Command{c}})
		boundedOutput := false
		if e == nil && len(results) == 1 {
			r := results[0]
			resources = append(resources, qualificationResourceObservation{Fixture: fixture.mode, Status: r.Status, ExitStatus: r.ExitStatus, CPUTimeNS: r.CPUTimeNS, WallTimeNS: r.WallTimeNS, MemoryBytes: r.MemoryBytes, ProcessPeak: r.ProcessPeak, FileErrorTypes: r.FileErrorTypes})
			if fixture.mode == "output" && !r.HasError && r.FileErrorCount == 1 && len(r.FileErrorTypes) == 1 && r.FileErrorTypes[0] == restclient.CollectSizeExceeded && (r.Status == restclient.OutputLimit || r.Status == restclient.TimeLimit) {
				// The mature collector retains exactly limit+1 as its overflow
				// sentinel. A prior CPU limit may remain the low-level status.
				output, downloadErr := session.Download(ctx, r.CachedFiles["stdout"], 4097)
				resources[len(resources)-1].OutputCollectedBytes = len(output)
				boundedOutput = downloadErr == nil && len(output) == 4097 && r.WallTimeNS <= fixture.clock+uint64(time.Second)
			}
		}
		if e != nil || len(results) != 1 || fixture.mode == "output" && !boundedOutput || fixture.mode != "output" && (results[0].Status != fixture.status || results[0].HasError || results[0].FileErrorCount != 0) {
			for _, result := range results {
				fmt.Fprintf(os.Stderr, "supervisor qualification_fixture mode=%s status=%s exit=%d memory=%d cpu=%d wall=%d error=%t fileErrors=%d fileErrorTypes=%v\n", fixture.mode, result.Status, result.ExitStatus, result.MemoryBytes, result.CPUTimeNS, result.WallTimeNS, result.HasError, result.FileErrorCount, result.FileErrorTypes)
			}
			return fail("qualification_" + fixture.mode)
		}
		r := results[0]
		switch fixture.mode {
		case "cpu":
			checks["cpu_limits"] = r.CPUTimeNS >= fixture.cpu && r.WallTimeNS < fixture.clock
		case "wall":
			checks["wall_limits"] = r.CPUTimeNS < fixture.cpu && r.WallTimeNS >= fixture.clock
		case "memory":
			checks["memory_limits"] = r.MemoryBytes >= fixture.memory
		case "output":
			checks["output_limits"] = true
		case "fork":
			checks["process_limits"] = r.ProcessPeak > 1 && r.ProcessPeak <= 8
			forkPeak = r.ProcessPeak
		}
	}
	cleaned, e := session.Run(ctx, restclient.Request{RequestID: "supervisor-qualification-cleanup", Commands: []restclient.Command{command("inspect")}})
	if e != nil || len(cleaned) != 1 || cleaned[0].Status != restclient.Accepted || cleaned[0].ExitStatus != 0 {
		cleanupEvidence.FailureStage = "inspect_execution"
		return fail("qualification_cleanup")
	}
	data, e := session.Download(ctx, cleaned[0].CachedFiles["stdout"], 4096)
	var clean probeObservation
	if e != nil || json.Unmarshal(data, &clean) != nil || !clean.Filesystem {
		cleanupEvidence.FailureStage = "inspect_observation"
		return fail("qualification_cleanup")
	}
	if err = session.Close(); err != nil {
		return fail("qualification_cache_cleanup")
	}
	closed = true
	_, err = client.Download(ctx, binary, 4<<20)
	var missing *restclient.Error
	checks["cache_cleanup"] = errors.As(err, &missing) && missing.Kind == restclient.MissingFileError && missing.HTTPStatus == 404
	stopSampling()
	<-samplingDone
	observation.mu.Lock()
	checks["cgroup_cpu"], checks["cgroup_memory"], checks["cgroup_pids"], checks["compiler_isolation"] = observation.cleanup.cpu, observation.cleanup.memory, observation.cleanup.pids, observation.cleanup.compiler
	checks["namespaces"] = checks["namespaces"] && observation.Concurrent
	observation.mu.Unlock()
	cleanupEvidence, checks["cleanup"] = observation.cleanup.proof(forkPeak, startup)
	for _, key := range judgeruntime.RequiredIsolationChecks {
		if !checks[key] {
			return fail("qualification_" + key)
		}
	}
	if err := writeProbeObservations(s, managerPID, observations, resources, cleanupEvidence); err != nil {
		return err
	}
	observationsWritten = true
	if ctx.Err() != nil {
		return fail("qualification_deadline")
	}
	return writeMeasurement(s, managerPID, checks, publication)
}

// This fixed synthetic re-probe preserves bounded raw infrastructure evidence
// only in the existing root-only startup facility. It never executes caller bytes.
func recordPrivateToolchainError(ctx context.Context, s settings, stdin restclient.FileID, args []string) {
	command := map[string]any{"args": args, "env": []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C", "LC_ALL=C", "HOME=/w", "TMPDIR=/w"}, "files": []any{map[string]any{"fileId": stdin}, map[string]any{"name": "stdout", "max": 4096, "pipe": true}, map[string]any{"name": "stderr", "max": 4096, "pipe": true}}, "cpuLimit": 1000000000, "clockLimit": 3000000000, "memoryLimit": 134217728, "stackLimit": 134217728, "procLimit": 16, "copyOutCached": []string{"stdout", "stderr"}, "copyOutMax": 4194304, "strictMemoryLimit": true}
	body, e := json.Marshal(map[string]any{"cmd": []any{command}})
	if e != nil {
		return
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, "http://127.0.0.1:5050/run", bytes.NewReader(body))
	if e != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+s.runtimeToken)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "127.0.0.1:5050" {
			return nil, fail("qualification_diagnostic_endpoint")
		}
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, address)
	}}, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	response, e := client.Do(req)
	if e != nil {
		return
	}
	defer response.Body.Close()
	data, e := io.ReadAll(io.LimitReader(response.Body, 16<<10))
	if e != nil {
		return
	}
	f, e := openPrivateLog(filepath.Join(filepath.Dir(QualificationPath), "qualification-private.log"), 0)
	if e != nil {
		return
	}
	defer f.Close()
	f.Write(append(data, '\n'))
}

func compilerBoundary(status string) bool {
	fields := map[string][]string{}
	for _, line := range strings.Split(status, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok {
			fields[key] = strings.Fields(value)
		}
	}
	uid := fields["Uid"]
	if len(uid) != 4 {
		return false
	}
	for _, value := range uid {
		n, e := strconv.Atoi(value)
		if e != nil || n < 100000 || n >= 165536 {
			return false
		}
	}
	for _, key := range []string{"CapEff", "CapPrm", "CapInh", "CapAmb"} {
		if strings.Join(fields[key], "") != "0000000000000000" {
			return false
		}
	}
	filters, err := strconv.Atoi(strings.Join(fields["Seccomp_filters"], ""))
	return err == nil && filters >= 3 && len(fields["NSpid"]) >= 3 && strings.Join(fields["NoNewPrivs"], "") == "1" && strings.Join(fields["Seccomp"], "") == "2"
}

func awaitManager(ctx context.Context, helperPID int) (int, error) {
	path := "/proc/" + strconv.Itoa(helperPID) + "/task/" + strconv.Itoa(helperPID) + "/children"
	for {
		children, err := os.ReadFile(path)
		if err != nil {
			return 0, fail("qualification_manager")
		}
		pids := strings.Fields(string(children))
		if len(pids) == 1 {
			pid, e := strconv.Atoi(pids[0])
			comm, ce := os.ReadFile("/proc/" + pids[0] + "/comm")
			if e == nil && ce == nil && strings.TrimSpace(string(comm)) == "go-judge" {
				return pid, nil
			}
		} else if len(pids) > 1 {
			return 0, fail("qualification_manager")
		}
		select {
		case <-ctx.Done():
			return 0, fail("qualification_manager")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func executionCgroupsEmpty() bool {
	paths, err := filepath.Glob("/sys/fs/cgroup/manager/containers/*/cgroup.procs")
	if err != nil {
		return false
	}
	for _, path := range paths {
		data, e := os.ReadFile(path)
		if e != nil || len(bytes.TrimSpace(data)) != 0 {
			return false
		}
	}
	return true
}

func writeMeasurement(s settings, pid int, checks map[string]bool, publication *qualificationPublication) error {
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	end := bytes.LastIndexByte(stat, ')')
	if err != nil || end < 0 {
		return fail("measurement_process")
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) < 20 || fields[0] == "Z" {
		return fail("measurement_process")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return fail("measurement_boot")
	}
	profile, err := measuredProfile(pid)
	if err != nil {
		return err
	}
	identity := judgeruntime.FrozenIdentity{LanguageConfigVersion: judgeruntime.CompilerConfigVersion, CompilerVersion: judgeruntime.CompilerVersion, ToolchainDigest: judgeruntime.CPP17ToolchainDigest, WorkerImageDigest: s.imageDigest, SandboxVersion: judgeruntime.SandboxVersion, CheckerDigest: s.checkerDigest}
	if identity.Validate() != nil {
		return fail("measurement_identity")
	}
	m := judgeruntime.RuntimeMeasurement{Version: 1, Identity: identity, PID: pid, StartTicks: fields[19], BootID: strings.TrimSpace(string(boot)), MeasuredAt: time.Now().UTC(), SecurityProfileSHA256: profile, Checks: checks}
	data, err := json.Marshal(m)
	if err != nil {
		return fail("measurement_encoding")
	}
	temporary := QualificationPath + ".tmp"
	f, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0644)
	if err != nil {
		return fail("measurement_write")
	}
	defer os.Remove(temporary)
	_, err = f.Write(append(data, '\n'))
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return fail("measurement_write")
	}
	return publication.publish(temporary)
}

func measuredProfile(pid int) (string, error) {
	var profile bytes.Buffer
	managerPrefix := "/proc/" + strconv.Itoa(pid)
	managerStatus, err := os.ReadFile(managerPrefix + "/status")
	if err != nil || !strings.Contains(string(managerStatus), "Uid:\t30000\t30000\t30000\t30000\n") || !strings.Contains(string(managerStatus), "Gid:\t30000\t30000\t30000\t30000\n") || !strings.Contains(string(managerStatus), "CapEff:\t000001ffffffffff\n") || !strings.Contains(string(managerStatus), "CapBnd:\t000001ffffffffff\n") || !strings.Contains(string(managerStatus), "Seccomp:\t2\n") || !strings.Contains(string(managerStatus), "NoNewPrivs:\t1\n") {
		return "", fail("measurement_manager_profile")
	}
	for _, line := range strings.Split(string(managerStatus), "\n") {
		if strings.HasPrefix(line, "Uid:") || strings.HasPrefix(line, "Gid:") || strings.HasPrefix(line, "CapEff:") || strings.HasPrefix(line, "CapBnd:") || strings.HasPrefix(line, "Seccomp:") || strings.HasPrefix(line, "NoNewPrivs:") {
			profile.WriteString(line)
			profile.WriteByte('\n')
		}
	}
	for _, path := range []string{"/proc/self/status", "/proc/self/attr/current", managerPrefix + "/uid_map", managerPrefix + "/gid_map", "/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/pids.max", "/sys/fs/cgroup/cpu.max", "/opt/startrack/mount.yaml", "/opt/startrack/startrack-v02.seccomp.json", "/opt/startrack/startrack-v02.apparmor", "/opt/startrack/startrack-workload-seccomp.yaml", "/opt/startrack/workload-security-profile.lock.json"} {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fail("measurement_profile")
		}
		if path == "/proc/self/status" {
			if !strings.Contains(string(data), "CapBnd:\t00000000812000e9\n") || !strings.Contains(string(data), "Seccomp:\t2\n") || !strings.Contains(string(data), "NoNewPrivs:\t1\n") {
				return "", fail("measurement_profile")
			}
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "CapBnd:") || strings.HasPrefix(line, "Seccomp:") || strings.HasPrefix(line, "NoNewPrivs:") {
					profile.WriteString(line)
					profile.WriteByte('\n')
				}
			}
		} else {
			if (path == managerPrefix+"/uid_map" || path == managerPrefix+"/gid_map") && strings.Join(strings.Fields(string(data)), " ") != "0 30000 1 1 100000 65536" {
				return "", fail("measurement_manager_mapping")
			}
			expected := map[string]string{"/proc/self/attr/current": "startrack-v02 (enforce)", "/sys/fs/cgroup/memory.max": "4294967296", "/sys/fs/cgroup/pids.max": "256", "/sys/fs/cgroup/cpu.max": "200000 100000"}
			if value, ok := expected[path]; ok && strings.TrimSpace(string(data)) != value {
				return "", fail("measurement_profile")
			}
			profile.Write(data)
			profile.WriteByte('\n')
		}
	}
	sum := sha256.Sum256(profile.Bytes())
	return hex.EncodeToString(sum[:]), nil
}
