//go:build linux

package supervisor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const boundaryTimeout = 8 * time.Second

var boundaryEnvironment = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C", "LC_ALL=C", "HOME=/nonexistent", "TZ=UTC"}

// VerifyServiceProcessBoundary checks the final service processes, whose PIDs
// must come from the supervisor's owned exec.Cmd handles. It grants no ptrace
// capability and does not read their environments, descriptor contents, or
// memory. A failed check prevents qualification; it never repairs isolation.
func VerifyServiceProcessBoundary(ctx context.Context, apiPID, judgerPID int) error {
	if os.Geteuid() != 0 {
		return fail("process_boundary_configuration")
	}
	if err := os.Remove(ProcessBoundaryPath); err != nil && !os.IsNotExist(err) {
		return fail("process_boundary_report")
	}
	verified := false
	defer func() {
		if !verified {
			os.Remove(ProcessBoundaryPath)
		}
	}()
	if ctx == nil || runtime.GOARCH != "amd64" || apiPID <= 1 || judgerPID <= 1 || apiPID == judgerPID {
		return fail("process_boundary_configuration")
	}
	executable, err := os.Executable()
	if err != nil || executable != processBoundaryBinary {
		return fail("process_boundary_executable")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*boundaryTimeout)
	defer cancel()
	observations := make([]processBoundaryObservation, 0, 2)
	for _, target := range []struct {
		role string
		pid  int
	}{{"api", apiPID}, {"judger", judgerPID}} {
		if ctx.Err() != nil {
			return fail("process_boundary_timeout")
		}
		role, _ := boundaryRole(target.role)
		start, err := inspectBoundaryProcess(target.pid, role.uid, role.binary+"\x00", 0, true, role.fds)
		if err != nil {
			return err
		}
		request := processBoundaryRequest{Version: 1, Kind: "probe", Role: target.role, PID: target.pid, StartTicks: start}
		body, err := json.Marshal(request)
		if err != nil {
			return fail("process_boundary_protocol")
		}
		probeCtx, stop := context.WithTimeout(ctx, boundaryTimeout)
		cmd := boundaryCommand(probeCtx, body)
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: role.uid, Gid: role.uid, Groups: []uint32{}}
		output := &boundaryOutput{}
		cmd.Stdout = output
		err = cmd.Run()
		stop()
		if err != nil || output.overflow {
			return fail("process_boundary_peer")
		}
		var result processBoundaryResult
		if decodeBoundaryMessage(output.body, &result) != nil || result.Version != 1 || result.Result != "denied" || !validControlOutcome(result.ControlMem) || !validControlOutcome(result.ControlVMRead) || !validControlOutcome(result.ControlPtrace) {
			return fail("process_boundary_result")
		}
		// Root establishes descriptor existence independently of the peer's
		// denied directory traversal. ENOENT can never masquerade as denial.
		if _, err := inspectBoundaryProcess(target.pid, role.uid, role.binary+"\x00", start, true, role.fds); err != nil {
			return err
		}
		observations = append(observations, processBoundaryObservation{
			Role: target.role, UID: role.uid, PID: target.pid, StartTicks: start,
			ControlMem: result.ControlMem, ControlVMRead: result.ControlVMRead, ControlPtrace: result.ControlPtrace, Denied: true,
		})
	}
	if ctx.Err() != nil {
		return fail("process_boundary_timeout")
	}
	for _, observation := range observations {
		role, _ := boundaryRole(observation.Role)
		if _, err := inspectBoundaryProcess(observation.PID, role.uid, role.binary+"\x00", observation.StartTicks, true, role.fds); err != nil {
			return err
		}
	}
	bootFile, err := os.Open("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return fail("process_boundary_report")
	}
	boot, err := io.ReadAll(io.LimitReader(bootFile, 65))
	bootFile.Close()
	if err != nil || len(boot) > 64 {
		return fail("process_boundary_report")
	}
	body, err := encodeBoundaryReport(processBoundaryReport{
		Version: 1, ImageDigest: os.Getenv("JUDGE_WORKER_IMAGE_DIGEST"), BootID: strings.TrimSpace(string(boot)),
		MeasuredAt: time.Now().UTC(), Observations: observations,
	})
	if err != nil {
		return err
	}
	if err := writeStructuralReport(ProcessBoundaryPath, body); err != nil {
		return err
	}
	info, err := os.Lstat(ProcessBoundaryPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0644 {
		return fail("process_boundary_report")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || ctx.Err() != nil {
		return fail("process_boundary_report")
	}
	verified = true
	return nil
}

type boundaryOutput struct {
	body     []byte
	overflow bool
}

func (w *boundaryOutput) Write(body []byte) (int, error) {
	n := len(body)
	if len(w.body)+n > processBoundaryLimit {
		w.overflow = true
		body = body[:processBoundaryLimit-len(w.body)]
	}
	w.body = append(w.body, body...)
	return n, nil
}

func boundaryCommand(ctx context.Context, input []byte) *exec.Cmd {
	cmd := exec.CommandContext(ctx, processBoundaryBinary, processBoundaryFlag)
	cmd.Env, cmd.Dir = append([]string(nil), boundaryEnvironment...), "/"
	cmd.Stdin, cmd.Stderr = bytes.NewReader(input), io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.WaitDelay = time.Second
	return cmd
}

// ProcessBoundaryPeer is reachable only through the fixed private flag. The
// control branch uses this same executable, environment, credentials, and
// inherited AppArmor/seccomp profile, changing only its own dumpability.
func ProcessBoundaryPeer() error {
	if runtime.GOARCH != "amd64" || len(os.Args) != 2 || os.Args[0] != processBoundaryBinary || os.Args[1] != processBoundaryFlag || (os.Geteuid() != APIUID && os.Geteuid() != JudgerUID) {
		return fail("process_boundary_configuration")
	}
	uid := uint32(os.Geteuid())
	groups, err := syscall.Getgroups()
	if err != nil || len(groups) != 0 {
		return fail("process_boundary_credentials")
	}
	status, err := readBoundaryProc(os.Getpid(), "status", 16384)
	if err != nil || boundaryCredentials(status, uid) != nil {
		return fail("process_boundary_credentials")
	}
	ctx, cancel := context.WithTimeout(context.Background(), boundaryTimeout)
	defer cancel()
	stopInput := context.AfterFunc(ctx, func() { os.Stdin.Close() })
	defer stopInput()
	body, err := io.ReadAll(io.LimitReader(os.Stdin, processBoundaryLimit+1))
	var request processBoundaryRequest
	if err != nil || decodeBoundaryMessage(body, &request) != nil || !request.valid() {
		return fail("process_boundary_protocol")
	}
	if request.Kind == "control" {
		return runBoundaryControl(ctx, uid)
	}
	role, _ := boundaryRole(request.Role)
	if role.uid != uid || request.PID == os.Getpid() {
		return fail("process_boundary_identity")
	}
	control, err := verifyBoundaryControl(ctx, uid)
	if err != nil {
		return err
	}
	if _, err := inspectBoundaryProcess(request.PID, uid, role.binary+"\x00", request.StartTicks, false, nil); err != nil {
		return err
	}
	for _, name := range []string{"environ", "mem"} {
		if !boundaryPermissionDenied(openBoundaryProc(request.PID, name)) {
			return fail("process_boundary_denial")
		}
	}
	for _, fd := range role.fds {
		name := "fd/" + strconv.Itoa(fd)
		if _, err := os.Readlink(boundaryProcPath(request.PID, name)); !boundaryPermissionDenied(err) {
			return fail("process_boundary_denial")
		}
		if !boundaryPermissionDenied(openBoundaryProc(request.PID, name)) {
			return fail("process_boundary_denial")
		}
	}
	// Bit 63 is outside Linux amd64's userspace, including five-level paging.
	// The address cannot expose target data. Permission must fail before page
	// lookup; EFAULT is an isolation failure, not a pass.
	if _, errno := boundaryVMRead(request.PID, uint64(1)<<63); !boundaryPermissionDenied(errno) {
		return fail("process_boundary_denial")
	}
	runtime.LockOSThread()
	_, _, errno := syscall.Syscall6(syscall.SYS_PTRACE, 0x4206, uintptr(request.PID), 0, 0, 0, 0) // PTRACE_SEIZE: no stop or target data read.
	if errno == 0 {
		// No EXITKILL option is used. On this failure the peer exits and Linux
		// detaches the tracee; supervisor waits for that exit before returning.
		syscall.PtraceDetach(request.PID)
	}
	runtime.UnlockOSThread()
	if !boundaryPermissionDenied(errno) {
		return fail("process_boundary_denial")
	}
	if _, err := inspectBoundaryProcess(request.PID, uid, role.binary+"\x00", request.StartTicks, false, nil); err != nil {
		return err
	}
	control.Version, control.Result = 1, "denied"
	if ctx.Err() != nil || json.NewEncoder(os.Stdout).Encode(control) != nil {
		return fail("process_boundary_result")
	}
	return nil
}

func boundaryProcPath(pid int, name string) string { return "/proc/" + strconv.Itoa(pid) + "/" + name }

func readBoundaryProc(pid int, name string, limit int64) ([]byte, error) {
	f, err := os.Open(boundaryProcPath(pid, name))
	if err != nil {
		return nil, fail("process_boundary_identity")
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(body)) > limit {
		return nil, fail("process_boundary_identity")
	}
	return body, nil
}

func inspectBoundaryProcess(pid int, uid uint32, cmdline string, expected uint64, checkDescriptors bool, fds []int) (uint64, error) {
	stat, err := readBoundaryProc(pid, "stat", 4096)
	if err != nil {
		return 0, err
	}
	start, err := boundaryStat(stat, pid)
	if err != nil || (expected != 0 && start != expected) {
		return 0, fail("process_boundary_identity")
	}
	status, err := readBoundaryProc(pid, "status", 16384)
	if err != nil || boundaryCredentials(status, uid) != nil {
		return 0, fail("process_boundary_identity")
	}
	args, err := readBoundaryProc(pid, "cmdline", 512)
	if err != nil || string(args) != cmdline {
		return 0, fail("process_boundary_identity")
	}
	// Nondumpability can deny /proc/PID/exe even to the supervisor, which
	// intentionally has no CAP_SYS_PTRACE. Exact cmdline plus owned child PID,
	// credentials and unchanged start ticks are mandatory in that case.
	executable, err := os.Readlink(boundaryProcPath(pid, "exe"))
	if err == nil {
		binary, _, _ := bytes.Cut([]byte(cmdline), []byte{0})
		if executable != string(binary) {
			return 0, fail("process_boundary_identity")
		}
	} else if !boundaryPermissionDenied(err) {
		return 0, fail("process_boundary_identity")
	}
	if checkDescriptors {
		for _, fd := range fds {
			info, err := os.Lstat(boundaryProcPath(pid, "fd/"+strconv.Itoa(fd)))
			if err != nil || info.Mode()&os.ModeSymlink == 0 {
				return 0, fail("process_boundary_descriptor")
			}
		}
	}
	stat, err = readBoundaryProc(pid, "stat", 4096)
	if err != nil {
		return 0, err
	}
	end, err := boundaryStat(stat, pid)
	if err != nil || end != start {
		return 0, fail("process_boundary_identity")
	}
	return start, nil
}

// Opening only establishes access. No target bytes or descriptor link values
// are retained or emitted, including on an unexpected successful open.
func openBoundaryProc(pid int, name string) error {
	f, err := os.OpenFile(boundaryProcPath(pid, name), os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err == nil {
		f.Close()
	}
	return err
}

func runBoundaryControl(ctx context.Context, uid uint32) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_PRCTL, 4, 1, 0); errno != 0 {
		return fail("process_boundary_control")
	}
	if value, _, errno := syscall.Syscall(syscall.SYS_PRCTL, 3, 0, 0); errno != 0 || value != 1 {
		return fail("process_boundary_control")
	}
	start, err := inspectBoundaryProcess(os.Getpid(), uid, processBoundaryBinary+"\x00"+processBoundaryFlag+"\x00", 0, true, []int{1, 2, 3})
	if err != nil {
		return err
	}
	// mmap keeps the synthetic address stable across Go stack movement.
	memory, err := syscall.Mmap(-1, 0, 4096, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANON)
	if err != nil {
		return fail("process_boundary_control")
	}
	defer syscall.Munmap(memory)
	memory[0] = 0x5a
	control := processBoundaryControl{Version: 1, PID: os.Getpid(), StartTicks: start, Address: uint64(uintptr(unsafe.Pointer(&memory[0])))}
	if json.NewEncoder(os.Stdout).Encode(control) != nil {
		return fail("process_boundary_control")
	}
	<-ctx.Done()
	runtime.KeepAlive(memory)
	return nil
}

func verifyBoundaryControl(ctx context.Context, uid uint32) (processBoundaryResult, error) {
	result := processBoundaryResult{}
	body, _ := json.Marshal(processBoundaryRequest{Version: 1, Kind: "control"})
	cmd := boundaryCommand(ctx, body)
	fd, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		return result, fail("process_boundary_control")
	}
	defer fd.Close()
	cmd.ExtraFiles = []*os.File{fd}
	stdout, err := cmd.StdoutPipe()
	if err != nil || cmd.Start() != nil {
		if stdout != nil {
			stdout.Close()
		}
		return result, fail("process_boundary_control")
	}
	defer func() { cmd.Process.Kill(); stdout.Close(); cmd.Wait() }()
	type handshake struct {
		body []byte
		err  error
	}
	ready := make(chan handshake, 1)
	go func() {
		line, err := bufio.NewReaderSize(stdout, processBoundaryLimit+1).ReadSlice('\n')
		ready <- handshake{append([]byte(nil), line...), err}
	}()
	var control processBoundaryControl
	select {
	case <-ctx.Done():
		return result, fail("process_boundary_control")
	case h := <-ready:
		if h.err != nil || decodeBoundaryMessage(h.body, &control) != nil || control.Version != 1 || control.PID != cmd.Process.Pid || control.StartTicks == 0 || control.Address == 0 {
			return result, fail("process_boundary_control")
		}
	}
	controlCmdline := processBoundaryBinary + "\x00" + processBoundaryFlag + "\x00"
	if _, err := inspectBoundaryProcess(control.PID, uid, controlCmdline, control.StartTicks, false, nil); err != nil {
		return result, err
	}
	if openBoundaryProc(control.PID, "environ") != nil {
		return result, fail("process_boundary_control")
	}
	for _, descriptor := range []string{"fd/1", "fd/2", "fd/3"} {
		if _, err := os.Readlink(boundaryProcPath(control.PID, descriptor)); err != nil || openBoundaryProc(control.PID, descriptor) != nil {
			return result, fail("process_boundary_control")
		}
	}
	var ok bool
	if result.ControlMem, ok = boundaryControlOutcome(openBoundaryProc(control.PID, "mem")); !ok {
		return result, fail("process_boundary_control")
	}
	value, errno := boundaryVMRead(control.PID, control.Address)
	if errno == 0 {
		if value != 0x5a {
			return result, fail("process_boundary_control")
		}
		result.ControlVMRead = "allowed"
	} else if result.ControlVMRead, ok = boundaryControlOutcome(errno); !ok {
		return result, fail("process_boundary_control")
	}
	if result.ControlPtrace, err = boundaryControlPtrace(ctx, control.PID); err != nil {
		return result, err
	}
	if _, err := inspectBoundaryProcess(control.PID, uid, controlCmdline, control.StartTicks, false, nil); err != nil {
		return result, err
	}
	return result, nil
}

func boundaryControlPtrace(ctx context.Context, pid int) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	_, _, errno := syscall.Syscall6(syscall.SYS_PTRACE, 0x4206, uintptr(pid), 0, 0, 0, 0) // PTRACE_SEIZE
	if errno != 0 {
		if outcome, ok := boundaryControlOutcome(errno); ok {
			return outcome, nil
		}
		return "", fail("process_boundary_control")
	}
	// Unlike ATTACH, SEIZE does not stop the peer. Interrupt, observe the stop,
	// then detach to prove trace access without leaving a synthetic child held.
	if _, _, errno = syscall.Syscall6(syscall.SYS_PTRACE, 0x4207, uintptr(pid), 0, 0, 0, 0); errno != 0 { // PTRACE_INTERRUPT
		return "", fail("process_boundary_control")
	}
	for ctx.Err() == nil {
		var status syscall.WaitStatus
		got, err := syscall.Wait4(pid, &status, syscall.WNOHANG|0x40000000, nil) // __WALL
		if err == syscall.EINTR {
			continue
		}
		if err != nil || (got == pid && !status.Stopped()) {
			return "", fail("process_boundary_control")
		}
		if got == pid {
			if syscall.PtraceDetach(pid) != nil {
				return "", fail("process_boundary_control")
			}
			return "allowed", nil
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Millisecond):
		}
	}
	return "", fail("process_boundary_control")
}
