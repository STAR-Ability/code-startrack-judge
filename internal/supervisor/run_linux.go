//go:build linux

package supervisor

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Run is the fixed PID1 service bootstrap. A failed component stops the whole
// container; the operator restarts the measured instance, never a weaker mode.
func Run(ctx context.Context) error {
	if ctx == nil || os.Getpid() != 1 || os.Geteuid() != 0 {
		return fail("linux_pid1")
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_PRCTL, 4, 0, 0); errno != 0 {
		return fail("dumpability")
	}
	if err := validateRootEnvironment(os.Environ()); err != nil {
		return err
	}
	if err := rootAncestors(SecretsDirectory); err != nil {
		return err
	}
	s, err := loadSettings(os.Getenv, func(name string) (string, error) {
		return readSecretFile(filepath.Join(SecretsDirectory, name), 0)
	})
	if err != nil {
		return err
	}
	if err = prepareDirectories(); err != nil {
		return err
	}
	os.Remove(QualificationPath)
	os.Remove(QualificationPath + ".tmp")
	os.Remove(MatrixPath)
	os.Remove(MatrixPath + ".tmp")
	accounting := &cgroupAccounting{}
	defer accounting.close()
	if err = prepareCgroup(accounting); err != nil {
		return err
	}
	// Docker masks selected /proc children. Linux refuses a new user-namespace
	// proc mount when every inherited proc is partially masked. This private,
	// root-only bootstrap mount permits the manager to replace /proc with its own
	// PID-namespace view; it is hidden again by RuntimeInit before go-judge exec.
	if os.MkdirAll("/run/startrack-supervisor/bootstrap/proc", 0700) != nil {
		return fail("bootstrap_proc_directory")
	}
	if syscall.Mount("proc", "/run/startrack-supervisor/bootstrap/proc", "proc", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "") != nil {
		return fail("bootstrap_proc_mount")
	}

	type childState struct {
		cmd  *exec.Cmd
		done chan struct{}
	}
	children := []childState{}
	runtimeDrain := make(chan struct{})
	monitor := func(c *exec.Cmd) childState {
		state := childState{c, make(chan struct{})}
		go func() {
			c.Wait()
			if c.Path == RuntimeInitBinary {
				<-runtimeDrain
			}
			if c.ProcessState != nil {
				if status, ok := c.ProcessState.Sys().(syscall.WaitStatus); ok {
					fmt.Fprintf(os.Stderr, "supervisor child_exit pid=%d status=%d signal=%d\n", c.Process.Pid, status.ExitStatus(), status.Signal())
				}
			}
			close(state.done)
		}()
		children = append(children, state)
		return state
	}
	defer func() {
		os.Remove(QualificationPath)
		for _, child := range children {
			child.cmd.Process.Signal(syscall.SIGTERM)
		}
		deadline := time.After(10 * time.Second)
		for _, child := range children {
			select {
			case <-child.done:
			case <-deadline:
				for _, c := range children {
					c.cmd.Process.Kill()
				}
				return
			}
		}
	}()
	runtime, err := startRuntime(s, runtimeDrain)
	if err != nil {
		return err
	}
	runtimeState := monitor(runtime)
	qualificationFailed := make(chan error, 1)
	startQualification := func() {
		go func() {
			for {
				probeCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
				err := qualify(probeCtx, s, runtime.Process.Pid)
				cancel()
				if err != nil {
					os.Remove(QualificationPath)
					qualificationFailed <- err
					return
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(15 * time.Second):
				}
			}
		}()
	}
	if s.qualificationOnly {
		startQualification()
		matrixFailed := make(chan error, 1)
		go func() { matrixFailed <- runQualificationMatrix(ctx, s, accounting) }()
		select {
		case <-ctx.Done():
			return nil
		case <-runtimeState.done:
			return fail("runtime_stopped")
		case err := <-qualificationFailed:
			return err
		case err := <-matrixFailed:
			if err != nil {
				return err
			}
			select {
			case <-ctx.Done():
				return nil
			case <-runtimeState.done:
				return fail("runtime_stopped")
			case err := <-qualificationFailed:
				return err
			}
		}
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: SchedulingSocket, Net: "unix"})
	if err != nil {
		return fail("scheduler_listener")
	}
	defer listener.Close()
	listener.SetUnlinkOnClose(false)
	if os.Chown(SchedulingSocket, JudgerUID, SchedulingGID) != nil || os.Chmod(SchedulingSocket, 0660) != nil {
		return fail("scheduler_listener_ownership")
	}
	fd, err := listener.File()
	if err != nil {
		return fail("scheduler_descriptor")
	}
	judger := ownedChild(JudgerBinary, s.judgerEnvironment(), JudgerUID, nil)
	judger.ExtraFiles = []*os.File{fd}
	err = judger.Start()
	fd.Close()
	if err != nil {
		return fail("judger_start")
	}
	monitor(judger)
	api := ownedChild(APIBinary, s.apiEnvironment(), APIUID, []uint32{SchedulingGID})
	if api.Start() != nil {
		return fail("api_start")
	}
	monitor(api)
	startQualification()
	failure := make(chan struct{}, len(children))
	for _, child := range children {
		go func(c childState) { <-c.done; failure <- struct{}{} }(child)
	}
	select {
	case <-ctx.Done():
		return nil
	case <-failure:
		return fail("component_stopped")
	case err := <-qualificationFailed:
		return err
	}
}

func ownedChild(binary string, env []string, uid uint32, groups []uint32) *exec.Cmd {
	c := exec.Command(binary)
	c.Env, c.Dir = env, "/"
	c.Stdin, c.Stdout, c.Stderr = nil, os.Stdout, os.Stderr
	c.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid, Groups: groups}, Pdeathsig: syscall.SIGKILL}
	return c
}

func startRuntime(s settings, drained chan struct{}) (*exec.Cmd, error) {
	read, write, err := os.Pipe()
	if err != nil {
		return nil, fail("runtime_barrier")
	}
	defer read.Close()
	defer write.Close()
	diagnostics, status, err := os.Pipe()
	if err != nil {
		return nil, fail("runtime_status")
	}
	defer status.Close()
	statusDone := make(chan struct{})
	go func() {
		defer close(statusDone)
		defer diagnostics.Close()
		body, _ := io.ReadAll(io.LimitReader(diagnostics, 256))
		if regexp.MustCompile(`^supervisor [a-z0-9_]+ failure\n$`).Match(body) {
			os.Stderr.Write(body)
		}
	}()
	c := exec.Command(RuntimeInitBinary)
	c.Env, c.Dir = s.runtimeEnvironment(), "/"
	c.ExtraFiles = []*os.File{read, status}
	// Bounded raw startup diagnostics have a separate root-only facility. They
	// never enter normal container logs or the structural measurement report.
	logs, logWriter, err := os.Pipe()
	if err != nil {
		return nil, fail("runtime_diagnostics")
	}
	defer logWriter.Close()
	privateLog, err := openPrivateLog(filepath.Join(filepath.Dir(QualificationPath), "runtime-private.log"), 0)
	if err != nil {
		logs.Close()
		return nil, fail("runtime_diagnostics")
	}
	logsDone := make(chan struct{})
	go func() {
		defer close(logsDone)
		defer logs.Close()
		defer privateLog.Close()
		io.Copy(privateLog, io.LimitReader(logs, 64<<10))
	}()
	go func() { <-statusDone; <-logsDone; close(drained) }()
	c.Stdout, c.Stderr = logWriter, logWriter
	c.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: RuntimeHostUID, Size: 1}, {ContainerID: 1, HostID: 100000, Size: 65536}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: RuntimeHostUID, Size: 1}, {ContainerID: 1, HostID: 100000, Size: 65536}},
		GidMappingsEnableSetgroups: true,
		Credential:                 &syscall.Credential{Uid: 0, Gid: 0}, Pdeathsig: syscall.SIGKILL,
	}
	if c.Start() != nil {
		return nil, fail("runtime_start")
	}
	if os.WriteFile("/sys/fs/cgroup/cgroup.procs", []byte(strconv.Itoa(c.Process.Pid)), 0) != nil {
		c.Process.Kill()
		c.Wait()
		return nil, fail("runtime_delegation")
	}
	if _, err = write.Write([]byte{1}); err != nil {
		c.Process.Kill()
		c.Wait()
		return nil, fail("runtime_barrier")
	}
	return c, nil
}

func prepareDirectories() error {
	for _, dir := range []struct {
		path string
		uid  int
		mode os.FileMode
	}{
		{"/run/startrack-api", 0, 0755}, {"/run/startrack-judger", 0, 0755}, {"/run/startrack-runtime", 0, 0755},
		{SocketDirectory, 0, 0755}, {filepath.Dir(QualificationPath), 0, 0755},
		{PrivateDirectory, APIUID, 0700}, {"/var/lib/startrack-judger/dispatches", JudgerUID, 0700},
		{"/run/startrack-api/tmp", APIUID, 0700}, {"/run/startrack-judger/tmp", JudgerUID, 0700},
		{RuntimeDirectory, RuntimeHostUID, 0700}, {RuntimeCacheDirectory, RuntimeHostUID, 0700},
	} {
		if err := rootAncestors(filepath.Dir(dir.path)); err != nil {
			return err
		}
		if os.MkdirAll(dir.path, dir.mode) != nil {
			return fail("directory_creation")
		}
		info, err := os.Lstat(dir.path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fail("directory_type")
		}
		if os.Chown(dir.path, dir.uid, dir.uid) != nil || os.Chmod(dir.path, dir.mode) != nil {
			return fail("directory_ownership")
		}
	}
	return nil
}

// Every replaceable ancestor must be root-owned and immutable to service roles.
func rootAncestors(path string) error {
	for {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
			return fail("directory_ancestor")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return fail("directory_ancestor")
		}
		if path == "/" {
			return nil
		}
		path = filepath.Dir(path)
	}
}

func prepareCgroup(accounting *cgroupAccounting) error {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil || strings.TrimSpace(string(data)) != "0::/" {
		return fail("private_cgroup_root")
	}
	if err = syscall.Mount("", "/sys/fs/cgroup", "", syscall.MS_REMOUNT|syscall.MS_BIND|syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, ""); err != nil {
		return fail("cgroup_remount")
	}
	for _, name := range []string{"service", "runtime"} {
		if os.Mkdir("/sys/fs/cgroup/"+name, 0755) != nil {
			return fail("cgroup_directory")
		}
	}
	if os.WriteFile("/sys/fs/cgroup/service/cgroup.procs", []byte(strconv.Itoa(os.Getpid())), 0) != nil {
		return fail("service_cgroup")
	}
	if os.WriteFile("/sys/fs/cgroup/cgroup.subtree_control", []byte("+cpu +memory +pids"), 0) != nil {
		return fail("cgroup_controllers")
	}
	for _, name := range []string{"", "cgroup.procs", "cgroup.threads", "cgroup.subtree_control"} {
		path := filepath.Join("/sys/fs/cgroup/runtime", name)
		if os.Chown(path, RuntimeHostUID, 0) != nil {
			return fail("cgroup_owner")
		}
		mode := os.FileMode(0660)
		if name == "" {
			mode = 0750
		}
		if os.Chmod(path, mode) != nil {
			return fail("cgroup_mode")
		}
	}
	// Manager plus untrusted execution stay within these service-owned maxima.
	for name, value := range map[string]string{"memory.max": "6442450944", "memory.swap.max": "0", "pids.max": "256"} {
		if os.WriteFile("/sys/fs/cgroup/service/"+name, []byte(value), 0) != nil {
			return fail("service_cgroup_limits")
		}
	}
	for name, value := range map[string]string{"memory.max": "4294967296", "memory.swap.max": "0", "pids.max": "256", "cpu.max": "200000 100000"} {
		if os.WriteFile("/sys/fs/cgroup/runtime/"+name, []byte(value), 0) != nil {
			return fail("cgroup_limits")
		}
	}
	if err := accounting.open(); err != nil {
		return err
	}
	if syscall.Mount("/sys/fs/cgroup/runtime", "/sys/fs/cgroup", "", syscall.MS_BIND, "") != nil {
		return fail("cgroup_mount_boundary")
	}
	return nil
}
