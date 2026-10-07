//go:build linux

package supervisor

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// RuntimeInit prepares the manager boundary and supervises the pinned binary. It
// does not execute submissions or replace the mature inner sandbox.
func RuntimeInit() error {
	runtime.LockOSThread()
	if os.Getpid() != 1 || os.Geteuid() != 0 {
		return fail("manager_namespace")
	}
	data, err := os.ReadFile("/proc/self/uid_map")
	if err != nil || strings.Join(strings.Fields(string(data)), " ") != "0 30000 1 1 100000 65536" {
		return fail("manager_uid_mapping")
	}
	data, err = os.ReadFile("/proc/self/gid_map")
	if err != nil || strings.Join(strings.Fields(string(data)), " ") != "0 30000 1 1 100000 65536" {
		return fail("manager_gid_mapping")
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_PRCTL, 4, 0, 0); errno != 0 {
		return fail("manager_dumpability")
	}
	// The supervisor moves this process into its delegated subtree before this
	// barrier opens. A cgroup namespace created earlier would hide the wrong root.
	barrier := os.NewFile(3, "manager-start-barrier")
	var barrierValue [1]byte
	if barrier == nil {
		return fail("manager_start_barrier")
	}
	n, err := barrier.Read(barrierValue[:])
	barrier.Close()
	if err != nil || n != 1 || barrierValue[0] != 1 {
		return fail("manager_start_barrier")
	}
	if err := syscall.Unshare(syscall.CLONE_NEWCGROUP); err != nil {
		return fail("manager_cgroup_namespace")
	}
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return fail("manager_mount_propagation")
	}
	if err := syscall.Mount("proc", "/proc", "proc", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, ""); err != nil {
		return fail("manager_private_proc")
	}
	// The supervisor narrowed the inherited mount to the delegated subtree
	// before creating this user namespace. Linux locks that more-privileged mount
	// against unmount, so the manager cannot reveal the service sibling again.
	// The private cgroup namespace initially reports '/'. The pinned upstream
	// rejects an empty prefix, so give it a nonempty delegated parent before exec.
	if err := os.Mkdir("/sys/fs/cgroup/manager", 0755); err != nil {
		return fail("manager_cgroup_directory")
	}
	if err := os.WriteFile("/sys/fs/cgroup/manager/cgroup.procs", []byte("1"), 0); err != nil {
		return fail("manager_cgroup_membership")
	}
	if err := os.WriteFile("/sys/fs/cgroup/cgroup.subtree_control", []byte("+cpu +memory +pids"), 0); err != nil {
		return fail("manager_cgroup_controllers")
	}
	// Mask the outer service's facilities even if a future manager compromise
	// bypasses the inner sandbox. These mounts stay private to this child.
	for index, path := range []string{filepath.Dir(SecretsDirectory), filepath.Dir(PrivateDirectory), "/var/lib/startrack-judger", "/run/startrack-api", "/run/startrack-judger", filepath.Dir(QualificationPath), SocketDirectory} {
		if err := syscall.Mount("tmpfs", path, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "size=4k,nr_inodes=4,mode=000"); err != nil {
			return fail("manager_private_facility_" + strconv.Itoa(index))
		}
	}
	if err := os.Chdir(RuntimeDirectory); err != nil {
		return fail("manager_work_directory")
	}
	// A second user namespace locks the proc/facility mounts created above.
	// The actual go-judge cannot unmount them to uncover the outer process view.
	// This trusted PID1 helper receives only the low-level runtime credential.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	// This fixed trusted fixture models manager compromise in the exact same
	// nested namespaces. It never executes package or submitted bytes.
	probe := exec.CommandContext(ctx, RuntimeInitBinary, "--manager-boundary-probe")
	probe.Env, probe.Dir = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C"}, RuntimeDirectory
	probe.Stdout, probe.Stderr = os.Stdout, os.Stderr
	probe.SysProcAttr = managerNamespace()
	if probe.Run() != nil {
		return fail("manager_boundary")
	}
	manager := exec.Command(RuntimeBinary)
	manager.Env, manager.Dir = os.Environ(), RuntimeDirectory
	manager.Stdout, manager.Stderr = os.Stdout, os.Stderr
	manager.SysProcAttr = managerNamespace()
	if manager.Start() != nil {
		return fail("manager_exec")
	}
	done := make(chan error, 1)
	go func() { done <- manager.Wait() }()
	select {
	case <-done:
		return fail("manager_stopped")
	case <-ctx.Done():
	}
	manager.Process.Signal(syscall.SIGTERM)
	select {
	case <-done:
		return nil
	case <-time.After(5 * time.Second):
		manager.Process.Kill()
		<-done
		return nil
	}
}

func managerNamespace() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1}, {ContainerID: 1, HostID: 1, Size: 65536}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1}, {ContainerID: 1, HostID: 1, Size: 65536}},
		GidMappingsEnableSetgroups: true, Credential: &syscall.Credential{Uid: 0, Gid: 0}, Pdeathsig: syscall.SIGKILL,
	}
}
