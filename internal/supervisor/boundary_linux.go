//go:build linux

package supervisor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// ManagerBoundaryProbe is a fixed trusted startup fixture, not an execution
// adapter. It runs before go-judge in an identical nested user/mount namespace.
func ManagerBoundaryProbe() error {
	if os.Getpid() == 1 || os.Geteuid() != 0 {
		return fail("manager_probe_identity")
	}
	uidMap, e1 := os.ReadFile("/proc/self/uid_map")
	gidMap, e2 := os.ReadFile("/proc/self/gid_map")
	status, e3 := os.ReadFile("/proc/self/status")
	if e1 != nil || e2 != nil || e3 != nil || strings.Join(strings.Fields(string(uidMap)), " ") != "0 0 1 1 1 65536" || strings.Join(strings.Fields(string(gidMap)), " ") != "0 0 1 1 1 65536" || !strings.Contains(string(status), "CapEff:\t000001ffffffffff\n") || !strings.Contains(string(status), "CapBnd:\t000001ffffffffff\n") || !strings.Contains(string(status), "NoNewPrivs:\t1\n") || !strings.Contains(string(status), "Seccomp:\t2\n") {
		fmt.Fprintf(os.Stdout, "manager_probe uid_map=%q gid_map=%q\n", strings.Join(strings.Fields(string(uidMap)), " "), strings.Join(strings.Fields(string(gidMap)), " "))
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "Cap") || strings.HasPrefix(line, "NoNewPrivs:") || strings.HasPrefix(line, "Seccomp:") {
				fmt.Fprintln(os.Stdout, line)
			}
		}
		return fail("manager_probe_profile")
	}
	// The pinned sandbox needs this namespaced capability before it drops every
	// capability for workload exec. This fixture only tightens its own securebits.
	bits, _, getErr := syscall.Syscall(syscall.SYS_PRCTL, 27, 0, 0)
	_, _, setErr := syscall.Syscall(syscall.SYS_PRCTL, 28, bits|44, 0)
	if getErr != 0 || setErr != 0 {
		fmt.Fprintf(os.Stdout, "manager_probe securebits=%d get_errno=%d set_errno=%d\n", bits, getErr, setErr)
		return fail("manager_probe_securebits")
	}
	for _, path := range []string{"/proc", filepath.Dir(SecretsDirectory), filepath.Dir(PrivateDirectory), "/var/lib/startrack-judger", "/run/startrack-api", "/run/startrack-judger", filepath.Dir(QualificationPath), SocketDirectory, "/sys/fs/cgroup"} {
		for _, flags := range []int{0, syscall.MNT_DETACH} {
			if syscall.Unmount(path, flags) == nil {
				return fail("manager_probe_unmount")
			}
		}
	}
	for _, path := range []string{"/proc/1/environ", "/proc/1/mem", "/proc/1/fd/3", "/proc/1/root/run/secrets/startrack/database-url", SecretsDirectory + "/database-url", PrivateDirectory, "/run/startrack-supervisor/bootstrap/proc/1/environ", "/sys/fs/cgroup/service/cgroup.procs"} {
		file, err := os.Open(path)
		if err == nil {
			file.Close()
			return fail("manager_probe_private_access")
		}
	}
	for _, path := range []string{"/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/pids.max", "/sys/fs/cgroup/cpu.max"} {
		file, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err == nil {
			file.Close()
			return fail("manager_probe_cgroup_control")
		}
	}
	directory, err := os.MkdirTemp(RuntimeDirectory, "boundary-")
	if err != nil {
		return fail("manager_probe_directory")
	}
	defer os.RemoveAll(directory)
	if syscall.Mount("proc", directory, "proc", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "") == nil {
		syscall.Unmount(directory, syscall.MNT_DETACH)
		return fail("manager_probe_outer_proc")
	}
	fmt.Fprintln(os.Stdout, `{"managerBoundary":"PASS","uidMapping":"0:0:1,1:1:65536","effectiveCapabilities":"000001ffffffffff","boundingCapabilities":"000001ffffffffff","outerUID":30000,"unmountDenied":true,"privateAccessDenied":true,"ancestorControlsDenied":true,"outerProcDenied":true}`)
	fmt.Fprintf(os.Stdout, "manager_probe invalid_pivot_root=%v\n", syscall.PivotRoot("/__startrack_absent", "/__startrack_absent/old"))
	return nil
}
