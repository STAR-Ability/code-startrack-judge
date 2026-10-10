package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
)

const MeasurementPath = "/run/startrack-supervisor/runtime-measurement.json"

// RuntimeMeasurement is produced only by the supervisor's Linux qualification
// harness after actual probes. It is safe structural evidence, without runtime
// token, source, answers, raw output, logs or private host addresses.
type RuntimeMeasurement struct {
	Version               int             `json:"version"`
	Identity              FrozenIdentity  `json:"identity"`
	PID                   int             `json:"pid"`
	StartTicks            string          `json:"startTicks"`
	BootID                string          `json:"bootId"`
	MeasuredAt            time.Time       `json:"measuredAt"`
	SecurityProfileSHA256 string          `json:"securityProfileSha256"`
	Checks                map[string]bool `json:"checks"`
}

var RequiredIsolationChecks = []string{"cgroup_cpu", "cgroup_memory", "cgroup_pids", "seccomp", "namespaces", "network_denied", "filesystem_isolation", "credential_isolation", "process_limits", "output_limits", "cleanup", "cpu_limits", "wall_limits", "memory_limits", "compiler_isolation", "cache_cleanup", "sibling_proc_denied", "unique_execution_uids"}

type LinuxMeasurementVerifier struct{}

// Verify checks immutable identity, freshness, root-owned proof, and the live
// boot/PID/start-time identity. Portable development cannot pass this verifier.
func (LinuxMeasurementVerifier) Verify(ctx context.Context, identity FrozenIdentity) (string, error) {
	if goruntime.GOOS != "linux" || ctx == nil || ctx.Err() != nil {
		return "", failure("SANDBOX_ISOLATION_UNVERIFIED", false)
	}
	for p := filepath.Dir(MeasurementPath); ; p = filepath.Dir(p) {
		info, e := os.Lstat(p)
		if e != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return "", failure("SANDBOX_MEASUREMENT_INVALID", false)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return "", failure("SANDBOX_MEASUREMENT_INVALID", false)
		}
		if !info.IsDir() {
			return "", failure("SANDBOX_MEASUREMENT_INVALID", false)
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	fd, e := syscall.Open(MeasurementPath, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return "", failure("SANDBOX_MEASUREMENT_INVALID", false)
	}
	f := os.NewFile(uintptr(fd), "private-runtime-measurement")
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0644 || info.Size() > 64<<10 {
		return "", failure("SANDBOX_MEASUREMENT_INVALID", false)
	}
	fileStat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || fileStat.Uid != 0 || fileStat.Nlink != 1 {
		return "", failure("SANDBOX_MEASUREMENT_INVALID", false)
	}
	raw, e := io.ReadAll(io.LimitReader(f, 64<<10+1))
	if e != nil || len(raw) > 64<<10 || canonical.ValidateJSON(raw) != nil {
		return "", failure("SANDBOX_MEASUREMENT_INVALID", false)
	}
	var m RuntimeMeasurement
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&m) != nil {
		return "", failure("SANDBOX_MEASUREMENT_INVALID", false)
	}
	if m.Version != 1 || m.Identity != identity || m.Identity.Validate() != nil || m.PID <= 1 || m.MeasuredAt.IsZero() || time.Since(m.MeasuredAt) > 30*time.Second || time.Until(m.MeasuredAt) > 5*time.Second || !digestPattern.MatchString(m.SecurityProfileSHA256) || len(m.Checks) != len(RequiredIsolationChecks) {
		return "", failure("SANDBOX_MEASUREMENT_INVALID", false)
	}
	for _, key := range RequiredIsolationChecks {
		if !m.Checks[key] {
			return "", failure("SANDBOX_ISOLATION_UNVERIFIED", false)
		}
	}
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil || strings.TrimSpace(string(boot)) != m.BootID {
		return "", failure("SANDBOX_INSTANCE_CHANGED", false)
	}
	stat, e := os.ReadFile("/proc/" + strconv.Itoa(m.PID) + "/stat")
	if e != nil {
		return "", failure("SANDBOX_INSTANCE_CHANGED", false)
	}
	end := bytes.LastIndexByte(stat, ')')
	if end < 0 {
		return "", failure("SANDBOX_INSTANCE_CHANGED", false)
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) < 20 || fields[0] == "Z" || fields[19] != m.StartTicks {
		return "", failure("SANDBOX_INSTANCE_CHANGED", false)
	}
	if ctx.Err() != nil {
		return "", failure("SANDBOX_ISOLATION_UNVERIFIED", false)
	}
	return m.BootID + ":" + strconv.Itoa(m.PID) + ":" + m.StartTicks + ":" + m.SecurityProfileSHA256, nil
}
