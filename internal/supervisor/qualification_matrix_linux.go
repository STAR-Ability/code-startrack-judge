//go:build linux

package supervisor

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const MatrixPath = "/run/startrack-supervisor/runtime-matrix.json"

// These CLOEXEC directory descriptors retain trusted accounting access after
// the runtime mount hides the service sibling. They never reach child processes.
type cgroupAccounting struct{ directories map[string]*os.File }

func (a *cgroupAccounting) open() error {
	a.directories = map[string]*os.File{}
	for label, path := range map[string]string{"outer": "/sys/fs/cgroup", "service": "/sys/fs/cgroup/service", "runtime": "/sys/fs/cgroup/runtime"} {
		f, err := os.Open(path)
		if err != nil {
			return fail("qualification_cgroup_accounting")
		}
		a.directories[label] = f
	}
	return nil
}

func (a *cgroupAccounting) close() {
	for _, f := range a.directories {
		f.Close()
	}
}

func (a *cgroupAccounting) snapshot() (map[string]map[string]string, error) {
	result := map[string]map[string]string{}
	for label, dir := range a.directories {
		values := map[string]string{}
		for _, name := range []string{"memory.current", "memory.peak", "memory.max", "memory.swap.max", "memory.events", "memory.events.local", "pids.current", "pids.peak", "pids.max", "cpu.max", "cpu.stat"} {
			fd, err := syscall.Openat(int(dir.Fd()), name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
			if err != nil {
				return nil, fail("qualification_cgroup_accounting")
			}
			f := os.NewFile(uintptr(fd), name)
			data, err := io.ReadAll(io.LimitReader(f, 4097))
			f.Close()
			if err != nil || len(data) > 4096 {
				return nil, fail("qualification_cgroup_accounting")
			}
			values[name] = strings.TrimSpace(string(data))
		}
		result[label] = values
	}
	return result, nil
}

type matrixReportWriter struct{ bytes.Buffer }

func (w *matrixReportWriter) Write(p []byte) (int, error) {
	if w.Len()+len(p) > 65536 {
		return 0, fail("qualification_matrix_report_size")
	}
	return w.Buffer.Write(p)
}

type matrixPrivateWriter struct {
	file      *os.File
	remaining int
}

func (w *matrixPrivateWriter) Write(p []byte) (int, error) {
	n := len(p)
	if len(p) > w.remaining {
		p = p[:w.remaining]
	}
	if len(p) > 0 {
		written, err := w.file.Write(p)
		w.remaining -= written
		if err != nil {
			return written, err
		}
	}
	return n, nil
}

// Only the explicit synthetic qualification mode starts this fixed binary. It
// inherits PID1's service cgroup and receives the low-level token through stdin.
func runQualificationMatrix(ctx context.Context, s settings, accounting *cgroupAccounting) error {
	if !s.qualificationOnly {
		return fail("qualification_matrix_mode")
	}
	defer retainQualificationMatrixLogs()
	os.Remove(MatrixPath)
	os.Remove(MatrixPath + ".tmp")
	waitCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	for {
		if info, err := os.Lstat(QualificationPath); err == nil && info.Mode().IsRegular() {
			break
		}
		select {
		case <-waitCtx.Done():
			return fail("qualification_matrix_measurement")
		case <-time.After(100 * time.Millisecond):
		}
	}
	payload, err := json.Marshal(map[string]string{"token": s.runtimeToken, "workerImageDigest": s.imageDigest, "checkerDigest": s.checkerDigest, "bridgeDigest": s.bridgeDigest})
	if err != nil {
		return fail("qualification_matrix_payload")
	}
	log, err := openPrivateLog(filepath.Join(filepath.Dir(MatrixPath), "matrix-private.log"), 0)
	if err != nil {
		return err
	}
	defer log.Close()
	output := &matrixReportWriter{}
	child := ownedChild("/opt/startrack/bin/startrack-runtime-matrix", []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8", "TZ=UTC", "HOME=/nonexistent", "TMPDIR=/run/startrack-judger/tmp"}, JudgerUID, nil)
	child.Stdin, child.Stdout, child.Stderr = bytes.NewReader(payload), output, &matrixPrivateWriter{file: log, remaining: 65536}
	if child.Start() != nil {
		return fail("qualification_matrix_start")
	}
	pid := child.Process.Pid
	group, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil || strings.TrimSpace(string(group)) != "0::/service" {
		child.Process.Kill()
		child.Wait()
		return fail("qualification_matrix_service_cgroup")
	}
	before, err := accounting.snapshot()
	if err != nil {
		child.Process.Kill()
		child.Wait()
		return err
	}
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	deadline := time.NewTimer(15 * time.Minute)
	defer deadline.Stop()
	select {
	case err = <-done:
	case <-ctx.Done():
		child.Process.Kill()
		<-done
		return fail("qualification_matrix_interrupted")
	case <-deadline.C:
		child.Process.Kill()
		<-done
		return fail("qualification_matrix_timeout")
	}
	// Keep the bounded fixed synthetic report even when the matrix exits nonzero.
	// It stays private until the trusted harness validates a successful outcome.
	if len(output.Bytes()) > 0 {
		if reportLog, openErr := openPrivateLog(filepath.Join(filepath.Dir(MatrixPath), "matrix-report-private.json"), 0); openErr == nil {
			reportLog.Write(output.Bytes())
			reportLog.Close()
		}
	}
	if err != nil {
		return fail("qualification_matrix_execution")
	}
	var matrix struct {
		Passed bool `json:"passed"`
	}
	if json.Unmarshal(output.Bytes(), &matrix) != nil || !matrix.Passed {
		return fail("qualification_matrix_report")
	}
	after, err := accounting.snapshot()
	if err != nil {
		return err
	}
	report := struct {
		WorkerImageDigest string                       `json:"workerImageDigest"`
		MatrixCgroup      string                       `json:"matrixCgroup"`
		MatrixUID         uint32                       `json:"matrixUID"`
		Before            map[string]map[string]string `json:"cgroupsBefore"`
		After             map[string]map[string]string `json:"cgroupsAfter"`
		Matrix            json.RawMessage              `json:"matrix"`
	}{s.imageDigest, "/service", JudgerUID, before, after, output.Bytes()}
	data, err := json.Marshal(report)
	if err != nil || len(data) > 65536 {
		return fail("qualification_matrix_report_size")
	}
	f, err := os.OpenFile(MatrixPath+".tmp", os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0644)
	if err != nil {
		return fail("qualification_matrix_report_write")
	}
	_, err = f.Write(append(data, '\n'))
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil || os.Rename(MatrixPath+".tmp", MatrixPath) != nil {
		return fail("qualification_matrix_report_write")
	}
	return nil
}

// Fixed synthetic diagnostics survive tmpfs teardown in a separate root-only
// facility. Names and bytes never enter the public structural report.
func retainQualificationMatrixLogs() {
	const source = "/run/startrack-judger/tmp/matrix-evidence"
	// Qualification has no running business judger. Transfer only these fixed
	// completed synthetic facilities so root needs no DAC bypass capability.
	for _, path := range []string{"/run/startrack-judger/tmp", source} {
		fd, err := syscall.Open(path, 0x200000|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return
		}
		f := os.NewFile(uintptr(fd), "synthetic-private-directory")
		info, err := f.Stat()
		facts, ok := infoSys(info)
		if err != nil || !ok || !info.IsDir() || info.Mode().Perm() != 0700 || facts.Uid != JudgerUID || syscall.Fchownat(fd, "", 0, 0, 0x1000) != nil {
			f.Close()
			return
		}
		f.Close()
	}
	target := filepath.Join(filepath.Dir(MatrixPath), "private-matrix")
	if os.Mkdir(target, 0700) != nil {
		return
	}
	entries, err := os.ReadDir(source)
	if err != nil || len(entries) > 8 {
		return
	}
	allowed := regexp.MustCompile(`^(ALL_PARTS|VALIDATOR_EXIT_ZERO|ACCEPTED_REFERENCE_WRONG|STATEMENT_ARTIFACTS|MAXIMUM_PACKAGE)-[A-Za-z0-9]+\.log$`)
	for _, entry := range entries {
		if !allowed.MatchString(entry.Name()) {
			continue
		}
		// O_PATH permits inspection without granting root DAC override. After the
		// fixed matrix exits, transfer this validated evidence inode to its keeper.
		fd, err := syscall.Open(filepath.Join(source, entry.Name()), 0x200000|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
		if err != nil {
			continue
		}
		input := os.NewFile(uintptr(fd), "synthetic-private-log")
		info, err := input.Stat()
		stat, ok := infoSys(info)
		if err != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 65536 || stat.Uid != JudgerUID || stat.Nlink != 1 {
			input.Close()
			continue
		}
		if syscall.Fchownat(fd, "", 0, 0, 0x1000) != nil {
			input.Close()
			continue
		}
		readable, err := os.Open("/proc/self/fd/" + strconv.Itoa(fd))
		input.Close()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(readable, 65537))
		readable.Close()
		if err != nil || len(data) > 65536 {
			continue
		}
		output, err := openPrivateLog(filepath.Join(target, entry.Name()), 0)
		if err != nil {
			continue
		}
		output.Write(data)
		output.Close()
	}
}

func infoSys(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}
