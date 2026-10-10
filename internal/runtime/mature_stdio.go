// SPDX-License-Identifier: Apache-2.0
package runtime

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const MatureBridgePath = "/opt/startrack/libexec/problemtools-bridge.py"
const matureSpoolRoot = "/run/startrack-judger/tmp"

// StdioMatureRunner starts only the project-owned trusted orchestration wrapper.
// It receives an explicit credential-free environment and protected artifact
// workspace. Every untrusted native operation is synchronously delegated to
// MatureHandler, which executes through the reviewed sandbox, never os/exec.
type StdioMatureRunner struct{ BridgeSHA256 string }

func (r StdioMatureRunner) Verify(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || !digestPattern.MatchString(r.BridgeSHA256) {
		return failure("MATURE_HELPER_IDENTITY_INVALID", false)
	}
	raw, e := readTrustedHelper(MatureBridgePath, 1<<20)
	if e != nil || !bytesMatch(raw, BlobRef{SHA256: r.BridgeSHA256, SizeBytes: int64(len(raw))}) {
		return failure("MATURE_HELPER_IDENTITY_INVALID", false)
	}
	return nil
}

func readTrustedHelper(path string, max int64) ([]byte, error) {
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, e := os.Lstat(parent)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return nil, failure("MATURE_HELPER_UNAVAILABLE", false)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return nil, failure("MATURE_HELPER_UNAVAILABLE", false)
		}
		if parent == filepath.Dir(parent) {
			break
		}
	}
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, failure("MATURE_HELPER_UNAVAILABLE", false)
	}
	f := os.NewFile(uintptr(fd), "fixed-trusted-helper")
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > max {
		return nil, failure("MATURE_HELPER_UNAVAILABLE", false)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 {
		return nil, failure("MATURE_HELPER_UNAVAILABLE", false)
	}
	raw, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(raw)) > max {
		return nil, failure("MATURE_HELPER_UNAVAILABLE", false)
	}
	return raw, nil
}

type boundedPrivateLog struct {
	mu        sync.Mutex
	remaining int64
	bytes     []byte
}

func (w *boundedPrivateLog) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if int64(len(p)) > w.remaining {
		return 0, failure("MATURE_PRIVATE_LOG_BOUNDS", false)
	}
	w.remaining -= int64(len(p))
	w.bytes = append(w.bytes, p...)
	return len(p), nil
}
func (w *boundedPrivateLog) snapshot() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.bytes...)
}

func (r StdioMatureRunner) Run(ctx context.Context, input MatureInput, reader BlobReader, handle MatureHandler) (out MatureOutcome, err error) {
	if ctx == nil || !input.valid() || reader == nil || handle == nil {
		return out, failure("MATURE_CONFIGURATION_INVALID", false)
	}
	if e := r.Verify(ctx); e != nil {
		return out, e
	}
	info, e := os.Lstat(matureSpoolRoot)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return out, failure("MATURE_SPOOL_INVALID", false)
	}
	directory, e := os.MkdirTemp(matureSpoolRoot, "mature-")
	if e != nil {
		return out, failure("MATURE_SPOOL_FAILED", false)
	}
	defer func() {
		if os.RemoveAll(directory) != nil {
			err = failure("MATURE_SPOOL_CLEANUP_FAILED", true)
		}
	}()
	packageDir := filepath.Join(directory, input.Manifest.Statement.Shortname)
	if e := os.Mkdir(packageDir, 0700); e != nil {
		return out, failure("MATURE_SPOOL_FAILED", false)
	}
	for _, f := range input.Manifest.Files {
		path := filepath.Join(packageDir, filepath.FromSlash(f.NormalizedPath))
		if !strings.HasPrefix(path, packageDir+string(filepath.Separator)) || strings.Contains(f.NormalizedPath, "\\") {
			return out, failure("MATURE_PATH_INVALID", false)
		}
		data, e := reader.ReadBlob(ctx, f.NormalizedSHA256, f.NormalizedSizeBytes, MaxFileBytes)
		if e != nil || !bytesMatch(data, BlobRef{SHA256: f.NormalizedSHA256, SizeBytes: f.NormalizedSizeBytes}) {
			return out, failure("PRIVATE_INPUT_INTEGRITY_FAILED", false)
		}
		if os.MkdirAll(filepath.Dir(path), 0700) != nil {
			return out, failure("MATURE_SPOOL_FAILED", false)
		}
		file, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return out, failure("MATURE_SPOOL_FAILED", false)
		}
		_, e = file.Write(data)
		closeError := file.Close()
		if e != nil || closeError != nil {
			return out, failure("MATURE_SPOOL_FAILED", false)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/local/bin/python3", "-I", MatureBridgePath)
	command.Dir = directory
	command.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "HOME=" + directory, "TMPDIR=" + directory}
	privateLog := &boundedPrivateLog{remaining: 2 << 20}
	command.Stderr = privateLog
	command.WaitDelay = 5 * time.Second
	stdin, e := command.StdinPipe()
	if e != nil {
		return out, failure("MATURE_PIPE_FAILED", false)
	}
	stdout, e := command.StdoutPipe()
	if e != nil {
		stdin.Close()
		return out, failure("MATURE_PIPE_FAILED", false)
	}
	if e := command.Start(); e != nil {
		stdin.Close()
		stdout.Close()
		return out, failure("MATURE_HELPER_UNAVAILABLE", false)
	}
	waited := false
	defer func() {
		stdin.Close()
		stdout.Close()
		if !waited {
			command.Process.Kill()
			command.Wait()
		}
		out.RawLog = privateLog.snapshot()
	}()
	encoder := json.NewEncoder(stdin)
	control := struct {
		PackageDir            string         `json:"packageDir"`
		Manifest              any            `json:"manifest"`
		Identity              FrozenIdentity `json:"identity"`
		FixedTimeLimitSeconds string         `json:"fixedTimeLimitSeconds"`
	}{packageDir, input.Manifest, input.Identity, fmt.Sprintf("%d.%03d", input.Manifest.Limits.TimeLimitMS/1000, input.Manifest.Limits.TimeLimitMS%1000)}
	if encoder.Encode(control) != nil {
		return out, failure("MATURE_CONTROL_FAILED", false)
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 4096), MaxMatureFrameBytes)
	for scanner.Scan() {
		var marker struct {
			Operation string `json:"operation"`
		}
		if json.Unmarshal(scanner.Bytes(), &marker) != nil {
			return out, failure("MATURE_PROTOCOL_INVALID", false)
		}
		if marker.Operation == "RESULT" {
			var report struct {
				Operation string              `json:"operation"`
				Completed bool                `json:"completed"`
				Parts     []MaturePartOutcome `json:"parts"`
				Errors    int                 `json:"errors"`
				Warnings  int                 `json:"warnings"`
			}
			if strictDecode(scanner.Bytes(), &report) != nil {
				return out, failure("MATURE_REPORT_INVALID", false)
			}
			out = MatureOutcome{Completed: report.Completed, Parts: report.Parts, Errors: report.Errors, Warnings: report.Warnings}
			if !out.valid() {
				return out, failure("MATURE_REPORT_INVALID", false)
			}
			stdin.Close()
			if scanner.Scan() || scanner.Err() != nil {
				return out, failure("MATURE_PROTOCOL_INVALID", false)
			}
			e := command.Wait()
			waited = true
			out.RawLog = privateLog.snapshot()
			if e != nil || !out.Completed {
				return out, failure("MATURE_HELPER_FAILED", false)
			}
			return out, nil
		}
		var request MatureRequest
		if strictDecode(scanner.Bytes(), &request) != nil {
			return out, failure("MATURE_PROTOCOL_INVALID", false)
		}
		response, e := handle(ctx, request)
		if e != nil {
			return out, e
		}
		if encoder.Encode(response) != nil {
			return out, failure("MATURE_PROTOCOL_FAILED", false)
		}
	}
	if ctx.Err() != nil {
		return out, failure("MATURE_OPERATION_INTERRUPTED", true)
	}
	return out, failure("MATURE_HELPER_FAILED", false)
}

var _ io.Writer = (*boundedPrivateLog)(nil)
