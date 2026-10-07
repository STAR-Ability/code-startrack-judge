// SPDX-License-Identifier: Apache-2.0
// The controlled demo-protocol adapter exposes a private Unix socket only.
package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/processguard"
	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
	"github.com/STAR-Ability/code-startrack-judge/internal/runtime/restclient"
)

const checkerFile = "/opt/startrack/libexec/default_validator"
const graderFile = "/opt/startrack/libexec/default_grader"
const ledgerDirectory = "/var/lib/startrack-judger/dispatches"
const spoolDirectory = "/run/startrack-judger/tmp"

func main() {
	if processguard.Harden() != nil {
		log.Print("required judger process hardening unavailable")
		os.Exit(1)
	}
	if err := run(); err != nil {
		log.Print("controlled judger stopped: ", err)
		os.Exit(1)
	}
}
func run() error {
	if os.Geteuid() != 20001 {
		return errors.New("judger requires its dedicated nonroot identity")
	}
	if socket := os.Getenv("JUDGE_SCHEDULER_SOCKET"); socket != "" && socket != judgeruntime.SchedulerSocket {
		return errors.New("scheduler socket configuration invalid")
	}
	if os.Getenv("JUDGE_SCHEDULER_FD") != "3" {
		return errors.New("scheduler requires supervisor-owned listener descriptor")
	}
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(key)
		if key == "JUDGE_SCHEDULER_TOKEN" || key == "JUDGE_RUNTIME_TOKEN" {
			continue
		}
		if strings.Contains(upper, "DATABASE") || strings.HasPrefix(upper, "SMTP") || strings.HasPrefix(upper, "AWS_") || strings.HasPrefix(upper, "AZURE_") || strings.HasSuffix(upper, "_TOKEN") || strings.HasSuffix(upper, "_PASSWORD") || strings.HasSuffix(upper, "_SECRET") {
			return errors.New("judger received an out-of-scope credential setting")
		}
	}
	schedulerToken, runtimeToken := os.Getenv("JUDGE_SCHEDULER_TOKEN"), os.Getenv("JUDGE_RUNTIME_TOKEN")
	if subtle.ConstantTimeCompare([]byte(schedulerToken), []byte(runtimeToken)) == 1 {
		return errors.New("scheduler and sandbox credentials must be independent")
	}
	client, err := restclient.New(restclient.Options{Token: runtimeToken})
	if err != nil {
		return err
	}
	identity := judgeruntime.FrozenIdentity{LanguageConfigVersion: judgeruntime.CompilerConfigVersion, CompilerVersion: judgeruntime.CompilerVersion, ToolchainDigest: judgeruntime.CPP17ToolchainDigest, WorkerImageDigest: os.Getenv("JUDGE_WORKER_IMAGE_DIGEST"), SandboxVersion: judgeruntime.SandboxVersion, CheckerDigest: os.Getenv("JUDGE_CHECKER_SHA256")}
	if err = identity.Validate(); err != nil {
		return err
	}
	info, err := os.Lstat(checkerFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > judgeruntime.MaxFileBytes {
		return errors.New("pinned checker file invalid")
	}
	f, err := os.Open(checkerFile)
	if err != nil {
		return errors.New("pinned checker unavailable")
	}
	checker, err := io.ReadAll(io.LimitReader(f, judgeruntime.MaxFileBytes+1))
	f.Close()
	if err != nil || len(checker) > judgeruntime.MaxFileBytes {
		return errors.New("pinned checker file invalid")
	}
	info, err = os.Lstat(graderFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 || info.Size() > judgeruntime.MaxFileBytes {
		return errors.New("pinned grader file invalid")
	}
	f, err = os.Open(graderFile)
	if err != nil {
		return errors.New("pinned grader unavailable")
	}
	grader, err := io.ReadAll(io.LimitReader(f, judgeruntime.MaxFileBytes+1))
	f.Close()
	if err != nil || len(grader) > judgeruntime.MaxFileBytes {
		return errors.New("pinned grader file invalid")
	}
	ledger, err := judgeruntime.NewFileLedger(ledgerDirectory)
	if err != nil {
		return err
	}
	adapter, err := judgeruntime.New(judgeruntime.Options{Client: client, Reader: judgeruntime.MissingBlobReader{}, Identity: identity, Checker: checker, Grader: grader, BridgeDigest: os.Getenv("JUDGE_MATURE_BRIDGE_SHA256"), Verifier: judgeruntime.LinuxMeasurementVerifier{}, Ledger: ledger, AnalysisSupported: true})
	if err != nil {
		return err
	}
	handler, err := judgeruntime.NewSchedulerServer(adapter, schedulerToken, spoolDirectory)
	if err != nil {
		return err
	}
	if err = verifySocketDirectory(); err != nil {
		return err
	}
	info, err = os.Lstat(judgeruntime.SchedulerSocket)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0660 {
		return errors.New("scheduler socket state invalid")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 20001 || stat.Gid != 20002 {
		return errors.New("scheduler socket ownership invalid")
	}
	fd := os.NewFile(3, "supervised-scheduler-listener")
	if fd == nil {
		return errors.New("scheduler listener unavailable")
	}
	listener, err := net.FileListener(fd)
	fd.Close()
	if err != nil {
		return errors.New("scheduler listener unavailable")
	}
	defer listener.Close()
	if listener.Addr().Network() != "unix" || listener.Addr().String() != judgeruntime.SchedulerSocket {
		return errors.New("scheduler listener binding invalid")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, BaseContext: func(net.Listener) context.Context { return ctx }}
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			probeCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
			adapter.Qualify(probeCtx)
			cancel()
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			return errors.New("scheduler server stopped")
		}
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		server.Shutdown(shutdownCtx)
	}
	return nil
}
func verifySocketDirectory() error {
	info, err := os.Lstat("/run/startrack")
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0755 {
		return errors.New("scheduler directory invalid")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
		return errors.New("scheduler directory ownership invalid")
	}
	return nil
}
