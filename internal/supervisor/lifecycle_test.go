//go:build linux || darwin

package supervisor

import (
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Fixed self-reexec actors exercise actual Wait/reaping without namespaces,
// service credentials, arbitrary commands or sandbox execution.
func TestSupervisorComponentActor(t *testing.T) {
	mode := os.Getenv("STARTRACK_SUPERVISOR_COMPONENT_ACTOR")
	if mode == "" {
		return
	}
	if mode == "exit7" {
		os.Exit(7)
	}
	if mode == "exit0" {
		os.Exit(0)
	}
	stop := make(chan os.Signal, 1)
	if mode == "ignore" || mode == "hold-pipe" {
		signal.Ignore(syscall.SIGTERM)
	} else {
		signal.Notify(stop, syscall.SIGTERM)
	}
	ready := os.NewFile(3, "actor-ready")
	if _, err := ready.Write([]byte{1}); err != nil {
		os.Exit(9)
	}
	ready.Close()
	if mode == "ignore" || mode == "hold-pipe" {
		for {
			time.Sleep(time.Second)
		}
	}
	<-stop
	if mode == "term7" {
		os.Exit(7)
	}
	os.Exit(0)
}

func componentActor(t *testing.T, mode string, extra ...*os.File) *exec.Cmd {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestSupervisorComponentActor$")
	cmd.Env = []string{"STARTRACK_SUPERVISOR_COMPONENT_ACTOR=" + mode, "GORACE=atexit_sleep_ms=0"}
	if mode == "exit7" || mode == "exit0" {
		return cmd
	}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.ExtraFiles = append([]*os.File{write}, extra...)
	if err := cmd.Start(); err != nil {
		read.Close()
		write.Close()
		t.Fatal(err)
	}
	write.Close()
	read.SetReadDeadline(time.Now().Add(3 * time.Second))
	var ready [1]byte
	n, err := read.Read(ready[:])
	read.Close()
	if err != nil || n != 1 || ready[0] != 1 {
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatalf("actor readiness: n=%d err=%v", n, err)
	}
	return cmd
}

func awaitComponent(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("owned child did not settle")
	}
}

func cleanupMonitoredChild(t *testing.T, child *componentChild) {
	t.Helper()
	t.Cleanup(func() {
		child.cmd.Process.Kill()
		awaitComponent(t, child.settled)
	})
}

func TestComponentStopRequiresActualCleanWait(t *testing.T) {
	for _, mode := range []string{"term0", "term7", "ignore"} {
		t.Run(mode, func(t *testing.T) {
			p := newQualificationPublication(filepath.Join(t.TempDir(), "measurement"))
			cmd := componentActor(t, mode)
			child := monitorComponent(cmd, "api", p, nil, time.Second)
			cleanupMonitoredChild(t, child)
			allowance := time.Second
			if mode == "ignore" {
				allowance = 30 * time.Millisecond
			}
			if !stopComponents([]*componentChild{child}, p, allowance, time.Second) {
				t.Fatal("actual child was not reaped and settled")
			}
			if cmd.ProcessState == nil {
				t.Fatal("missing actual Wait process state")
			}
			if mode == "term0" {
				if child.waitErr != nil || p.failure() != nil {
					t.Fatalf("clean stop rejected: wait=%v fatal=%v", child.waitErr, p.failure())
				}
			} else if child.waitErr == nil || p.failure() == nil {
				t.Fatal("nonzero or forced stop reported clean")
			}
			if mode == "ignore" {
				status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
				if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
					t.Fatal("TERM-ignoring child was not actually killed/reaped")
				}
			}
			// The monitoring goroutine consumed the actual kernel wait status.
			var status syscall.WaitStatus
			if _, err := syscall.Wait4(cmd.Process.Pid, &status, syscall.WNOHANG, nil); err != syscall.ECHILD {
				t.Fatalf("child remains waitable: %v", err)
			}
		})
	}
}

func TestUnexpectedCleanComponentExitStaysFatal(t *testing.T) {
	p := newQualificationPublication(filepath.Join(t.TempDir(), "measurement"))
	cmd := componentActor(t, "exit0")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	child := monitorComponent(cmd, "runtime", p, nil, time.Second)
	cleanupMonitoredChild(t, child)
	awaitComponent(t, child.exited)
	p.terminate(child)
	if child.waitErr != nil || p.failure() == nil {
		t.Fatal("unexpected exit0 was excused as shutdown")
	}
}

func TestComponentWaitPrecedesHeldDiagnosticEOF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "measurement")
	if err := os.WriteFile(path, []byte("fresh measurement"), 0644); err != nil {
		t.Fatal(err)
	}
	p := newQualificationPublication(path)
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	// A second owned actor retains the same inherited write descriptor. Keeping
	// it a direct child lets this test actually reap every actor, without changing
	// the test process's global subreaper policy or leaving reparented orphans.
	holder := componentActor(t, "hold-pipe", write)
	t.Cleanup(func() { holder.Process.Kill(); holder.Wait() })
	drained := make(chan struct{})
	go func() { io.Copy(io.Discard, read); close(drained) }()
	cmd := componentActor(t, "exit7")
	cmd.Stdout = write
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	write.Close()
	child := monitorComponent(cmd, "runtime", p, &childDiagnostics{done: drained, close: diagnosticsCloser(read)}, 100*time.Millisecond)
	cleanupMonitoredChild(t, child)
	awaitComponent(t, child.exited)
	if child.waitErr == nil || p.failure() == nil {
		t.Fatal("actual fatal Wait status was delayed or lost")
	}
	select {
	case <-drained:
		t.Fatal("held diagnostic pipe reached EOF before settlement")
	default:
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("fatal exit did not revoke evidence before diagnostic EOF")
	}
	awaitComponent(t, child.settled)
	if cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 7 {
		t.Fatal("diagnostic settlement overwrote actual child exit status")
	}
}

func TestExpectedCleanExitWithUnsettledDiagnosticsIsFatal(t *testing.T) {
	p := newQualificationPublication(filepath.Join(t.TempDir(), "measurement"))
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	drained := make(chan struct{})
	go func() { io.Copy(io.Discard, read); close(drained) }()
	cmd := componentActor(t, "term0")
	child := monitorComponent(cmd, "runtime", p, &childDiagnostics{done: drained, close: diagnosticsCloser(read)}, 20*time.Millisecond)
	cleanupMonitoredChild(t, child)
	if !stopComponents([]*componentChild{child}, p, time.Second, time.Second) {
		t.Fatal("diagnostic reader did not settle after withdrawal")
	}
	if child.waitErr != nil || !cmd.ProcessState.Success() || p.failure() == nil {
		t.Fatal("unsettled diagnostics were counted as clean shutdown")
	}
}
