//go:build linux

package supervisor

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

// The subprocesses are trusted test fixtures; they need no namespaces or
// sandbox privileges. Each mode positively acknowledges its signal setup.
func TestManagerStopChild(t *testing.T) {
	mode := os.Getenv("STARTRACK_TEST_MANAGER_STOP")
	if mode == "" {
		return
	}
	term := make(chan os.Signal, 1)
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGUSR1)
	if mode == "ignore" {
		signal.Ignore(syscall.SIGTERM)
	} else {
		signal.Notify(term, syscall.SIGTERM)
	}
	if _, err := os.Stdout.WriteString("ready\n"); err != nil {
		os.Exit(8)
	}
	select {
	case <-term:
		if mode == "nonzero" {
			os.Exit(7)
		}
		os.Exit(0)
	case <-exit:
		os.Exit(0)
	}
}

func startManagerStopChild(t *testing.T, mode string) *exec.Cmd {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestManagerStopChild$")
	cmd.Env = []string{"STARTRACK_TEST_MANAGER_STOP=" + mode}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		stdout.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); stdout.Close() })
	ready := make(chan bool, 1)
	go func() {
		line, err := bufio.NewReader(stdout).ReadString('\n')
		ready <- err == nil && line == "ready\n"
	}()
	select {
	case ok := <-ready:
		if !ok {
			cmd.Process.Kill()
			cmd.Wait()
			t.Fatal("manager fixture did not acknowledge signal setup")
		}
	case <-time.After(5 * time.Second):
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatal("manager fixture startup deadline")
	}
	return cmd
}

func TestManagerStopWaitClassification(t *testing.T) {
	for _, tc := range []struct {
		mode, want string
	}{
		{"clean", ""},
		{"nonzero", "manager_stop_wait"},
		{"ignore", "manager_stop_deadline"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			cmd := startManagerStopChild(t, tc.mode)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			allowance := 3 * time.Second
			if tc.mode == "ignore" {
				allowance = 100 * time.Millisecond
			}
			err := superviseManager(ctx, cmd, allowance)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err != fail(tc.want) {
				t.Fatalf("got %v, want %s", err, tc.want)
			}
			if cmd.ProcessState == nil {
				t.Fatal("manager returned without actual Wait/reaping")
			}
			if tc.mode == "ignore" {
				status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
				if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
					t.Fatal("forced-stop fixture was not actually killed and reaped")
				}
			}
		})
	}
}

func TestManagerUnexpectedExitIsFault(t *testing.T) {
	cmd := startManagerStopChild(t, "clean")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- superviseManager(ctx, cmd, time.Second) }()
	if err := cmd.Process.Signal(syscall.SIGUSR1); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		cancel()
		if err != fail("manager_stopped") || cmd.ProcessState == nil || !cmd.ProcessState.Success() {
			t.Fatalf("unexpected zero exit was not retained as a fault: %v", err)
		}
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("unexpected manager exit was not observed")
	}
}

func TestManagerObservedExitWinsConcurrentCancellation(t *testing.T) {
	cmd := startManagerStopChild(t, "clean")
	observation := observeManager(cmd)
	if err := cmd.Process.Signal(syscall.SIGUSR1); err != nil {
		t.Fatal(err)
	}
	select {
	case <-observation.done:
	case <-time.After(5 * time.Second):
		t.Fatal("actual manager Wait did not finish")
	}
	if cmd.ProcessState == nil || !cmd.ProcessState.Success() {
		t.Fatal("fixture did not produce an actual unexpected zero exit")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Both cases are positively ready. Whichever select case wins, an already
	// observed process fault must precede operator cancellation and remain sticky.
	for range 100 {
		err := observation.waitForStop(ctx, time.Second, func(os.Signal) error {
			t.Fatal("observed manager exit attempted a new signal")
			return syscall.EPERM
		})
		if err != fail("manager_stopped") {
			t.Fatalf("concurrent cancellation erased actual manager failure: %v", err)
		}
	}
}

func TestManagerStopSignalFailureKillsAndReaps(t *testing.T) {
	cmd := startManagerStopChild(t, "clean")
	observation := observeManager(cmd)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	signalAttempted := false
	// Model a denied TERM syscall. Kill and Wait still operate on a real child;
	// this is error-path verification, not a sandbox permission observation.
	err := observation.waitForStop(ctx, time.Second, func(signal os.Signal) error {
		if signal != syscall.SIGTERM {
			t.Fatal("manager stop used an unexpected signal")
		}
		signalAttempted = true
		return syscall.EPERM
	})
	if !signalAttempted || err != fail("manager_stop_signal") || cmd.ProcessState == nil {
		t.Fatalf("signal failure was lost or returned without reaping: %v", err)
	}
	status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatal("failed-signal fixture was not actually killed and reaped")
	}
}
