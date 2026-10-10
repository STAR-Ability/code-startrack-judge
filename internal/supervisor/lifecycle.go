//go:build linux || darwin

package supervisor

import (
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

type childDiagnostics struct {
	done  <-chan struct{}
	close func()
}

type componentChild struct {
	cmd      *exec.Cmd
	name     string
	exited   chan struct{}
	settled  chan struct{}
	waitErr  error // Read only after exited closes.
	expected bool  // Protected by qualificationPublication.mu.
}

// Cmd.Wait reports process death independently of diagnostic EOF. A descendant
// holding a pipe cannot delay fatal publication withdrawal or hide exit status.
func monitorComponent(cmd *exec.Cmd, name string, p *qualificationPublication, diagnostics *childDiagnostics, settlement time.Duration) *componentChild {
	c := &componentChild{cmd: cmd, name: name, exited: make(chan struct{}), settled: make(chan struct{})}
	go func() {
		c.waitErr = cmd.Wait()
		p.mu.Lock()
		if !c.expected || c.waitErr != nil || cmd.ProcessState == nil || !cmd.ProcessState.Success() {
			p.failLocked(fail(name + "_stopped"))
		}
		close(c.exited)
		p.mu.Unlock()
		if diagnostics != nil {
			timer := time.NewTimer(settlement)
			select {
			case <-diagnostics.done:
			case <-timer.C:
				p.reject(fail("runtime_diagnostics_settlement"))
				diagnostics.close()
				<-diagnostics.done
			}
			timer.Stop()
		}
		close(c.settled)
	}()
	return c
}

func (p *qualificationPublication) terminate(c *componentChild) {
	p.mu.Lock()
	defer p.mu.Unlock()
	select {
	case <-c.exited:
		return
	default:
	}
	c.expected = true
	if c.cmd.Process.Signal(syscall.SIGTERM) != nil {
		p.failLocked(fail(c.name + "_stop_signal"))
	}
}

// A single allowance covers all components. Forced termination remains fatal,
// and every owned child is waited/reaped before diagnostic/accounting closure.
func stopComponents(children []*componentChild, p *qualificationPublication, allowance, killGrace time.Duration) bool {
	for _, child := range children {
		p.terminate(child)
	}
	timer := time.NewTimer(allowance)
	defer timer.Stop()
	forced := false
	for _, child := range children {
		select {
		case <-child.exited:
			continue
		case <-timer.C:
			forced = true
		}
		break
	}
	if forced {
		p.reject(fail("component_stop_deadline"))
		for _, child := range children {
			select {
			case <-child.exited:
			default:
				if err := child.cmd.Process.Kill(); err != nil && err != os.ErrProcessDone {
					p.reject(fail("component_kill"))
				}
			}
		}
	}
	deadline := time.NewTimer(killGrace)
	defer deadline.Stop()
	for _, child := range children {
		select {
		case <-child.settled:
		case <-deadline.C:
			p.reject(fail("component_reap_settlement"))
			return false
		}
	}
	return true
}

func diagnosticsCloser(files ...*os.File) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			for _, file := range files {
				file.Close()
			}
		})
	}
}
