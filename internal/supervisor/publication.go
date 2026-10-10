package supervisor

import (
	"errors"
	"os"
	"sync"
)

var errQualificationRevoked = errors.New("supervisor qualification publication revoked")

// Only the last rename of a fully checked measurement consults revoked. Probe
// and cleanup errors must still be reported after publication has been revoked.
type qualificationPublication struct {
	mu      sync.Mutex
	path    string
	revoked bool
	fatal   error
	failed  chan struct{}
	stopped chan struct{}
	rename  func(string, string) error
	remove  func(string) error
}

func newQualificationPublication(path string) *qualificationPublication {
	return &qualificationPublication{path: path, failed: make(chan struct{}), stopped: make(chan struct{}), rename: os.Rename, remove: os.Remove}
}

func (p *qualificationPublication) failLocked(err error) {
	if err != nil && p.fatal == nil {
		p.fatal = err
		close(p.failed)
	}
	p.revokeLocked()
}

func (p *qualificationPublication) revokeLocked() {
	if !p.revoked {
		p.revoked = true
		close(p.stopped)
	}
	if err := p.remove(p.path); err != nil && !errors.Is(err, os.ErrNotExist) && p.fatal == nil {
		p.fatal = fail("measurement_revoke")
		close(p.failed)
	}
}

func (p *qualificationPublication) reject(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failLocked(err)
}

func (p *qualificationPublication) revoke() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.revokeLocked()
	return p.fatal
}

func (p *qualificationPublication) failure() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.fatal
}

func (p *qualificationPublication) publish(temporary string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fatal != nil {
		return p.fatal
	}
	if p.revoked {
		return errQualificationRevoked
	}
	if p.rename(temporary, p.path) != nil {
		p.failLocked(fail("measurement_write"))
		return p.fatal
	}
	return nil
}

// This check is the scheduling admission point. Revoke serializes against it:
// an admitted probe finishes its full checks, but no later probe can start.
func (p *qualificationPublication) admitProbe() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.revoked && p.fatal == nil
}

func (p *qualificationPublication) acceptProbeResult(err error) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err == errQualificationRevoked && p.revoked && p.fatal == nil {
		return true
	}
	if err != nil {
		p.failLocked(err)
		return false
	}
	return p.fatal == nil
}
