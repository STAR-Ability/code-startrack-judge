//go:build linux

// Package processguard protects credential-bearing trusted process memory.
package processguard

import (
	"errors"
	"syscall"
)

// Harden must run in the final executable, before credentials are consumed.
// Execve resets a launcher's setting. This never certifies sandbox isolation.
func Harden() error {
	if _, _, errno := syscall.Syscall(syscall.SYS_PRCTL, 4, 0, 0); errno != 0 {
		return errors.New("process hardening unavailable")
	}
	value, _, errno := syscall.Syscall(syscall.SYS_PRCTL, 3, 0, 0)
	if errno != 0 || value != 0 {
		return errors.New("process hardening unavailable")
	}
	return nil
}
