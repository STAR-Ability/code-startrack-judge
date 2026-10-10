//go:build !linux

package processguard

// Portable API development has no Linux sandbox qualification. The Linux-only
// measurement verifier remains mandatory for every real execution capability.
func Harden() error { return nil }
