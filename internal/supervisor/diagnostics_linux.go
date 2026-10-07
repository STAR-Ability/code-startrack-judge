//go:build linux

package supervisor

import (
	"os"
	"syscall"
)

func openPrivateLog(path string, owner uint32) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, fail("runtime_diagnostics")
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fail("runtime_diagnostics")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Uid != owner || st.Nlink != 1 {
		f.Close()
		return nil, fail("runtime_diagnostics_permissions")
	}
	if f.Truncate(0) != nil {
		f.Close()
		return nil, fail("runtime_diagnostics")
	}
	return f, nil
}
