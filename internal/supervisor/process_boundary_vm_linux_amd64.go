//go:build linux && amd64

package supervisor

import (
	"runtime"
	"syscall"
	"unsafe"
)

// The qualified image is Linux amd64. syscall's frozen amd64 table predates
// process_vm_readv, whose Linux ABI number is 310. Other architectures fail
// closed rather than silently reusing this number.
func boundaryVMRead(pid int, address uint64) (byte, syscall.Errno) {
	var value byte
	local := syscall.Iovec{Base: &value, Len: 1}
	// An integer ABI field keeps a remote address out of Go's pointer graph.
	remote := struct{ base, length uintptr }{uintptr(address), 1}
	n, _, errno := syscall.Syscall6(310, uintptr(pid), uintptr(unsafe.Pointer(&local)), 1, uintptr(unsafe.Pointer(&remote)), 1, 0)
	runtime.KeepAlive(local)
	runtime.KeepAlive(remote)
	if errno == 0 && n != 1 {
		return 0, syscall.EIO
	}
	return value, errno
}
