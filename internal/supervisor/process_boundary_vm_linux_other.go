//go:build linux && !amd64

package supervisor

import "syscall"

func boundaryVMRead(int, uint64) (byte, syscall.Errno) { return 0, syscall.ENOSYS }
