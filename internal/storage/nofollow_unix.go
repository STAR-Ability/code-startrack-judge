//go:build linux || darwin

package storage

import "syscall"

const noFollow = syscall.O_NOFOLLOW
