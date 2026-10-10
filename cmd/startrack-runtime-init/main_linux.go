//go:build linux

package main

import (
	"fmt"
	"github.com/STAR-Ability/code-startrack-judge/internal/processguard"
	"os"
	"syscall"

	"github.com/STAR-Ability/code-startrack-judge/internal/supervisor"
)

func main() {
	if processguard.Harden() != nil {
		fmt.Fprintln(os.Stderr, "PROCESS_HARDENING_UNAVAILABLE")
		os.Exit(1)
	}
	if len(os.Args) == 2 && os.Args[1] == "--manager-boundary-probe" {
		if err := supervisor.ManagerBoundaryProbe(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	status := os.NewFile(4, "supervisor-status")
	syscall.CloseOnExec(4)
	if err := supervisor.RuntimeInit(); err != nil {
		fmt.Fprintln(status, err)
		os.Exit(1)
	}
}
