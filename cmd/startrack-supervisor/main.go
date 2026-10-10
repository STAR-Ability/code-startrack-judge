package main

import (
	"context"
	"fmt"
	"github.com/STAR-Ability/code-startrack-judge/internal/processguard"
	"os"
	"os/signal"
	"syscall"

	"github.com/STAR-Ability/code-startrack-judge/internal/supervisor"
)

func main() {
	if processguard.Harden() != nil {
		fmt.Fprintln(os.Stderr, "PROCESS_HARDENING_UNAVAILABLE")
		os.Exit(1)
	}
	if len(os.Args) == 2 && os.Args[1] == "--process-boundary-peer" {
		if err := supervisor.ProcessBoundaryPeer(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "supervisor arguments failure")
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := supervisor.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
