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
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := supervisor.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
