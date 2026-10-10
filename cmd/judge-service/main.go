// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/config"
	"github.com/STAR-Ability/code-startrack-judge/internal/processguard"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	if err := processguard.Harden(); err != nil {
		slog.Error("judge service stopped", "code", "PROCESS_HARDENING_UNAVAILABLE")
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		// Driver, network and configuration errors may contain credentials or paths.
		// Keep normal diagnostics bounded until restricted error reporting is wired.
		slog.Error("judge service stopped", "code", "SERVICE_START_FAILED")
		os.Exit(1)
	}
}

func run(ctx context.Context) (runErr error) {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	db, err := sql.Open("pgx", cfg.DatabaseURL())
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(30 * time.Minute)

	workersContext, cancelWorkers := context.WithCancel(ctx)
	defer cancelWorkers()
	app, err := newApplication(workersContext, cfg, db, slog.Default())
	if err != nil {
		return err
	}
	defer app.close()
	workerErrors, waitWorkers := app.startWorkers(workersContext)
	defer func() {
		cancelWorkers()
		if workerErr := waitWorkers(); runErr == nil && workerErr != nil {
			runErr = workerErr
		}
	}()
	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           app.handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 * 1024,
		ErrorLog:          slog.NewLogLogger(slog.Default().Handler(), slog.LevelError),
		BaseContext:       func(net.Listener) context.Context { return workersContext },
	}
	stopped := make(chan error, 1)
	go func() { stopped <- server.ListenAndServe() }()
	select {
	case err := <-stopped:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case err := <-workerErrors:
		cancelWorkers()
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}
