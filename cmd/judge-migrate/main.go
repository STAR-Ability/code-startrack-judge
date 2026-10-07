// judge-migrate exposes only forward application and read-only status.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/persistence/migrate"
	"github.com/STAR-Ability/code-startrack-judge/migrations"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 || (os.Args[1] != "up" && os.Args[1] != "status") {
		return fmt.Errorf("usage: judge-migrate {up|status} [-ceiling N]")
	}
	command := os.Args[1]
	flags := flag.NewFlagSet("judge-migrate "+command, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	ceiling := flags.Int("ceiling", 0, "apply through this release's forward ceiling (0 means highest)")
	if err := flags.Parse(os.Args[2:]); err != nil {
		return fmt.Errorf("invalid migration command flags")
	}
	if flags.NArg() != 0 || (command == "status" && *ceiling != 0) {
		return fmt.Errorf("unexpected migration arguments")
	}
	files, err := migrate.Load(migrations.Files)
	if err != nil {
		return err
	}
	dsn := os.Getenv("JUDGE_MIGRATION_DATABASE_URL")
	if dsn == "" {
		return fmt.Errorf("JUDGE_MIGRATION_DATABASE_URL is required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	db, err := migrate.Open(ctx, dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	var status migrate.Status
	if command == "up" {
		status, err = migrate.Apply(ctx, db, files, *ceiling)
	} else {
		status, err = migrate.Inspect(ctx, db, files)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(status)
}
