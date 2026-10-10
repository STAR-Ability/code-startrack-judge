// judge-outbox is a trusted operator tool, not an HTTP callback or task API.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/callbacks"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/persistence/migrate"
	"github.com/STAR-Ability/code-startrack-judge/internal/persistence/outbox"
	"github.com/STAR-Ability/code-startrack-judge/internal/processguard"
)

func main() {
	if processguard.Harden() != nil {
		fmt.Fprintln(os.Stderr, "PROCESS_HARDENING_UNAVAILABLE")
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Getenv, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, getenv func(string) string, stdout io.Writer) error {
	if len(args) < 1 || (args[0] != "list" && args[0] != "redeliver") {
		return errors.New("usage: judge-outbox {list|redeliver} [flags]")
	}
	command := args[0]
	flags := flag.NewFlagSet("judge-outbox", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var limit int
	var after, event, operator, reason string
	if command == "list" {
		flags.IntVar(&limit, "limit", 100, "maximum rows (1..100)")
		flags.StringVar(&after, "after-event", "", "exclusive event UUID cursor")
	} else {
		flags.StringVar(&event, "event", "", "retained dead-letter event UUID")
		flags.StringVar(&operator, "operator", "", "auditable operator reference")
		flags.StringVar(&reason, "reason", "", "MAPPING_RECONCILED, AUTH_RESTORED, TRANSPORT_RESTORED or CONFLICT_RESOLVED")
	}
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return callbacks.ErrInvalid
	}
	dsn := getenv("JUDGE_OUTBOX_DATABASE_URL")
	if dsn == "" {
		return errors.New("JUDGE_OUTBOX_DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	db, err := migrate.Open(ctx, dsn)
	if err != nil {
		return callbacks.ErrPersistence
	}
	defer db.Close()
	repo, err := outbox.New(db)
	if err != nil {
		return err
	}
	if command == "list" {
		var cursor *contract.UUID
		if after != "" {
			id := contract.UUID(after)
			cursor = &id
		}
		rows, err := repo.ListDeadLetters(ctx, limit, cursor)
		if err != nil {
			return err
		}
		if json.NewEncoder(stdout).Encode(rows) != nil {
			return errors.New("cannot write retained event list")
		}
		return nil
	}
	// Validate the outbound credential before reserving a manual action, so a
	// missing credential is not recorded as a fictional network delivery.
	client, err := callbacks.NewClient(getenv("JUDGE_BACKEND_TOKEN"))
	if err != nil {
		return err
	}
	defer client.Close()
	d, replayID, err := repo.ClaimReplay(ctx, contract.UUID(event), operator, outbox.ReplayReason(reason))
	if err != nil {
		return err
	}
	outcome := client.Send(ctx, d)
	if err := repo.Complete(ctx, d, outcome); err != nil {
		return err
	}
	result := struct {
		EventID   contract.UUID  `json:"eventId"`
		ReplayID  contract.UUID  `json:"replayId"`
		Accepted  bool           `json:"accepted"`
		Duplicate bool           `json:"duplicate"`
		ErrorCode callbacks.Code `json:"errorCode"`
	}{d.EventID, replayID, outcome.Accepted, outcome.Duplicate, outcome.ErrorCode}
	if json.NewEncoder(stdout).Encode(result) != nil {
		return errors.New("cannot write redelivery result")
	}
	if !outcome.Accepted {
		return errors.New("callback remains retained dead letter")
	}
	return nil
}
