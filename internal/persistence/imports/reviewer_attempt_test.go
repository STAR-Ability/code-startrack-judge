// SPDX-License-Identifier: Apache-2.0

package imports

import (
	"context"
	"database/sql"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	domain "github.com/STAR-Ability/code-startrack-judge/internal/imports"
	testpg "github.com/STAR-Ability/code-startrack-judge/internal/testutil/postgres"
)

func TestReviewAttemptAuditCannotStartAfterLeaseExpiredDuringRowLockWait(t *testing.T) {
	db := testpg.New(t)
	repository := New(db.Runtime)
	job, lease := reviewClaim(t, repository, "problems/review")
	if _, err := db.Admin.Exec(`UPDATE judge.import_jobs SET lease_expires_at=clock_timestamp()+interval '2 seconds' WHERE id=$1`, job.ImportJobID); err != nil {
		t.Fatal("cannot shorten synthetic attempt reservation")
	}
	lock, err := db.Admin.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal("cannot start independent attempt lock holder")
	}
	defer lock.Rollback()
	var id string
	if err := lock.QueryRow(`SELECT id::text FROM judge.import_jobs WHERE id=$1 FOR UPDATE`, job.ImportJobID).Scan(&id); err != nil {
		t.Fatal("cannot hold synthetic attempt row lock")
	}
	var applied atomic.Bool
	prepared := reviewPrepared(func(context.Context, *sql.Tx, domain.PendingItem) (domain.ItemResult, error) {
		applied.Store(true)
		return domain.ItemResult{}, domain.ErrUnavailable
	})
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- repository.RetainAttempt(ctx, lease, lease.Items[0], prepared) }()
	blocked := false
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if err := db.Admin.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%judge.import_jobs%')`).Scan(&blocked); err != nil {
			t.Fatal("cannot inspect actual attempt lock wait")
		}
		if blocked {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !blocked {
		t.Fatal("attempt audit never reached the held PostgreSQL lock")
	}
	if _, err := lock.Exec(`SELECT pg_sleep(2.1)`); err != nil {
		t.Fatal("cannot cross synthetic attempt lease deadline")
	}
	// No tuple change is made: a clock predicate evaluated before the wait
	// cannot authorize registration when the unchanged tuple becomes available.
	if err := lock.Rollback(); err != nil {
		t.Fatal("cannot release synthetic attempt lock")
	}
	if err := <-result; !errors.Is(err, domain.ErrLeaseLost) || applied.Load() {
		t.Fatal("expired waiting owner reached attempt audit registration")
	}
	current, err := repository.Get(context.Background(), job.ImportJobID)
	if err != nil || current.Revision != 2 || current.CompletedPackageCount != 0 || current.Items[0].Status != "PENDING" {
		t.Fatal("rejected stale attempt audit changed public import facts")
	}
}
