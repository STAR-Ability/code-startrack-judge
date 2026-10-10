package storage_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
)

// A direct SQL registration has the ledger FK's KEY SHARE lock even when a
// future caller forgets the Registry advisory lock. Collection must wait before
// unlinking private bytes, then recheck the newly committed pin.
func TestReviewDirectStageFKPreventsUnlinkBeforeCollectorLock(t *testing.T) {
	f := lifecycle(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	data := "independent FK-locked private object"
	object := blob(t, data)
	stage, err := f.registry.StageImmutable(ctx, strings.NewReader(data), object)
	if err != nil {
		t.Fatal("cannot stage independent private object")
	}
	if err := f.registry.Release(ctx, stage); err != nil {
		t.Fatal("cannot release initial private pin")
	}
	id, err := contract.NewUUID()
	if err != nil {
		t.Fatal("cannot allocate direct SQL pin identity")
	}
	direct, err := f.db.Runtime.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal("cannot start direct SQL registration")
	}
	defer direct.Rollback()
	if _, err := direct.ExecContext(ctx, `INSERT INTO judge.private_object_stages(id,object_key,expires_at) VALUES($1,$2,clock_timestamp()+interval '1 hour')`, string(id), object.Key); err != nil {
		t.Fatal("cannot acquire private object FK lock")
	}
	type collection struct {
		count int
		err   error
	}
	result := make(chan collection, 1)
	go func() {
		n, err := f.registry.Collect(ctx, time.Now().Add(time.Hour), 100)
		result <- collection{n, err}
	}()
	deadline := time.Now().Add(2 * time.Second)
	blocked := false
	for time.Now().Before(deadline) {
		if err := f.db.Admin.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%judge.private_objects%' AND query LIKE '%FOR UPDATE%')`).Scan(&blocked); err != nil {
			t.Fatal("cannot inspect collector ledger lock wait")
		}
		if blocked {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !blocked {
		t.Fatal("collector did not lock the ledger before private unlink")
	}
	if err := f.store.Verify(ctx, object); err != nil {
		t.Fatal("collector unlinked bytes while direct FK registration was pending")
	}
	if err := direct.Commit(); err != nil {
		t.Fatal("cannot commit independent private pin")
	}
	collected := <-result
	if collected.err != nil || collected.count != 0 {
		t.Fatal("collector removed an object with a newly committed direct pin")
	}
	if err := f.store.Verify(ctx, object); err != nil {
		t.Fatal("collector failed to preserve newly pinned private bytes")
	}
}
