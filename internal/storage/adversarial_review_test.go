package storage_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/storage"
)

func TestReviewStageRenewCannotCrossDeadlineWhileWaitingForRowLock(t *testing.T) {
	f := lifecycle(t)
	f.db.Admin.SetMaxOpenConns(4)
	ctx := context.Background()
	object := blob(t, "synthetic staged validation bytes")
	stage, err := f.registry.StageImmutable(ctx, strings.NewReader("synthetic staged validation bytes"), object)
	if err != nil {
		t.Fatal(err)
	}
	execFixture(t, f.db.Admin, `UPDATE judge.private_object_stages SET expires_at=clock_timestamp()+interval '2 seconds' WHERE id=$1`, string(stage.RegistrationID))
	lock, err := f.db.Admin.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal("cannot start independent stage row-lock holder")
	}
	defer lock.Rollback()
	var id string
	if err := lock.QueryRowContext(ctx, `SELECT id::text FROM judge.private_object_stages WHERE id=$1 FOR UPDATE`, string(stage.RegistrationID)).Scan(&id); err != nil {
		t.Fatal("cannot lock synthetic object stage")
	}
	renewCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- f.registry.Renew(renewCtx, stage) }()
	// Observe the real database lock wait before crossing the deadline. The
	// tuple stays unchanged, exposing predicates evaluated before lock waiting.
	deadline := time.Now().Add(time.Second)
	blocked := false
	for time.Now().Before(deadline) {
		if err := f.db.Admin.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%judge.private_object_stages%')`).Scan(&blocked); err != nil {
			t.Fatal("cannot inspect live stage-renewal lock wait")
		}
		if blocked {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !blocked {
		t.Fatal("renewal never reached the independent stage row lock")
	}
	if _, err := lock.ExecContext(ctx, `SELECT pg_sleep(2.1)`); err != nil {
		t.Fatal("cannot cross synthetic stage deadline")
	}
	if err := lock.Rollback(); err != nil {
		t.Fatal("cannot release synthetic stage row lock")
	}
	if err := <-result; !errors.Is(err, storage.ErrStageLost) {
		t.Fatal("expired stage resurrected after waiting for its row lock")
	}
	var expired bool
	if f.db.Admin.QueryRowContext(ctx, `SELECT expires_at<=clock_timestamp() FROM judge.private_object_stages WHERE id=$1`, string(stage.RegistrationID)).Scan(&expired) != nil || !expired {
		t.Fatal("rejected renewal changed the expired stage deadline")
	}
	if n, err := f.registry.Collect(ctx, time.Now().Add(time.Hour), 100); err != nil || n != 1 {
		t.Fatalf("expired abandoned stage was not collected: %d %v", n, err)
	}
}

func TestReviewImmutableAttachmentWithoutOwnerRollsBackStageConsumption(t *testing.T) {
	f := lifecycle(t)
	ctx := context.Background()
	object := blob(t, "synthetic rejected package archive")
	stage, err := f.registry.StageImmutable(ctx, strings.NewReader("synthetic rejected package archive"), object)
	if err != nil {
		t.Fatal(err)
	}
	ownerID, err := contract.NewUUID()
	if err != nil {
		t.Fatal("cannot allocate synthetic evidence owner")
	}
	tx, err := f.db.Runtime.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal("cannot start synthetic object registration")
	}
	defer tx.Rollback()
	// A matching key is insufficient: the deferred constraint must require a
	// real immutable business owner in this same registration transaction.
	if err := f.registry.AttachImmutable(ctx, tx, stage, "REJECTED", ownerID, "SOURCE"); err != nil {
		t.Fatal("cannot exercise deferred object-owner check")
	}
	if err := tx.Commit(); err == nil {
		t.Fatal("private reference committed without matching evidence owner")
	}
	var stageRetained, orphanReference bool
	if err := f.db.Admin.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM judge.private_object_stages WHERE id=$1),EXISTS(SELECT 1 FROM judge.private_object_references WHERE owner_id=$2)`, string(stage.RegistrationID), string(ownerID)).Scan(&stageRetained, &orphanReference); err != nil {
		t.Fatal("cannot inspect failed registration atomicity")
	}
	if !stageRetained || orphanReference {
		t.Fatal("failed registration consumed its stage or retained a false owner")
	}
	if n, err := f.registry.Collect(ctx, time.Now().Add(time.Hour), 100); err != nil || n != 0 {
		t.Fatalf("failed registration lost live staged bytes: %d %v", n, err)
	}
	if err := f.store.Verify(ctx, object); err != nil {
		t.Fatal("failed registration altered retained staged bytes")
	}
	if err := f.registry.Release(ctx, stage); err != nil {
		t.Fatal(err)
	}
	if n, err := f.registry.Collect(ctx, time.Now().Add(time.Hour), 100); err != nil || n != 1 {
		t.Fatalf("released failed-registration debris was not collected: %d %v", n, err)
	}
}
