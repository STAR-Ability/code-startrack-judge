package imports

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	domain "github.com/STAR-Ability/code-startrack-judge/internal/imports"
	testpg "github.com/STAR-Ability/code-startrack-judge/internal/testutil/postgres"
)

func request(t *testing.T, paths ...string) (contract.ImportRequest, string) {
	t.Helper()
	id, err := contract.NewUUID()
	if err != nil {
		t.Fatal("UUID unavailable")
	}
	r := contract.ImportRequest{RequestID: id, Source: "OJ_LAB", RepositoryURL: contract.PackageRepository, Revision: "cd416d900bab657acdcd96d77b629efa02cae8d4", PackagePaths: paths}
	raw, _ := json.Marshal(r)
	hash, err := canonical.RequestHash("IMPORT", nil, raw)
	if err != nil {
		t.Fatal("cannot hash fixture")
	}
	return r, hash
}

type rejection struct{}

func (rejection) Apply(_ context.Context, _ *sql.Tx, item domain.PendingItem) (domain.ItemResult, error) {
	return domain.ItemResult{
		Item:     contract.ImportItem{PackagePath: item.PackagePath, Status: "REJECTED", LicenseStatus: "MISSING", ValidationStatus: "PENDING", Errors: contract.Array[contract.TaskError]{{Code: "PACKAGE_LICENSE_MISSING", Message: "Package rights require ADMIN review", Retryable: false}}},
		Evidence: &domain.RejectedEvidence{FailureStage: "LICENSE_REVIEW", Provenance: map[string]any{"fixture": true}, SourceMetadata: map[string]any{}, Adaptations: []any{}, Errors: contract.Array[contract.TaskError]{{Code: "PACKAGE_LICENSE_MISSING", Message: "Package rights require ADMIN review", Retryable: false}}},
	}, nil
}

func TestPostgresAdmissionConcurrencyOrderedReplayAndConflict(t *testing.T) {
	db := testpg.New(t)
	r := New(db.Runtime)
	ctx := context.Background()
	req, hash := request(t, "problems/two", "problems/one")
	var wg sync.WaitGroup
	var mu sync.Mutex
	created := 0
	ids := map[contract.UUID]bool{}
	failures := 0
	for range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			job, first, err := r.Accept(ctx, req, hash)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failures++
				return
			}
			if first {
				created++
			}
			ids[job.ImportJobID] = true
			if job.Items[0].PackagePath != "problems/two" || job.Items[1].PackagePath != "problems/one" {
				failures++
			}
		}()
	}
	wg.Wait()
	if failures != 0 || created != 1 || len(ids) != 1 {
		t.Fatalf("admission concurrency: failures=%d created=%d identities=%d", failures, created, len(ids))
	}
	other := req
	other.PackagePaths = contract.Array[string]{"problems/changed"}
	raw, _ := json.Marshal(other)
	changedHash, _ := canonical.RequestHash("IMPORT", nil, raw)
	if _, _, err := r.Accept(ctx, other, changedHash); !errors.Is(err, domain.ErrConflict) {
		t.Fatal("different normalized body reused accepted identity")
	}
	job, foundHash, err := r.FindByRequest(ctx, req.RequestID)
	if err != nil || foundHash != hash || job.Revision != 1 || job.Status != contract.ImportQueued {
		t.Fatal("accepted frozen job was not recoverable")
	}
	var count int
	if db.Admin.QueryRow(`SELECT count(*) FROM judge.import_jobs`).Scan(&count) != nil || count != 1 {
		t.Fatal("duplicate jobs survived")
	}
}

func TestPostgresLeasesAtomicRejectionAndTerminalHistory(t *testing.T) {
	db := testpg.New(t)
	r := New(db.Runtime)
	ctx := context.Background()
	req, hash := request(t, "problems/two", "problems/one")
	job, _, err := r.Accept(ctx, req, hash)
	if err != nil {
		t.Fatal("accept failed")
	}
	lease, err := r.Claim(ctx)
	if err != nil || lease == nil || len(lease.Items) != 2 {
		t.Fatal("job not claimed")
	}
	if next, err := r.Claim(ctx); err != nil || next != nil {
		t.Fatal("live job claimed twice")
	}
	before, _ := r.Get(ctx, job.ImportJobID)
	if r.Heartbeat(ctx, *lease) != nil {
		t.Fatal("heartbeat failed")
	}
	after, _ := r.Get(ctx, job.ImportJobID)
	if before.Revision != after.Revision || before.UpdatedAt != after.UpdatedAt {
		t.Fatal("heartbeat changed public facts")
	}
	if err := r.CompleteItem(ctx, *lease, lease.Items[0], rejection{}); err != nil {
		t.Fatal("rejection and evidence did not commit")
	}
	progress, err := r.Get(ctx, job.ImportJobID)
	if err != nil || progress.CompletedPackageCount != 1 || progress.Status != contract.ImportRunning || progress.Items[0].Status != "REJECTED" {
		t.Fatal("ordered partial progress wrong")
	}
	if _, err := db.Admin.Exec(`UPDATE judge.import_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, job.ImportJobID); err != nil {
		t.Fatal("cannot expire synthetic lease")
	}
	if err := r.CompleteItem(ctx, *lease, lease.Items[1], rejection{}); !errors.Is(err, domain.ErrLeaseLost) {
		t.Fatal("expired worker committed before recovery")
	}
	recovered, err := r.Claim(ctx)
	if err != nil || recovered == nil || recovered.Token == lease.Token || len(recovered.Items) != 1 || recovered.Items[0].Ordinal != 2 {
		t.Fatal("recovery lost committed item or reused fence")
	}
	if err := r.Heartbeat(ctx, *lease); !errors.Is(err, domain.ErrLeaseLost) {
		t.Fatal("stale heartbeat renewed lease")
	}
	if err := r.CompleteItem(ctx, *recovered, recovered.Items[0], rejection{}); err != nil {
		t.Fatal("recovered rejection failed")
	}
	final, err := r.Get(ctx, job.ImportJobID)
	if err != nil || final.Status != contract.ImportFailed || final.FinishedAt == nil || final.CompletedPackageCount != 2 || final.Error == nil {
		t.Fatal("terminal summary invalid")
	}
	var evidence int
	if db.Admin.QueryRow(`SELECT count(*) FROM judge.rejected_package_evidence`).Scan(&evidence) != nil || evidence != 2 {
		t.Fatal("rejection evidence lost or duplicated")
	}
	if _, err := db.Runtime.Exec(`UPDATE judge.import_jobs SET status='QUEUED',revision=revision+1,finished_at=NULL,error=NULL WHERE id=$1`, job.ImportJobID); err == nil {
		t.Fatal("terminal job regressed")
	}
	if _, err := db.Runtime.Exec(`UPDATE judge.rejected_package_evidence SET provenance='{}'`); err == nil {
		t.Fatal("retained evidence changed")
	}
	replay, created, err := r.Accept(ctx, req, hash)
	if err != nil || created || replay.Status != contract.ImportFailed {
		t.Fatal("terminal import replay did not return current durable state")
	}
}

func TestPostgresFourReservationsThenRetainedExhaustion(t *testing.T) {
	db := testpg.New(t)
	r := New(db.Runtime)
	ctx := context.Background()
	req, hash := request(t, "problems/example")
	job, _, err := r.Accept(ctx, req, hash)
	if err != nil {
		t.Fatal("accept failed")
	}
	lease, err := r.Claim(ctx)
	if err != nil || lease == nil {
		t.Fatal("initial claim failed")
	}
	var firstStart string
	if db.Admin.QueryRow(`SELECT started_at::text FROM judge.import_jobs WHERE id=$1`, job.ImportJobID).Scan(&firstStart) != nil {
		t.Fatal("cannot read first execution")
	}
	for recovery := 1; recovery <= 3; recovery++ {
		if _, err := db.Admin.Exec(`UPDATE judge.import_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, job.ImportJobID); err != nil {
			t.Fatal("cannot expire lease")
		}
		next, err := r.Claim(ctx)
		if err != nil || next == nil || next.Token == lease.Token {
			t.Fatal("fresh recovery reservation missing")
		}
		lease = next
		var attempts int
		var start string
		if db.Admin.QueryRow(`SELECT attempt_count,started_at::text FROM judge.import_jobs WHERE id=$1`, job.ImportJobID).Scan(&attempts, &start) != nil || attempts != recovery || start != firstStart {
			t.Fatal("recovery budget or first start changed")
		}
	}
	if _, err := db.Admin.Exec(`UPDATE judge.import_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, job.ImportJobID); err != nil {
		t.Fatal("cannot expire last reservation")
	}
	if next, err := r.Claim(ctx); err != nil || next != nil {
		t.Fatal("fifth execution reservation was permitted")
	}
	final, err := r.Get(ctx, job.ImportJobID)
	if err != nil || final.Status != contract.ImportFailed || final.Revision != 6 || final.Items[0].Errors[0].Code != "IMPORT_INTERRUPTED" {
		t.Fatal("exhaustion evidence or terminal revision missing")
	}
}
