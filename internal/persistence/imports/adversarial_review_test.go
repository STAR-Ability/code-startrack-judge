package imports

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	domain "github.com/STAR-Ability/code-startrack-judge/internal/imports"
	testpg "github.com/STAR-Ability/code-startrack-judge/internal/testutil/postgres"
)

type reviewPrepared func(context.Context, *sql.Tx, domain.PendingItem) (domain.ItemResult, error)

func (f reviewPrepared) Apply(ctx context.Context, tx *sql.Tx, item domain.PendingItem) (domain.ItemResult, error) {
	return f(ctx, tx, item)
}

func reviewClaim(t *testing.T, r *Repository, paths ...string) (contract.ImportJob, domain.Lease) {
	t.Helper()
	req, hash := request(t, paths...)
	job, _, err := r.Accept(context.Background(), req, hash)
	if err != nil {
		t.Fatal("review fixture admission failed")
	}
	lease, err := r.Claim(context.Background())
	if err != nil || lease == nil {
		t.Fatal("review fixture claim failed")
	}
	return job, *lease
}

func TestReviewConcurrentClaimHasOneLiveExecutionReservation(t *testing.T) {
	db := testpg.New(t)
	r := New(db.Runtime)
	req, hash := request(t, "problems/review")
	job, _, err := r.Accept(context.Background(), req, hash)
	if err != nil {
		t.Fatal("review fixture admission failed")
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	claims, failures := 0, 0
	for range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lease, err := r.Claim(context.Background())
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failures++
			} else if lease != nil {
				claims++
				if lease.JobID != job.ImportJobID || len(lease.Items) != 1 {
					failures++
				}
			}
		}()
	}
	wg.Wait()
	if failures != 0 || claims != 1 {
		t.Fatalf("concurrent claims: reservations=%d failures=%d", claims, failures)
	}
	var attempts, revision int
	if db.Admin.QueryRow(`SELECT attempt_count,revision FROM judge.import_jobs WHERE id=$1`, job.ImportJobID).Scan(&attempts, &revision) != nil || attempts != 0 || revision != 2 {
		t.Fatal("initial concurrency consumed recovery budget or added public revisions")
	}
}

func TestReviewLeaseExpiryDuringRegistrationRollsBackAllFacts(t *testing.T) {
	db := testpg.New(t)
	r := New(db.Runtime)
	job, lease := reviewClaim(t, r, "problems/review")
	// Begin with a live lease, then cross the actual database deadline while
	// registration owns the job lock. The final fence must reject the commit.
	if _, err := db.Admin.Exec(`UPDATE judge.import_jobs SET lease_expires_at=clock_timestamp()+interval '200 milliseconds' WHERE id=$1`, job.ImportJobID); err != nil {
		t.Fatal("cannot shorten synthetic lease")
	}
	applied := false
	prepared := reviewPrepared(func(ctx context.Context, tx *sql.Tx, item domain.PendingItem) (domain.ItemResult, error) {
		applied = true
		if _, err := tx.ExecContext(ctx, `INSERT INTO judge.package_source_identities(id,repository_url,source_revision,package_path,source_sha256) VALUES('4d0c7889-6132-467f-9d57-915648989b8b',$1,$2,$3,repeat('a',64))`, contract.PackageRepository, lease.Revision, item.PackagePath); err != nil {
			return domain.ItemResult{}, err
		}
		if _, err := tx.ExecContext(ctx, `SELECT pg_sleep(0.35)`); err != nil {
			return domain.ItemResult{}, err
		}
		return rejection{}.Apply(ctx, tx, item)
	})
	if err := r.CompleteItem(context.Background(), lease, lease.Items[0], prepared); !errors.Is(err, domain.ErrLeaseLost) || !applied {
		t.Fatal("registration crossing its lease deadline was not fenced after Apply")
	}
	current, err := r.Get(context.Background(), job.ImportJobID)
	if err != nil || current.CompletedPackageCount != 0 || current.Items[0].Status != "PENDING" || current.Revision != 2 {
		t.Fatal("failed registration changed visible import facts")
	}
	var facts int
	if db.Admin.QueryRow(`SELECT (SELECT count(*) FROM judge.package_source_identities)+(SELECT count(*) FROM judge.rejected_package_evidence)`).Scan(&facts) != nil || facts != 0 {
		t.Fatal("expired registration leaked immutable source/evidence rows")
	}
	recovered, err := r.Claim(context.Background())
	if err != nil || recovered == nil || recovered.Token == lease.Token || len(recovered.Items) != 1 {
		t.Fatal("rolled-back work could not obtain a fresh recovery reservation")
	}
}

func TestReviewInvalidEvidenceRollsBackPreparedRegistration(t *testing.T) {
	db := testpg.New(t)
	r := New(db.Runtime)
	job, lease := reviewClaim(t, r, "problems/review")
	prepared := reviewPrepared(func(ctx context.Context, tx *sql.Tx, item domain.PendingItem) (domain.ItemResult, error) {
		if _, err := tx.ExecContext(ctx, `INSERT INTO judge.package_source_identities(id,repository_url,source_revision,package_path,source_sha256) VALUES('4d0c7889-6132-467f-9d57-915648989b8b',$1,$2,$3,repeat('a',64))`, contract.PackageRepository, lease.Revision, item.PackagePath); err != nil {
			return domain.ItemResult{}, err
		}
		result, err := rejection{}.Apply(ctx, tx, item)
		key := "private/review/archive"
		result.Evidence.SourceArchiveKey = &key
		// A missing paired checksum is invalid evidence, even though the staged
		// registration and public item shape were otherwise valid.
		return result, err
	})
	if err := r.CompleteItem(context.Background(), lease, lease.Items[0], prepared); err == nil {
		t.Fatal("unpaired retained object identity was accepted")
	}
	current, err := r.Get(context.Background(), job.ImportJobID)
	if err != nil || current.CompletedPackageCount != 0 || current.Items[0].Status != "PENDING" {
		t.Fatal("invalid evidence left partial terminal progress")
	}
	var facts int
	if db.Admin.QueryRow(`SELECT (SELECT count(*) FROM judge.package_source_identities)+(SELECT count(*) FROM judge.rejected_package_evidence)`).Scan(&facts) != nil || facts != 0 {
		t.Fatal("invalid evidence leaked registration outside the item transaction")
	}
	if err := r.CompleteItem(context.Background(), lease, lease.Items[0], rejection{}); err != nil {
		t.Fatal("valid deterministic retry after rolled-back registration failed")
	}
}

func TestReviewPreparedDiagnosticCannotEnterPublicImportProjection(t *testing.T) {
	db := testpg.New(t)
	r := New(db.Runtime)
	job, lease := reviewClaim(t, r, "problems/review")
	const privateDiagnostic = "hidden-answer=review-secret; /private/object; credential=review-token"
	prepared := reviewPrepared(func(ctx context.Context, tx *sql.Tx, item domain.PendingItem) (domain.ItemResult, error) {
		result, err := rejection{}.Apply(ctx, tx, item)
		result.Item.Errors[0].Message = privateDiagnostic
		result.Evidence.Errors[0].Message = privateDiagnostic
		return result, err
	})
	if err := r.CompleteItem(context.Background(), lease, lease.Items[0], prepared); err != nil {
		t.Fatal("known package failure did not produce a bounded terminal result")
	}
	current, err := r.Get(context.Background(), job.ImportJobID)
	if err != nil || len(current.Items[0].Errors) != 1 || strings.Contains(current.Items[0].Errors[0].Message, "review-secret") || strings.Contains(current.Items[0].Errors[0].Message, "review-token") || strings.Contains(current.Items[0].Errors[0].Message, "/private/") {
		t.Fatal("private preparation diagnostic entered public import facts")
	}
}

func TestReviewUnknownPreparedDiagnosticRollsBackWithoutPublicLeak(t *testing.T) {
	db := testpg.New(t)
	r := New(db.Runtime)
	job, lease := reviewClaim(t, r, "problems/review")
	prepared := reviewPrepared(func(ctx context.Context, tx *sql.Tx, item domain.PendingItem) (domain.ItemResult, error) {
		result, err := rejection{}.Apply(ctx, tx, item)
		result.Item.Errors[0].Code = "PRIVATE_OBJECT_ANSWER_VALUE"
		result.Evidence.Errors[0].Code = result.Item.Errors[0].Code
		return result, err
	})
	if err := r.CompleteItem(context.Background(), lease, lease.Items[0], prepared); err == nil {
		t.Fatal("unknown diagnostic code was accepted into terminal public facts")
	}
	current, err := r.Get(context.Background(), job.ImportJobID)
	if err != nil || current.Items[0].Status != "PENDING" || len(current.Items[0].Errors) != 0 {
		t.Fatal("unknown diagnostic failure left partial public progress")
	}
}

func TestReviewInvalidStagedRejectedOwnerIDRollsBack(t *testing.T) {
	db := testpg.New(t)
	r := New(db.Runtime)
	job, lease := reviewClaim(t, r, "problems/review")
	prepared := reviewPrepared(func(ctx context.Context, tx *sql.Tx, item domain.PendingItem) (domain.ItemResult, error) {
		if _, err := tx.ExecContext(ctx, `INSERT INTO judge.package_source_identities(id,repository_url,source_revision,package_path,source_sha256) VALUES('4d0c7889-6132-467f-9d57-915648989b8b',$1,$2,$3,repeat('a',64))`, contract.PackageRepository, lease.Revision, item.PackagePath); err != nil {
			return domain.ItemResult{}, err
		}
		result, err := rejection{}.Apply(ctx, tx, item)
		result.Evidence.ID = "invalid-staging-owner"
		return result, err
	})
	if err := r.CompleteItem(context.Background(), lease, lease.Items[0], prepared); err == nil {
		t.Fatal("invalid preallocated immutable owner identity was accepted")
	}
	current, err := r.Get(context.Background(), job.ImportJobID)
	if err != nil || current.CompletedPackageCount != 0 || current.Items[0].Status != "PENDING" {
		t.Fatal("invalid retained owner left partial public import progress")
	}
	var facts int
	if db.Admin.QueryRow(`SELECT (SELECT count(*) FROM judge.package_source_identities)+(SELECT count(*) FROM judge.rejected_package_evidence)`).Scan(&facts) != nil || facts != 0 {
		t.Fatal("invalid retained owner leaked staged registration")
	}
}

func TestReviewStoredLegacyDiagnosticIsRedactedDuringProjection(t *testing.T) {
	db := testpg.New(t)
	r := New(db.Runtime)
	job, lease := reviewClaim(t, r, "problems/review")
	// Seed a first terminal record through the database to model older persisted
	// diagnostics. This does not mutate immutable terminal history or disable ACLs.
	raw, err := json.Marshal(contract.Array[contract.TaskError]{{Code: "PACKAGE_LICENSE_MISSING", Message: "hidden-answer=legacy-secret; /private/legacy", Retryable: true}})
	if err != nil {
		t.Fatal("cannot encode synthetic historical diagnostic")
	}
	tx, err := db.Admin.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal("cannot start historical fixture transaction")
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE judge.import_items SET status='REJECTED',license_status='MISSING',errors=$2 WHERE id=$1`, lease.Items[0].ID, raw); err != nil {
		t.Fatal("cannot seed historical package failure")
	}
	if err := summarize(context.Background(), tx, job.ImportJobID); err != nil || tx.Commit() != nil {
		t.Fatal("cannot commit historical fixture summary")
	}
	current, err := r.Get(context.Background(), job.ImportJobID)
	if err != nil || len(current.Items[0].Errors) != 1 || strings.Contains(current.Items[0].Errors[0].Message, "legacy-secret") || strings.Contains(current.Items[0].Errors[0].Message, "/private/") || current.Items[0].Errors[0].Retryable {
		t.Fatal("older retained diagnostics bypassed safe public projection")
	}
}

func TestReviewHeartbeatCannotRenewAfterWaitingPastLeaseDeadline(t *testing.T) {
	db := testpg.New(t)
	db.Admin.SetMaxOpenConns(4)
	r := New(db.Runtime)
	job, lease := reviewClaim(t, r, "problems/review")
	if _, err := db.Admin.Exec(`UPDATE judge.import_jobs SET lease_expires_at=clock_timestamp()+interval '2 seconds' WHERE id=$1`, job.ImportJobID); err != nil {
		t.Fatal("cannot shorten synthetic lease")
	}
	lock, err := db.Admin.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal("cannot start independent row-lock holder")
	}
	defer lock.Rollback()
	var id string
	if err := lock.QueryRow(`SELECT id::text FROM judge.import_jobs WHERE id=$1 FOR UPDATE`, job.ImportJobID).Scan(&id); err != nil {
		t.Fatal("cannot lock synthetic import job")
	}
	result := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	go func() { result <- r.Heartbeat(ctx, lease) }()
	// Confirm the real heartbeat is blocked in PostgreSQL before crossing its
	// deadline. A lock file or goroutine intent alone would not prove this race.
	deadline := time.Now().Add(time.Second)
	blocked := false
	for time.Now().Before(deadline) {
		if err := db.Admin.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%judge.import_jobs%')`).Scan(&blocked); err != nil {
			t.Fatal("cannot inspect live heartbeat lock wait")
		}
		if blocked {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !blocked {
		t.Fatal("heartbeat never reached the independent job lock")
	}
	if _, err := lock.Exec(`SELECT pg_sleep(2.1)`); err != nil {
		t.Fatal("cannot cross synthetic lease deadline")
	}
	// Release without updating the tuple: predicates evaluated before the wait
	// must not authorize a renewal at the later database clock.
	if err := lock.Rollback(); err != nil {
		t.Fatal("cannot release synthetic job lock")
	}
	if err := <-result; !errors.Is(err, domain.ErrLeaseLost) {
		t.Fatal("heartbeat renewed an expired lease after its row-lock wait")
	}
	var stillExpired bool
	if db.Admin.QueryRow(`SELECT lease_expires_at<=clock_timestamp() FROM judge.import_jobs WHERE id=$1`, job.ImportJobID).Scan(&stillExpired) != nil || !stillExpired {
		t.Fatal("expired lease deadline changed during rejected heartbeat")
	}
}
