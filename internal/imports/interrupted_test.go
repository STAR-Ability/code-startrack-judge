// SPDX-License-Identifier: Apache-2.0

package imports_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/imports"
	problemstore "github.com/STAR-Ability/code-startrack-judge/internal/persistence/problems"
	"github.com/STAR-Ability/code-startrack-judge/internal/storage"
	"github.com/STAR-Ability/code-startrack-judge/internal/testutil/postgres"
	"github.com/STAR-Ability/code-startrack-judge/internal/validation"
)

type interruptedValidator struct{}

func (interruptedValidator) Validate(ctx context.Context, request validation.Request) (validation.Report, error) {
	report, err := (reviewRegistrationValidator{}).Validate(ctx, request)
	if err != nil {
		return report, err
	}
	report.Status, report.FinishedAt = "RUNNING", time.Time{}
	report.ProgramEvidenceSHA256, report.ProgramEvidenceCount = "", 0
	report.RawLog = []byte("PRIVATE_INTERRUPTED_STDERR_CANARY")
	return report, errors.New("PRIVATE_TRANSPORT_DIAGNOSTIC_CANARY")
}

func TestInterruptedAttemptRetainsPrefixWithoutCompletingOrQualifying(t *testing.T) {
	db := postgres.New(t)
	_, registry := reviewRegistrationPipeline(t, db, false)
	pipeline, err := imports.NewPipeline(imports.PipelineOptions{DB: db.Runtime, Source: &fixedSource{snapshot: candidateSource()}, Registry: registry, Problems: problemstore.New(db.Runtime, registry), Validation: interruptedValidator{}})
	if err != nil {
		t.Fatal(err)
	}
	repo, job := acceptedJob(t, db.Runtime, []string{"problems/private"})
	for attempt := 0; attempt < 2; attempt++ {
		lease, err := repo.Claim(context.Background())
		if err != nil || lease == nil {
			t.Fatal("cannot reserve interrupted import")
		}
		before, err := repo.Get(context.Background(), job.ImportJobID)
		if err != nil {
			t.Fatal(err)
		}
		prepared, validationErr := pipeline.Prepare(context.Background(), *lease, lease.Items[0])
		if prepared == nil || validationErr == nil {
			t.Fatal("interruption failed to return its private evidence and error")
		}
		if err := repo.CompleteItem(context.Background(), *lease, lease.Items[0], prepared); !errors.Is(err, imports.ErrUnavailable) {
			t.Fatal("incomplete evidence could complete an item", err)
		}
		if err := repo.RetainAttempt(context.Background(), *lease, lease.Items[0], prepared); err != nil {
			t.Fatal("live incomplete evidence was not retained", err)
		}
		after, err := repo.Get(context.Background(), job.ImportJobID)
		beforeJSON, _ := json.Marshal(before)
		afterJSON, _ := json.Marshal(after)
		if err != nil || !bytes.Equal(beforeJSON, afterJSON) || after.Items[0].Status != "PENDING" || bytes.Contains(afterJSON, []byte("PRIVATE_")) {
			t.Fatal("private attempt audit changed public import facts")
		}
		var audits, facts int
		if db.Runtime.QueryRow(`SELECT count(*) FROM judge.import_attempt_evidence WHERE provenance->'complete'='false'::jsonb AND (provenance->>'programEvidenceCount')::int=1 AND length(provenance->>'programEvidenceSha256')=64`).Scan(&audits) != nil || audits != attempt+1 {
			t.Fatal("actual event prefix or multiple immutable attempts were lost")
		}
		if db.Runtime.QueryRow(`SELECT (SELECT count(*) FROM judge.platform_problems)+(SELECT count(*) FROM judge.package_artifacts)+(SELECT count(*) FROM judge.problem_versions)+(SELECT count(*) FROM judge.package_validation_runs)`).Scan(&facts) != nil || facts != 0 {
			t.Fatal("interrupted attempt invented qualification facts")
		}
		if _, err := db.Admin.Exec(`UPDATE judge.import_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, job.ImportJobID); err != nil {
			t.Fatal("cannot simulate interrupted reservation expiry")
		}
		if err := repo.RetainAttempt(context.Background(), *lease, lease.Items[0], prepared); !errors.Is(err, imports.ErrLeaseLost) {
			t.Fatal("expired owner could append attempt evidence", err)
		}
	}
	if _, err := registry.Collect(context.Background(), time.Now().Add(time.Hour), 100); err != nil {
		t.Fatal("cannot collect unrelated stages", err)
	}
	rows, err := db.Runtime.Query(`SELECT DISTINCT o.object_key,o.sha256::text,o.size_bytes FROM judge.private_objects o JOIN judge.private_object_references r ON r.object_key=o.object_key WHERE r.owner_type='IMPORT_ATTEMPT'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var object storage.Object
		if rows.Scan(&object.Key, &object.SHA256, &object.SizeBytes) != nil || registry.Verify(context.Background(), object) != nil {
			t.Fatal("GC lost incomplete original/report/prefix bytes")
		}
		count++
	}
	if rows.Err() != nil || count < 4 {
		t.Fatal("incomplete attempt private object ownership was not durable")
	}
}
