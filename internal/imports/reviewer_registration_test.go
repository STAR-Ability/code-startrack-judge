// SPDX-License-Identifier: Apache-2.0

package imports_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/imports"
	"github.com/STAR-Ability/code-startrack-judge/internal/packages"
	problemstore "github.com/STAR-Ability/code-startrack-judge/internal/persistence/problems"
	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
	"github.com/STAR-Ability/code-startrack-judge/internal/runtime/restclient"
	"github.com/STAR-Ability/code-startrack-judge/internal/storage"
	"github.com/STAR-Ability/code-startrack-judge/internal/testutil/postgres"
	"github.com/STAR-Ability/code-startrack-judge/internal/validation"
)

// This fixture exercises registration only. Its inert package and synthetic
// report are never executed and do not qualify an execution environment.
type reviewRegistrationValidator struct{ failed bool }

func (v reviewRegistrationValidator) Validate(ctx context.Context, request validation.Request) (validation.Report, error) {
	event := judgeruntime.ValidationEvidence{Kind: "REFERENCE", Case: judgeruntime.ProgramCaseEvidence{SourceSHA256: strings.Repeat("a", 64), Ordinal: 1, Passed: !v.failed, Verdict: contract.VerdictAC, Status: restclient.Accepted}}
	if err := request.RecordEvidence(ctx, event); err != nil {
		return validation.Report{}, err
	}
	line, _ := json.Marshal(event)
	digest := sha256.Sum256(append(line, '\n'))
	part := validation.Checkpoint{Passed: true, Evidence: []validation.Evidence{{Check: "SYNTHETIC_REGISTRATION_FIXTURE", Summary: "Inert reviewer registration fixture; no execution proof."}}}
	result := validation.Report{Status: "PASSED", Context: validation.Context{ProblemtoolsVersion: "synthetic-reviewer", AdapterVersion: packages.AdapterVersion, ToolchainVersion: "synthetic-reviewer", ImageDigest: "sha256:" + strings.Repeat("b", 64), ConfigSHA256: strings.Repeat("c", 64), SourceSHA256: request.Candidate.SourceSHA256, NormalizedSHA256: request.Candidate.NormalizedSHA256}, Results: validation.Results{Structure: part, Statement: part, TestData: part, Validators: part, ReferenceSolutions: part}, Errors: contract.Array[contract.TaskError]{}, Adaptations: request.Candidate.Manifest.Adaptations, RawLog: []byte("PRIVATE_REVIEW_REGISTRATION_LOG"), ProgramEvidenceSHA256: hex.EncodeToString(digest[:]), ProgramEvidenceCount: 1, StartedAt: time.Now().Add(-time.Second), FinishedAt: time.Now()}
	if v.failed {
		result.Status = "FAILED"
		result.Results.ReferenceSolutions.Passed = false
		result.Errors = contract.Array[contract.TaskError]{{Code: "PRIVATE_REVIEW_FAILURE", Message: "PRIVATE_REVIEW_ERROR_DETAIL"}}
	}
	return result, nil
}

func reviewRegistrationPipeline(t *testing.T, db postgres.Database, failed bool) (*imports.ImportPipeline, *storage.Registry) {
	t.Helper()
	pipeline, registry, _ := reviewRegistrationPipelineWithStore(t, db, failed)
	return pipeline, registry
}

func reviewRegistrationPipelineWithStore(t *testing.T, db postgres.Database, failed bool) (*imports.ImportPipeline, *storage.Registry, *storage.Store) {
	t.Helper()
	source := &fixedSource{snapshot: candidateSource()}
	store, err := storage.New(filepath.Join(t.TempDir(), "private"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	registry, err := storage.NewRegistry(db.Runtime, store)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := packages.Adapt(packages.PinnedSource("problems/private"), source.snapshot.Files)
	if err != nil {
		t.Fatal(err)
	}
	license, _ := contract.NewUUID()
	if _, err := db.Admin.Exec(`INSERT INTO judge.license_evidence(id,repository_url,source_revision,package_path,status,license_scope,notice,source_url,license_files,evidence,reviewed_by,reviewed_at)
VALUES($1,$2,$3,'problems/private','VERIFIED','PACKAGE','Synthetic reviewer authority fixture','https://github.com/oj-lab/problem-packages','[{"path":"LICENSE","sha256":"fixture","spdxId":null}]',jsonb_build_object('policy','ADMIN_HUMAN_OFFLINE_V1','sourceSha256',$4::text),'ADMIN:synthetic',clock_timestamp())`, string(license), packages.RepositoryURL, packages.PinnedRevision, candidate.SourceSHA256); err != nil {
		t.Fatal("cannot insert synthetic preapproved registration fixture")
	}
	pipeline, err := imports.NewPipeline(imports.PipelineOptions{DB: db.Runtime, Source: source, Registry: registry, Problems: problemstore.New(db.Runtime, registry), Validation: reviewRegistrationValidator{failed}})
	if err != nil {
		t.Fatal(err)
	}
	return pipeline, registry, store
}

func TestReviewSuccessfulRegistrationReplayPreservesQualificationAndDraft(t *testing.T) {
	db := postgres.New(t)
	pipeline, registry := reviewRegistrationPipeline(t, db, false)
	var initialVersion, initialSelection string
	for attempt := 0; attempt < 2; attempt++ {
		repo, job := acceptedJob(t, db.Runtime, []string{"problems/private"})
		lease, err := repo.Claim(context.Background())
		if err != nil || lease == nil {
			t.Fatal("cannot claim synthetic reviewer import")
		}
		prepared, err := pipeline.Prepare(context.Background(), *lease, lease.Items[0])
		if err != nil || prepared == nil {
			t.Fatal("cannot prepare synthetic registration report", err)
		}
		if err := repo.CompleteItem(context.Background(), *lease, lease.Items[0], prepared); err != nil {
			t.Fatal("cannot atomically retain successful registration", err)
		}
		finished, err := repo.Get(context.Background(), job.ImportJobID)
		if err != nil || finished.Items[0].Status != "VALIDATED" || finished.Items[0].ProblemVersionID == nil {
			t.Fatal("successful registration was not projected")
		}
		version := string(*finished.Items[0].ProblemVersionID)
		var selection string
		if err := db.Runtime.QueryRow(`SELECT validation_run_id::text FROM judge.package_artifacts`).Scan(&selection); err != nil {
			t.Fatal("successful report was not selected")
		}
		if attempt == 0 {
			initialVersion, initialSelection = version, selection
		} else if initialVersion != version || initialSelection != selection {
			t.Fatal("repeat import rewrote version or qualification selection")
		}
		public, _ := json.Marshal(finished)
		if bytes.Contains(public, []byte("PRIVATE_")) || bytes.Contains(public, []byte("sha256/")) {
			t.Fatal("private registration evidence entered public import DTO")
		}
	}
	var artifacts, versions, runs, tests, references, drafts, stages int
	for query, destination := range map[string]*int{
		`SELECT count(*) FROM judge.package_artifacts`:       &artifacts,
		`SELECT count(*) FROM judge.problem_versions`:        &versions,
		`SELECT count(*) FROM judge.package_validation_runs`: &runs,
		`SELECT count(*) FROM judge.problem_test_cases`:      &tests,
		`SELECT count(*) FROM judge.reference_solutions`:     &references,
		`SELECT count(*) FROM judge.platform_problems WHERE status='DRAFT' AND current_version_id IS NULL AND latest_version_id IS NOT NULL`: &drafts,
		`SELECT count(*) FROM judge.private_object_stages`: &stages,
	} {
		if db.Runtime.QueryRow(query).Scan(destination) != nil {
			t.Fatal("cannot inspect immutable reviewer registration facts")
		}
	}
	if artifacts != 1 || versions != 1 || runs != 2 || tests != 2 || references != 1 || drafts != 1 || stages != 0 {
		t.Fatalf("registration/replay invariant failed: artifacts=%d versions=%d runs=%d tests=%d refs=%d drafts=%d stages=%d", artifacts, versions, runs, tests, references, drafts, stages)
	}
	if removed, err := registry.Collect(context.Background(), time.Now().Add(time.Hour), 100); err != nil || removed != 0 {
		t.Fatal("GC deleted successful immutable registration inputs")
	}
}

func TestReviewFailedValidationRetainsPrivateJournalAndNoProblem(t *testing.T) {
	db := postgres.New(t)
	pipeline, registry := reviewRegistrationPipeline(t, db, true)
	repo, job := acceptedJob(t, db.Runtime, []string{"problems/private"})
	lease, err := repo.Claim(context.Background())
	if err != nil || lease == nil {
		t.Fatal("cannot claim rejected synthetic reviewer import")
	}
	prepared, err := pipeline.Prepare(context.Background(), *lease, lease.Items[0])
	if err != nil || prepared == nil {
		t.Fatal("cannot prepare rejected synthetic reviewer report", err)
	}
	if err := repo.CompleteItem(context.Background(), *lease, lease.Items[0], prepared); err != nil {
		t.Fatal("failed validation private evidence was not retained", err)
	}
	finished, err := repo.Get(context.Background(), job.ImportJobID)
	if err != nil || finished.Items[0].Status != "REJECTED" || finished.Items[0].ValidationStatus != "FAILED" {
		t.Fatal("failed validation was not projected safely")
	}
	public, _ := json.Marshal(finished)
	if bytes.Contains(public, []byte("PRIVATE_")) || bytes.Contains(public, []byte("sha256/")) {
		t.Fatal("private rejection evidence entered public DTO")
	}
	var facts, chunks, preserved int
	if db.Runtime.QueryRow(`SELECT (SELECT count(*) FROM judge.platform_problems)+(SELECT count(*) FROM judge.package_artifacts)+(SELECT count(*) FROM judge.problem_versions)+(SELECT count(*) FROM judge.package_validation_runs)`).Scan(&facts) != nil || facts != 0 {
		t.Fatal("failed validation invented qualification or problem history")
	}
	if db.Runtime.QueryRow(`SELECT count(*) FROM judge.private_object_references WHERE owner_type='REJECTED' AND role='EVIDENCE_LOG'`).Scan(&chunks) != nil || chunks != 1 {
		t.Fatal("failed validation journal chunk has no immutable rejection owner")
	}
	if _, err := registry.Collect(context.Background(), time.Now().Add(time.Hour), 100); err != nil {
		t.Fatal("cannot collect unrelated failed-validation stages")
	}
	if db.Runtime.QueryRow(`SELECT count(*) FROM judge.private_objects o JOIN judge.private_object_references r ON r.object_key=o.object_key WHERE r.owner_type='REJECTED'`).Scan(&preserved) != nil || preserved != 4 {
		t.Fatal("GC lost failure source/normalized/report/journal evidence")
	}
	rows, err := db.Runtime.Query(`SELECT o.object_key,o.sha256::text,o.size_bytes FROM judge.private_objects o JOIN judge.private_object_references r ON r.object_key=o.object_key WHERE r.owner_type='REJECTED'`)
	if err != nil {
		t.Fatal("cannot inspect retained rejected evidence objects")
	}
	defer rows.Close()
	for rows.Next() {
		var object storage.Object
		if rows.Scan(&object.Key, &object.SHA256, &object.SizeBytes) != nil || registry.Verify(context.Background(), object) != nil {
			t.Fatal("retained rejected evidence lost exact durable private bytes")
		}
	}
	if rows.Err() != nil {
		t.Fatal("cannot finish checking retained rejected evidence objects")
	}
}
