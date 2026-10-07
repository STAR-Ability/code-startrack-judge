// SPDX-License-Identifier: Apache-2.0

package imports_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/imports"
	"github.com/STAR-Ability/code-startrack-judge/internal/packages"
	problemstore "github.com/STAR-Ability/code-startrack-judge/internal/persistence/problems"
	"github.com/STAR-Ability/code-startrack-judge/internal/storage"
	"github.com/STAR-Ability/code-startrack-judge/internal/testutil/postgres"
	"github.com/STAR-Ability/code-startrack-judge/internal/validation"
)

type detailBudgetForbiddenValidator struct{ calls atomic.Int32 }

func (v *detailBudgetForbiddenValidator) Validate(context.Context, validation.Request) (validation.Report, error) {
	v.calls.Add(1)
	return validation.Report{}, errors.New("public projection must be rejected before execution")
}

// Actual PostgreSQL and private archive retention are exercised. The package is
// inert, and its disposable ADMIN approval is synthetic: neither execution nor
// human rights review is qualified by this fixture.
func TestPostgresOversizedEscapedDetailRetainsApprovedImportRejection(t *testing.T) {
	db := postgres.New(t)
	ctx := context.Background()
	const packagePath = "problems/detail-budget"
	snapshot := candidateSource()
	for i := range snapshot.Files {
		switch snapshot.Files[i].Path {
		case "data/sample/a.in":
			snapshot.Files[i].Data = bytes.Repeat([]byte{'<'}, 3<<20)
		case "data/sample/a.ans":
			snapshot.Files[i].Data = bytes.Repeat([]byte{'&'}, 3<<20)
		}
	}
	candidate, err := packages.Adapt(packages.PinnedSource(packagePath), snapshot.Files)
	if err != nil || candidate == nil || !candidate.ManifestReady || len(candidate.Samples) != 1 {
		t.Fatal("moderate escaped sample fixture must satisfy the structural package protocol")
	}
	encodedSamples, err := json.Marshal(candidate.Samples)
	if err != nil || int64(len(encodedSamples)) <= contract.MaxResultBytes || len(candidate.Samples[0].Input)+len(candidate.Samples[0].Output) != 6<<20 {
		t.Fatal("fixture must exceed the response ceiling only after actual JSON escaping")
	}
	encodedSamples = nil
	store, err := storage.New(filepath.Join(t.TempDir(), "private"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	registry, err := storage.NewRegistry(db.Runtime, store)
	if err != nil {
		t.Fatal(err)
	}
	validator := &detailBudgetForbiddenValidator{}
	pipeline, err := imports.NewPipeline(imports.PipelineOptions{DB: db.Runtime, Source: &fixedSource{snapshot: snapshot}, Registry: registry, Problems: problemstore.New(db.Runtime, registry), Validation: validator})
	if err != nil {
		t.Fatal(err)
	}
	var initialCatalog, initialCatalogTime string
	if err := db.Runtime.QueryRow(`SELECT catalog_version::text,updated_at::text FROM judge.catalog_state`).Scan(&initialCatalog, &initialCatalogTime); err != nil {
		t.Fatal("cannot record catalog before rejected imports")
	}
	var firstEvidence, collectedLicense, firstEvidenceJSON string
	var approval contract.UUID
	for phase := 0; phase < 2; phase++ {
		if phase == 1 {
			approval, err = contract.NewUUID()
			if err != nil {
				t.Fatal(err)
			}
			// The exact source and normalized hashes scope this synthetic approval.
			// Proper license-file identities keep it eligible for the normal guard.
			files, err := json.Marshal([]map[string]any{{"path": "repository/LICENSE", "sha256": canonical.HashBytes(snapshot.RepositoryLicenses[0].Data), "spdxId": nil}})
			if err != nil {
				t.Fatal(err)
			}
			evidence, err := json.Marshal(map[string]any{"policy": "ADMIN_HUMAN_OFFLINE_V1", "sourceSha256": candidate.SourceSHA256, "normalizedSha256": candidate.NormalizedSHA256, "syntheticDisposableFixture": true})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Admin.Exec(`INSERT INTO judge.license_evidence(id,repository_url,source_revision,package_path,previous_evidence_id,status,license_scope,notice,source_url,license_files,evidence,reviewed_by,reviewed_at)
 VALUES($1,$2,$3,$4,$5,'VERIFIED','REPOSITORY_INHERITED','Synthetic disposable detail budget fixture',$6,$7::jsonb,$8::jsonb,'ADMIN:synthetic-detail-budget',clock_timestamp())`, string(approval), packages.RepositoryURL, packages.PinnedRevision, packagePath, collectedLicense, packages.RepositoryURL+"/tree/"+packages.PinnedRevision+"/"+packagePath, string(files), string(evidence)); err != nil {
				t.Fatal("cannot insert exact-source synthetic approval", err)
			}
		}
		repo, accepted := acceptedJob(t, db.Runtime, []string{packagePath})
		lease, err := repo.Claim(ctx)
		if err != nil || lease == nil || len(lease.Items) != 1 {
			t.Fatal("cannot reserve the retained import regression")
		}
		prepared, err := pipeline.Prepare(ctx, *lease, lease.Items[0])
		if err != nil || prepared == nil {
			t.Fatal("cannot prepare the structured import rejection", err)
		}
		if err := repo.CompleteItem(ctx, *lease, lease.Items[0], prepared); err != nil {
			t.Fatal("cannot atomically retain the structured import rejection", err)
		}
		finished, err := repo.Get(ctx, accepted.ImportJobID)
		if err != nil || finished.Status != contract.ImportFailed || finished.PackageCount != 1 || finished.CompletedPackageCount != 1 || finished.FinishedAt == nil || len(finished.Items) != 1 {
			t.Fatal("rejected package did not produce a complete failed import")
		}
		stage, code, licenseStatus, validationStatus := "LICENSE_REVIEW", "PACKAGE_LICENSE_MISSING", "REVIEW_REQUIRED", "PENDING"
		if phase == 1 {
			stage, code, licenseStatus, validationStatus = "UNSUPPORTED", "PACKAGE_UNSUPPORTED", "VERIFIED", "FAILED"
		}
		item := finished.Items[0]
		diagnostic, ok := imports.PublicDiagnostic(code)
		if !ok || item.PackagePath != packagePath || item.Status != "REJECTED" || item.LicenseStatus != licenseStatus || item.ValidationStatus != validationStatus || item.ProblemID != nil || item.ProblemVersionID != nil || len(item.Errors) != 1 || item.Errors[0] != diagnostic {
			t.Fatalf("phase %d lost its bounded rejection code, rights state, or empty registration identities", phase)
		}
		public, err := json.Marshal(finished)
		if err != nil {
			t.Fatal(err)
		}
		for _, canary := range []string{"PRIVATE_", "sha256/", "input_validators", "\\u003c\\u003c", "\\u0026\\u0026"} {
			if bytes.Contains(public, []byte(canary)) {
				t.Fatal("private rejection content entered the bounded import DTO")
			}
		}
		var evidenceID, retainedStage, retainedLicense, sourceHash, normalizedHash, retainedJSON string
		var logKey *string
		if err := db.Runtime.QueryRow(`SELECT id::text,failure_stage,license_evidence_id::text,source_sha256::text,normalized_sha256::text,validation_log_key,to_jsonb(e)::text FROM judge.rejected_package_evidence e WHERE import_item_id=$1`, string(lease.Items[0].ID)).Scan(&evidenceID, &retainedStage, &retainedLicense, &sourceHash, &normalizedHash, &logKey, &retainedJSON); err != nil || retainedStage != stage || sourceHash != candidate.SourceSHA256 || normalizedHash != candidate.NormalizedSHA256 || logKey != nil {
			t.Fatal("rejection lost its exact archive identities or invented technical evidence", err)
		}
		if phase == 0 {
			firstEvidence, collectedLicense, firstEvidenceJSON = evidenceID, retainedLicense, retainedJSON
		} else if retainedLicense != string(approval) {
			t.Fatal("unsupported rejection did not retain the exact approved license evidence")
		}
		if validator.calls.Load() != 0 {
			t.Fatal("unsupported or unapproved package reached technical validation")
		}
		var archiveCount int
		if err := db.Runtime.QueryRow(`SELECT count(*) FROM judge.private_objects`).Scan(&archiveCount); err != nil || archiveCount != 2 {
			t.Fatal("rejected import staged content beyond the shared source and normalized archives")
		}
		for _, table := range []string{"platform_problems", "package_artifacts", "problem_versions", "package_validation_runs", "problem_test_cases", "reference_solutions", "import_attempt_evidence", "catalog_snapshots", "catalog_snapshot_items", "private_object_stages"} {
			var count int
			if err := db.Runtime.QueryRow(`SELECT count(*) FROM judge.` + table).Scan(&count); err != nil || count != 0 {
				t.Fatalf("phase %d created %s state before eligibility: count=%d queryFailed=%t", phase, table, count, err != nil)
			}
		}
		var catalog, catalogTime string
		if err := db.Runtime.QueryRow(`SELECT catalog_version::text,updated_at::text FROM judge.catalog_state`).Scan(&catalog, &catalogTime); err != nil || catalog != initialCatalog || catalogTime != initialCatalogTime {
			t.Fatal("rejected import mutated the public catalog")
		}
	}
	var history string
	if err := db.Runtime.QueryRow(`SELECT to_jsonb(e)::text FROM judge.rejected_package_evidence e WHERE id=$1`, firstEvidence).Scan(&history); err != nil || history != firstEvidenceJSON {
		t.Fatal("approved retry rewrote the original license-review rejection history")
	}
	if removed, err := registry.Collect(ctx, time.Now().Add(time.Hour), 100); err != nil || removed != 0 {
		t.Fatal("GC removed immutable rejected package archives")
	}
	rows, err := db.Runtime.Query(`SELECT r.role,o.object_key,o.sha256::text,o.size_bytes FROM judge.private_object_references r JOIN judge.private_objects o ON o.object_key=r.object_key WHERE r.owner_type='REJECTED' ORDER BY r.owner_id,r.role`)
	if err != nil {
		t.Fatal("cannot inspect retained rejected archives after GC")
	}
	defer rows.Close()
	counts := map[string]int{}
	for rows.Next() {
		var role string
		var object storage.Object
		if err := rows.Scan(&role, &object.Key, &object.SHA256, &object.SizeBytes); err != nil {
			t.Fatal("cannot inspect immutable archive bytes after GC")
		}
		wantHash, wantSize := candidate.SourceSHA256, int64(len(candidate.SourceArchive))
		if role == "NORMALIZED" {
			wantHash, wantSize = candidate.NormalizedSHA256, int64(len(candidate.NormalizedArchive))
		} else if role != "SOURCE" {
			t.Fatal("rejection retained normalized files or technical logs before validation")
		}
		if object.SHA256 != wantHash || object.SizeBytes != wantSize || registry.Verify(ctx, object) != nil {
			t.Fatal("retained rejection archive lost exact bytes or hashes after GC")
		}
		counts[role]++
	}
	if rows.Err() != nil || counts["SOURCE"] != 2 || counts["NORMALIZED"] != 2 {
		t.Fatal("both structured rejections must retain both immutable archives")
	}
}
