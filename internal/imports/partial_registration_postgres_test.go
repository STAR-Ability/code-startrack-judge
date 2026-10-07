// SPDX-License-Identifier: Apache-2.0

package imports_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/imports"
	"github.com/STAR-Ability/code-startrack-judge/internal/packages"
	"github.com/STAR-Ability/code-startrack-judge/internal/testutil/postgres"
)

// Actual PostgreSQL, private objects, lease fencing, and registration are used.
// The source and validator are inert fixtures; this is no execution or rights proof.
func TestPostgresMixedImportRecoversValidatedDraftAndFinishesPartial(t *testing.T) {
	db := postgres.New(t)
	ctx := context.Background()
	pipeline, registry := reviewRegistrationPipeline(t, db, false)
	paths := []string{"problems/private", "problems/unapproved"}
	repo, accepted := acceptedJob(t, db.Runtime, paths)
	lease, err := repo.Claim(ctx)
	if err != nil || lease == nil || len(lease.Items) != 2 || lease.Items[0].PackagePath != paths[0] {
		t.Fatal("cannot reserve the mixed import")
	}
	validated, err := pipeline.Prepare(ctx, *lease, lease.Items[0])
	if err != nil || validated == nil {
		t.Fatal("cannot prepare the approved synthetic package")
	}
	if err := repo.CompleteItem(ctx, *lease, lease.Items[0], validated); err != nil {
		t.Fatal("cannot register the first validated draft")
	}
	progress, err := repo.Get(ctx, accepted.ImportJobID)
	if err != nil || progress.Status != "RUNNING" || progress.PackageCount != 2 || progress.CompletedPackageCount != 1 || progress.FinishedAt != nil || progress.Error != nil || progress.Items[0].Status != "VALIDATED" || progress.Items[0].ProblemVersionID == nil || progress.Items[1].Status != "PENDING" {
		t.Fatal("mixed import progress lost the committed draft or counted a pending item")
	}
	version := *progress.Items[0].ProblemVersionID
	// Simulate a worker loss between items. Recovery must prepare only the pending
	// package and must not replay, overwrite, or publish the committed version.
	if _, err := db.Admin.Exec(`UPDATE judge.import_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, string(accepted.ImportJobID)); err != nil {
		t.Fatal("cannot expire the isolated worker reservation")
	}
	recovered, err := repo.Claim(ctx)
	if err != nil || recovered == nil || recovered.JobID != lease.JobID || recovered.Token == lease.Token || len(recovered.Items) != 1 || recovered.Items[0].PackagePath != paths[1] {
		t.Fatal("recovery did not preserve completed work and fence the old owner")
	}
	rejected, err := pipeline.Prepare(ctx, *recovered, recovered.Items[0])
	if err != nil || rejected == nil {
		t.Fatal("cannot prepare the unapproved package rejection")
	}
	if err := repo.CompleteItem(ctx, *lease, recovered.Items[0], rejected); !errors.Is(err, imports.ErrLeaseLost) {
		t.Fatal("expired worker could complete a recovered item")
	}
	if err := repo.CompleteItem(ctx, *recovered, recovered.Items[0], rejected); err != nil {
		t.Fatal("cannot retain the mixed import rejection")
	}
	finished, err := repo.Get(ctx, accepted.ImportJobID)
	if err != nil || finished.Status != "PARTIAL" || finished.PackageCount != 2 || finished.CompletedPackageCount != 2 || finished.FinishedAt == nil || finished.Error == nil || finished.Error.Code != "PACKAGE_INVALID" || finished.Error.Retryable || finished.Items[0].ProblemVersionID == nil || *finished.Items[0].ProblemVersionID != version || finished.Items[0].Status != "VALIDATED" || finished.Items[1].Status != "REJECTED" || finished.Items[1].LicenseStatus != "REVIEW_REQUIRED" || finished.Items[1].ProblemID != nil || finished.Items[1].ProblemVersionID != nil || len(finished.Items[1].Errors) == 0 {
		t.Fatal("mixed outcomes did not produce a safe terminal PARTIAL job")
	}
	service := imports.New(repo, func(context.Context) bool { return false })
	replayed, created, err := service.Submit(ctx, contract.ImportRequest{RequestID: accepted.RequestID, Source: "OJ_LAB", RepositoryURL: packages.RepositoryURL, Revision: packages.PinnedRevision, PackagePaths: paths})
	want, _ := json.Marshal(finished)
	got, _ := json.Marshal(replayed)
	if err != nil || created || !bytes.Equal(want, got) {
		t.Fatal("terminal mixed import replay changed its frozen facts or required readiness")
	}
	for _, canary := range []string{"PRIVATE_", "sha256/", "input_validators", "lease_owner", "lease_expires_at"} {
		if bytes.Contains(want, []byte(canary)) {
			t.Fatal("mixed import leaked private evidence or worker scheduling state")
		}
	}
	var drafts, versions, artifacts, runs, rejectedOwners int
	var catalog string
	for query, destination := range map[string]*int{
		`SELECT count(*) FROM judge.platform_problems WHERE status='DRAFT' AND current_version_id IS NULL AND latest_version_id=$1`: &drafts,
		`SELECT count(*) FROM judge.problem_versions`:                                      &versions,
		`SELECT count(*) FROM judge.package_artifacts`:                                     &artifacts,
		`SELECT count(*) FROM judge.package_validation_runs`:                               &runs,
		`SELECT count(*) FROM judge.private_object_references WHERE owner_type='REJECTED'`: &rejectedOwners,
	} {
		var args []any
		if destination == &drafts {
			args = []any{string(version)}
		}
		if db.Runtime.QueryRow(query, args...).Scan(destination) != nil {
			t.Fatal("cannot inspect mixed import immutable registration")
		}
	}
	if db.Runtime.QueryRow(`SELECT catalog_version::text FROM judge.catalog_state`).Scan(&catalog) != nil || drafts != 1 || versions != 1 || artifacts != 1 || runs != 1 || rejectedOwners != 2 || catalog != "1" {
		t.Fatal("mixed import rewrote completed work, lost rejection evidence, or published a draft")
	}
	if removed, err := registry.Collect(ctx, time.Now().Add(time.Hour), 100); err != nil || removed != 0 {
		t.Fatal("GC removed validated or rejected mixed import evidence")
	}
}
