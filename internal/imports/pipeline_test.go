// SPDX-License-Identifier: Apache-2.0

package imports_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/imports"
	"github.com/STAR-Ability/code-startrack-judge/internal/packages"
	importstore "github.com/STAR-Ability/code-startrack-judge/internal/persistence/imports"
	problemstore "github.com/STAR-Ability/code-startrack-judge/internal/persistence/problems"
	"github.com/STAR-Ability/code-startrack-judge/internal/storage"
	"github.com/STAR-Ability/code-startrack-judge/internal/testutil/postgres"
	"github.com/STAR-Ability/code-startrack-judge/internal/validation"
)

type fixedSource struct {
	snapshot imports.SourceSnapshot
	err      error
	calls    int
}

func (s *fixedSource) Acquire(context.Context, string, string) (imports.SourceSnapshot, error) {
	s.calls++
	return s.snapshot, s.err
}

type forbiddenValidator struct{ t *testing.T }

func (v forbiddenValidator) Validate(context.Context, validation.Request) (validation.Report, error) {
	v.t.Error("unapproved package reached execution")
	return validation.Report{}, errors.New("forbidden")
}

func candidateSource() imports.SourceSnapshot {
	return imports.SourceSnapshot{Files: []packages.File{
		{Path: "problem.yaml", Data: []byte("name: Private fixture\n")},
		{Path: ".timelimit", Data: []byte("1\n")},
		{Path: "problem_statement/problem.md", Data: []byte("Public statement\n")},
		{Path: "data/sample/a.in", Data: []byte("public\n")}, {Path: "data/sample/a.ans", Data: []byte("public answer\n")},
		{Path: "data/secret/b.in", Data: []byte("PRIVATE_HIDDEN_INPUT_CANARY\n")}, {Path: "data/secret/b.ans", Data: []byte("PRIVATE_ANSWER_CANARY\n")},
		{Path: "input_validators/check.py", Data: []byte("inert private validator")},
		{Path: "submissions/accepted/main.cpp", Data: []byte("PRIVATE_REFERENCE_CANARY")},
	}, RepositoryLicenses: []packages.File{{Path: "LICENSE", Data: []byte("Private synthetic license requiring human coverage review.")}}}
}

func pipelineFixture(t *testing.T, db *sql.DB, source imports.Source) (*imports.ImportPipeline, *storage.Registry) {
	t.Helper()
	store, err := storage.New(filepath.Join(t.TempDir(), "private"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	registry, err := storage.NewRegistry(db, store)
	if err != nil {
		t.Fatal(err)
	}
	pipeline, err := imports.NewPipeline(imports.PipelineOptions{DB: db, Source: source, Registry: registry, Problems: problemstore.New(db, registry), Validation: forbiddenValidator{t}})
	if err != nil {
		t.Fatal(err)
	}
	return pipeline, registry
}

func acceptedJob(t *testing.T, db *sql.DB, paths []string) (*importstore.Repository, contract.ImportJob) {
	t.Helper()
	repo := importstore.New(db)
	requestID, err := contract.NewUUID()
	if err != nil {
		t.Fatal(err)
	}
	service := imports.New(repo, func(context.Context) bool { return true })
	job, created, err := service.Submit(context.Background(), contract.ImportRequest{RequestID: requestID, Source: "OJ_LAB", RepositoryURL: packages.RepositoryURL, Revision: packages.PinnedRevision, PackagePaths: paths})
	if err != nil || !created {
		t.Fatal("cannot create isolated import job")
	}
	return repo, job
}

func TestPipelineWholeSourceFailureAndImmutableReplay(t *testing.T) {
	db := postgres.New(t)
	source := &fixedSource{err: imports.ErrSourceUnavailable}
	pipeline, _ := pipelineFixture(t, db.Runtime, source)
	repo, job := acceptedJob(t, db.Runtime, []string{"problems/a", "problems/b"})
	lease, err := repo.Claim(context.Background())
	if err != nil || lease == nil {
		t.Fatal("cannot reserve import")
	}
	for _, item := range lease.Items {
		prepared, err := pipeline.Prepare(context.Background(), *lease, item)
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.CompleteItem(context.Background(), *lease, item, prepared); err != nil {
			t.Fatal(err)
		}
	}
	finished, err := repo.Get(context.Background(), job.ImportJobID)
	if err != nil || finished.Status != contract.ImportFailed || source.calls != 1 || finished.CompletedPackageCount != 2 {
		t.Fatal("whole-source failure was not retained consistently")
	}
	var evidence, objects, problems int
	if db.Runtime.QueryRow(`SELECT count(*) FROM judge.rejected_package_evidence`).Scan(&evidence) != nil || db.Runtime.QueryRow(`SELECT count(*) FROM judge.private_objects`).Scan(&objects) != nil || db.Runtime.QueryRow(`SELECT count(*) FROM judge.platform_problems`).Scan(&problems) != nil || evidence != 2 || objects != 0 || problems != 0 {
		t.Fatal("source failure invented content or problem identity")
	}
}

func TestPipelineUnapprovedPackageRetainsBytesPrivatelyThroughGC(t *testing.T) {
	db := postgres.New(t)
	source := &fixedSource{snapshot: candidateSource()}
	pipeline, registry := pipelineFixture(t, db.Runtime, source)
	repo, job := acceptedJob(t, db.Runtime, []string{"problems/private"})
	lease, err := repo.Claim(context.Background())
	if err != nil || lease == nil {
		t.Fatal("cannot reserve import")
	}
	prepared, err := pipeline.Prepare(context.Background(), *lease, lease.Items[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.CompleteItem(context.Background(), *lease, lease.Items[0], prepared); err != nil {
		t.Fatal(err)
	}
	finished, err := repo.Get(context.Background(), job.ImportJobID)
	if err != nil || finished.Items[0].Status != "REJECTED" || finished.Items[0].LicenseStatus != "REVIEW_REQUIRED" {
		t.Fatal("automatic collection bypassed human review")
	}
	public, _ := json.Marshal(finished)
	for _, canary := range []string{"PRIVATE_HIDDEN_INPUT_CANARY", "PRIVATE_ANSWER_CANARY", "PRIVATE_REFERENCE_CANARY", "sha256/", "input_validators"} {
		if strings.Contains(string(public), canary) {
			t.Fatal("private package bytes leaked into import DTO")
		}
	}
	var facts, objects, refs, stages, problems int
	for query, dest := range map[string]*int{`SELECT count(*) FROM judge.license_evidence WHERE status='REVIEW_REQUIRED' AND reviewed_by IS NULL`: &facts, `SELECT count(*) FROM judge.private_objects`: &objects, `SELECT count(*) FROM judge.private_object_references WHERE owner_type='REJECTED'`: &refs, `SELECT count(*) FROM judge.private_object_stages`: &stages, `SELECT count(*) FROM judge.platform_problems`: &problems} {
		if db.Runtime.QueryRow(query).Scan(dest) != nil {
			t.Fatal("cannot inspect retained private evidence")
		}
	}
	if facts != 1 || objects != 2 || refs != 2 || stages != 0 || problems != 0 {
		t.Fatal("rejection evidence and archive retention were not atomic")
	}
	removed, err := registry.Collect(context.Background(), time.Now().Add(time.Hour), 100)
	if err != nil || removed != 0 {
		t.Fatal("GC deleted immutable rejection archives")
	}
}
