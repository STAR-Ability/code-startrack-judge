package problems

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/storage"
	"github.com/STAR-Ability/code-startrack-judge/internal/testutil/postgres"
)

type immutableFixture struct {
	db         postgres.Database
	repository *Repository
	registry   *storage.Registry
	store      *storage.Store
	spec       ArtifactSpec
}

func makeImmutableFixture(t *testing.T) immutableFixture {
	t.Helper()
	db := postgres.New(t)
	directory := t.TempDir()
	if os.Chmod(directory, 0700) != nil {
		t.Fatal("private fixture unavailable")
	}
	store, err := storage.New(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	registry, err := storage.NewRegistry(db.Runtime, store)
	if err != nil {
		t.Fatal(err)
	}
	repository := New(db.Runtime, registry)
	source, err := store.Put(context.Background(), strings.NewReader("source exact archive\r\n"), 100)
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := store.Put(context.Background(), strings.NewReader("normalized private archive\n"), 100)
	if err != nil {
		t.Fatal(err)
	}
	identity := Identity{"OJ_LAB", contract.PackageRepository, "problems/immutable"}
	license, _ := contract.NewUUID()
	ctx := ValidationContext{"v1.20260907", "ojlab-kattis-v0.2.1", "synthetic-compiler", "sha256:" + strings.Repeat("a", 64), strings.Repeat("b", 64), source.SHA256, normalized.SHA256}
	spec := ArtifactSpec{Identity: identity, SourceRevision: strings.Repeat("a", 40), AdapterVersion: ctx.AdapterVersion, SourceArchive: source, NormalizedArchive: normalized, Manifest: json.RawMessage(`{"testCount":1,"files":[]}`), SourceMetadata: json.RawMessage(`{"fixture":true}`), LicenseEvidenceID: license, ValidationContext: ctx}
	err = repository.WithTx(context.Background(), nil, func(tx *Tx) error {
		problem, err := tx.EnsureProblem(identity)
		if err != nil {
			return err
		}
		spec.ProblemID = problem.ID
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	fixtureExec(t, db.Admin, `INSERT INTO judge.license_evidence(id,repository_url,source_revision,package_path,status,license_scope,spdx_id,notice,source_url,license_files,evidence,reviewed_by,reviewed_at) VALUES($1,$2,$3,$4,'VERIFIED','PACKAGE','MIT','Synthetic reviewed notice','https://github.com/oj-lab/problem-packages','[{"path":"LICENSE","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","spdxId":"MIT"}]','{"syntheticOfflineReview":true}','synthetic-reviewer',now())`, string(license), identity.RepositoryURL, spec.SourceRevision, identity.PackagePath)
	return immutableFixture{db, repository, registry, store, spec}
}
func fixtureExec(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatal("isolated immutable fixture failed")
	}
}
func (f immutableFixture) register(t *testing.T, spec ArtifactSpec) (Artifact, bool, error) {
	t.Helper()
	var artifact Artifact
	var reused bool
	err := f.repository.WithTx(context.Background(), nil, func(tx *Tx) error { var err error; artifact, reused, err = tx.RegisterArtifact(spec); return err })
	return artifact, reused, err
}
func (f immutableFixture) qualified(t *testing.T) Artifact {
	t.Helper()
	var artifact Artifact
	err := f.repository.WithTx(context.Background(), nil, func(tx *Tx) error {
		var err error
		artifact, _, err = tx.RegisterArtifact(f.spec)
		if err != nil {
			return err
		}
		input, err := f.store.Put(context.Background(), strings.NewReader("1\n"), 100)
		if err != nil {
			return err
		}
		answer, err := f.store.Put(context.Background(), strings.NewReader("2\n"), 100)
		if err != nil {
			return err
		}
		reference, err := f.store.Put(context.Background(), strings.NewReader("int main(){}\n"), 100)
		if err != nil {
			return err
		}
		testID, _ := contract.NewUUID()
		referenceID, _ := contract.NewUUID()
		if err := tx.AppendTests([]TestCase{{ID: testID, PackageArtifactID: artifact.ID, Ordinal: 1, Visibility: "SECRET", Input: input, Answer: answer}}); err != nil {
			return err
		}
		if err := tx.AppendReferences([]ReferenceSolution{{ID: referenceID, PackageArtifactID: artifact.ID, Role: "ACCEPTED", LanguageID: "cpp17", Source: reference, UpstreamPath: "submissions/accepted/main.cpp"}}); err != nil {
			return err
		}
		id, _ := contract.NewUUID()
		run := ValidationRun{ID: id, PackageArtifactID: artifact.ID, Status: "PASSED", Context: f.spec.ValidationContext, Results: checkpointResults(true), Errors: []contract.TaskError{}, Adaptations: json.RawMessage(`[]`), StartedAt: time.Now().Add(-time.Second), FinishedAt: time.Now()}
		if err := tx.AppendValidation(run); err != nil {
			return err
		}
		if err := tx.SelectValidation(artifact.ID, id); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}
func checkpointResults(passed bool) json.RawMessage {
	sections := map[string]any{}
	for _, name := range []string{"structure", "statement", "testData", "validators", "referenceSolutions"} {
		sections[name] = map[string]any{"passed": passed, "evidence": []any{map[string]any{"check": "SYNTHETIC_CHECK", "subjectSha256": nil, "logObjectKey": nil, "summary": "Synthetic transaction fixture; no Linux qualification"}}}
	}
	encoded, _ := json.Marshal(sections)
	return encoded
}
func versionSpec(f immutableFixture, a Artifact) VersionSpec {
	return VersionSpec{ProblemID: f.spec.ProblemID, PackageArtifactID: a.ID, Title: "Immutable fixture", StatementFormat: "MARKDOWN", StatementContent: "Public statement", DifficultyScale: contract.DifficultyUnrated, TimeLimitMs: 1000, WallLimitMs: 2000, MemoryLimitBytes: 1 << 20, OutputLimitBytes: 1 << 20, LanguageIDs: []string{"cpp17"}, JudgeMode: "BATCH_PASS_FAIL", CheckerConfig: json.RawMessage(`{}`)}
}

func TestPostgresImmutableContentEvidenceAndProblemReuse(t *testing.T) {
	f := makeImmutableFixture(t)
	artifact, reused, err := f.register(t, f.spec)
	if err != nil || reused {
		t.Fatalf("first registration %v", err)
	}
	exact, reused, err := f.register(t, f.spec)
	if err != nil || !reused || exact.ID != artifact.ID {
		t.Fatal("exact content/evidence registration not reused")
	}
	variant := f.spec
	variant.ValidationContext.ImageDigest = "sha256:" + strings.Repeat("c", 64)
	changed, reused, err := f.register(t, variant)
	if err != nil || reused || changed.ID == artifact.ID || changed.ContentIdentityID != artifact.ContentIdentityID || changed.SourceIdentityID != artifact.SourceIdentityID {
		t.Fatal("evidence variants altered/reused wrong content identity")
	}
	for _, change := range []string{"source", "normalized", "manifest", "metadata"} {
		altered := f.spec
		switch change {
		case "source":
			altered.SourceArchive, _ = f.store.Put(context.Background(), strings.NewReader("different source"), 100)
			altered.AdapterVersion = "new-adapter"
			altered.ValidationContext.AdapterVersion = altered.AdapterVersion
			altered.ValidationContext.SourceSHA256 = altered.SourceArchive.SHA256
		case "normalized":
			altered.NormalizedArchive, _ = f.store.Put(context.Background(), strings.NewReader("different normalized"), 100)
			altered.ValidationContext.NormalizedSHA256 = altered.NormalizedArchive.SHA256
		case "manifest":
			altered.Manifest = json.RawMessage(`{"testCount":2,"files":[]}`)
		case "metadata":
			altered.SourceMetadata = json.RawMessage(`{"fixture":false}`)
		}
		if _, _, err := f.register(t, altered); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("%s identity conflict accepted: %v", change, err)
		}
	}
	var group sync.WaitGroup
	results := make(chan contract.ID, 12)
	failures := make(chan error, 12)
	for range 12 {
		group.Add(1)
		go func() {
			defer group.Done()
			var id contract.ID
			err := f.repository.WithTx(context.Background(), nil, func(tx *Tx) error { problem, err := tx.EnsureProblem(f.spec.Identity); id = problem.ID; return err })
			results <- id
			failures <- err
		}()
	}
	group.Wait()
	close(results)
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	for id := range results {
		if id != f.spec.ProblemID {
			t.Fatal("stable source identity forked")
		}
	}
	loaded, err := f.repository.LoadArtifact(context.Background(), artifact.ID)
	if err != nil || loaded.Spec.SourceArchive != f.spec.SourceArchive || loaded.ManifestSHA256 != artifact.ManifestSHA256 {
		t.Fatal("frozen artifact read drift")
	}
}

func TestPostgresVersionAllocationAndMemberHistory(t *testing.T) {
	f := makeImmutableFixture(t)
	artifact := f.qualified(t)
	spec := versionSpec(f, artifact)
	var group sync.WaitGroup
	versions := make(chan Version, 12)
	failures := make(chan error, 12)
	for index := range 12 {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			candidate := spec
			candidate.Title = fmt.Sprintf("Immutable %d", index)
			var version Version
			err := f.repository.WithTx(context.Background(), nil, func(tx *Tx) error { var err error; version, err = tx.CreateVersion(candidate); return err })
			versions <- version
			failures <- err
		}(index)
	}
	group.Wait()
	close(versions)
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	seen := map[int64]bool{}
	for version := range versions {
		if seen[version.VersionNumber] {
			t.Fatal("version number raced")
		}
		seen[version.VersionNumber] = true
	}
	for number := int64(1); number <= 12; number++ {
		if !seen[number] {
			t.Fatal("version sequence has a gap")
		}
	}
	var catalog int
	var current *string
	if err := f.db.Runtime.QueryRow(`SELECT c.catalog_version,p.current_version_id::text FROM judge.catalog_state c CROSS JOIN judge.platform_problems p WHERE p.id=$1`, string(spec.ProblemID)).Scan(&catalog, &current); err != nil || catalog != 1 || current != nil {
		t.Fatal("draft registration altered catalog/public version")
	}
	tests, err := f.repository.ListTests(context.Background(), artifact.ID)
	if err != nil || len(tests) != 1 {
		t.Fatal("private test read failed")
	}
	references, err := f.repository.ListReferences(context.Background(), artifact.ID)
	if err != nil || len(references) != 1 {
		t.Fatal("private reference read failed")
	}
	for _, query := range []string{`UPDATE judge.problem_versions SET title='rewrite' WHERE problem_id=$1`, `DELETE FROM judge.problem_versions WHERE problem_id=$1`, `UPDATE judge.problem_test_cases SET visibility='SAMPLE' WHERE package_artifact_id=$1`, `DELETE FROM judge.reference_solutions WHERE package_artifact_id=$1`} {
		argument := any(string(spec.ProblemID))
		if strings.Contains(query, "package_artifact_id") {
			argument = string(artifact.ID)
		}
		if _, err := f.db.Runtime.Exec(query, argument); err == nil {
			t.Fatal("historical immutable fact rewritten")
		}
	}
	extra := tests[0]
	extra.ID, _ = contract.NewUUID()
	extra.Ordinal = 2
	if err := f.repository.WithTx(context.Background(), nil, func(tx *Tx) error { return tx.AppendTests([]TestCase{extra}) }); err == nil {
		t.Fatal("qualified member set was extended")
	}
}

func TestPostgresValidationSelectionAndImmutableLogs(t *testing.T) {
	f := makeImmutableFixture(t)
	artifact, _, err := f.register(t, f.spec)
	if err != nil {
		t.Fatal(err)
	}
	log, err := f.store.Put(context.Background(), strings.NewReader("private synthetic log"), 100)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := contract.NewUUID()
	run := ValidationRun{ID: id, PackageArtifactID: artifact.ID, Status: "FAILED", Context: f.spec.ValidationContext, Results: checkpointResults(false), Errors: []contract.TaskError{{Code: "PACKAGE_VALIDATION_FAILED", Message: "Synthetic failure"}}, Adaptations: json.RawMessage(`[]`), Log: &log, StartedAt: time.Now().Add(-time.Second), FinishedAt: time.Now()}
	if err := f.repository.WithTx(context.Background(), nil, func(tx *Tx) error { return tx.AppendValidation(run) }); err != nil {
		t.Fatal(err)
	}
	if err := f.repository.WithTx(context.Background(), nil, func(tx *Tx) error { return tx.SelectValidation(artifact.ID, id) }); !errors.Is(err, ErrIntegrity) {
		t.Fatal("failed validation qualified artifact")
	}
	loaded, err := f.repository.LoadValidation(context.Background(), id)
	if err != nil || loaded.Log == nil || *loaded.Log != log || loaded.Status != "FAILED" {
		t.Fatal("private immutable validation read failed")
	}
	if _, err := f.db.Runtime.Exec(`UPDATE judge.package_validation_runs SET errors='[]',status='PASSED' WHERE id=$1`, string(id)); err == nil {
		t.Fatal("terminal validation mutated")
	}
	mismatched := run
	mismatched.ID, _ = contract.NewUUID()
	mismatched.Context.ImageDigest = "sha256:" + strings.Repeat("e", 64)
	mismatched.Status = "PASSED"
	mismatched.Results = checkpointResults(true)
	mismatched.Errors = []contract.TaskError{}
	if err := f.repository.WithTx(context.Background(), nil, func(tx *Tx) error { return tx.AppendValidation(mismatched) }); err != nil {
		t.Fatal("new profile audit run rejected")
	}
	if err := f.repository.WithTx(context.Background(), nil, func(tx *Tx) error { return tx.SelectValidation(artifact.ID, mismatched.ID) }); !errors.Is(err, ErrIntegrity) {
		t.Fatal("different profile qualified frozen artifact")
	}
	alteredSource := mismatched
	alteredSource.ID, _ = contract.NewUUID()
	alteredSource.Context.SourceSHA256 = strings.Repeat("f", 64)
	if err := f.repository.WithTx(context.Background(), nil, func(tx *Tx) error { return tx.AppendValidation(alteredSource) }); !errors.Is(err, ErrIntegrity) {
		t.Fatal("borrowed source validation accepted")
	}

	if n, err := f.registry.Collect(context.Background(), time.Now().Add(time.Hour), 100); err != nil || n != 0 {
		t.Fatal("accepted validation private bytes collected")
	}
}
