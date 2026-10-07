package imports

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/packages"
	problemstore "github.com/STAR-Ability/code-startrack-judge/internal/persistence/problems"
	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
	"github.com/STAR-Ability/code-startrack-judge/internal/runtime/restclient"
	"github.com/STAR-Ability/code-startrack-judge/internal/storage"
	"github.com/STAR-Ability/code-startrack-judge/internal/testutil/postgres"
	"github.com/STAR-Ability/code-startrack-judge/internal/validation"
)

func reviewJournalPipeline(t *testing.T) (*ImportPipeline, *storage.Store, postgres.Database) {
	t.Helper()
	db := postgres.New(t)
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal("cannot create private reviewer storage")
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
	return &ImportPipeline{options: PipelineOptions{DB: db.Runtime, Registry: registry, Problems: problemstore.New(db.Runtime, registry)}, sourceFailures: map[contract.UUID]error{}}, store, db
}

func reviewEvent(ordinal int) judgeruntime.ValidationEvidence {
	return judgeruntime.ValidationEvidence{Kind: "REFERENCE", Case: judgeruntime.ProgramCaseEvidence{SourceSHA256: strings.Repeat("a", 64), Ordinal: ordinal, Passed: true, Verdict: contract.VerdictAC, Status: restclient.Accepted, CPUTimeNS: 1000, WallTimeNS: 2000, MemoryBytes: 4096}}
}

func TestReviewJournalChunksPreserveExactOrderedBytesAndDigest(t *testing.T) {
	p, store, _ := reviewJournalPipeline(t)
	j := newEvidenceJournal(p)
	ctx := context.Background()
	var expected bytes.Buffer
	const count = 6000
	for ordinal := 1; ordinal <= count; ordinal++ {
		event := reviewEvent(ordinal)
		line, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		expected.Write(line)
		expected.WriteByte('\n')
		if err := j.Record(ctx, event); err != nil {
			t.Fatal("cannot retain ordered synthetic program evidence")
		}
	}
	digest := sha256.Sum256(expected.Bytes())
	if err := j.Seal(ctx, hex.EncodeToString(digest[:]), count); err != nil {
		t.Fatal("exact complete event journal was not sealed")
	}
	stages := j.Stages()
	if len(stages) < 2 || j.Count() != count {
		t.Fatal("event stream did not cross immutable chunk boundaries")
	}
	var actual bytes.Buffer
	for _, stage := range stages {
		if stage.Object.SizeBytes > evidenceChunkBytes {
			t.Fatal("private evidence chunk exceeded its bound")
		}
		data, err := store.Read(ctx, stage.Object, evidenceChunkBytes)
		if err != nil {
			t.Fatal("staged evidence chunk lost durable exact bytes")
		}
		actual.Write(data)
	}
	if !bytes.Equal(actual.Bytes(), expected.Bytes()) {
		t.Fatal("private evidence journal reordered, duplicated or lost events")
	}
	if err := j.Record(ctx, reviewEvent(count+1)); err == nil {
		t.Fatal("sealed private evidence history accepted another event")
	}
}

func TestReviewJournalReconciliationFailureRemainsLatched(t *testing.T) {
	p, _, _ := reviewJournalPipeline(t)
	for _, mismatch := range []string{"checksum", "count", "cancelled-record"} {
		t.Run(mismatch, func(t *testing.T) {
			j := newEvidenceJournal(p)
			event := reviewEvent(1)
			ctx := context.Background()
			if mismatch == "cancelled-record" {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				if err := j.Record(cancelled, event); err == nil {
					t.Fatal("cancelled private journal write succeeded")
				}
				if err := j.Seal(ctx, "", 0); err == nil {
					t.Fatal("ignored cancelled write became an empty successful journal")
				}
				return
			}
			if err := j.Record(ctx, event); err != nil {
				t.Fatal(err)
			}
			line, _ := json.Marshal(event)
			digest := sha256.Sum256(append(line, '\n'))
			correct := hex.EncodeToString(digest[:])
			checksum, count := correct, uint64(1)
			if mismatch == "checksum" {
				checksum = strings.Repeat("0", 64)
			} else {
				count++
			}
			if err := j.Seal(ctx, checksum, count); err == nil {
				t.Fatal("conflicting complete journal summary was accepted")
			}
			if err := j.Seal(ctx, correct, 1); err == nil || j.Record(ctx, event) == nil {
				t.Fatal("later valid data erased a journal reconciliation failure")
			}
		})
	}
}

type reviewPortableSource struct{ files []packages.File }

func (s reviewPortableSource) Acquire(context.Context, string, string) (SourceSnapshot, error) {
	return SourceSnapshot{Files: s.files}, nil
}

type reviewPortableValidator struct{ calls int }

func (v *reviewPortableValidator) Validate(context.Context, validation.Request) (validation.Report, error) {
	v.calls++
	part := validation.Checkpoint{Passed: true, Evidence: []validation.Evidence{{Check: "PORTABLE_CONTROL_FLOW", Summary: "Synthetic reviewer fixture; no execution proof."}}}
	return validation.Report{Status: "PORTABLE_ONLY", Results: validation.Results{Structure: part, Statement: part, TestData: part, Validators: part, ReferenceSolutions: part}, StartedAt: time.Now().Add(-time.Second), FinishedAt: time.Now()}, nil
}

func TestReviewPortableReportCannotRegisterArtifactOrValidationFacts(t *testing.T) {
	p, _, db := reviewJournalPipeline(t)
	files := []packages.File{
		{Path: "problem.yaml", Data: []byte("name: Reviewer portable fixture\n")},
		{Path: ".timelimit", Data: []byte("1\n")},
		{Path: "problem_statement/problem.md", Data: []byte("Public fixture statement\n")},
		{Path: "data/sample/a.in", Data: []byte("sample\n")}, {Path: "data/sample/a.ans", Data: []byte("answer\n")},
		{Path: "data/secret/b.in", Data: []byte("private input\n")}, {Path: "data/secret/b.ans", Data: []byte("private answer\n")},
		{Path: "input_validators/check.py", Data: []byte("inert fixture validator")},
		{Path: "submissions/accepted/main.cpp", Data: []byte("inert fixture reference")},
	}
	a, err := packages.Adapt(packages.PinnedSource("problems/reviewer-portable"), files)
	if err != nil {
		t.Fatal(err)
	}
	license, _ := contract.NewUUID()
	if _, err := db.Admin.Exec(`INSERT INTO judge.license_evidence(id,repository_url,source_revision,package_path,status,license_scope,notice,source_url,license_files,evidence,reviewed_by,reviewed_at)
VALUES($1,$2,$3,$4,'VERIFIED','PACKAGE','Synthetic reviewer authority fixture','https://github.com/oj-lab/problem-packages','[{"path":"LICENSE","sha256":"fixture","spdxId":null}]',jsonb_build_object('policy','ADMIN_HUMAN_OFFLINE_V1','sourceSha256',$5::text),'ADMIN:synthetic',clock_timestamp())`, string(license), packages.RepositoryURL, packages.PinnedRevision, "problems/reviewer-portable", a.SourceSHA256); err != nil {
		t.Fatal("cannot create synthetic preapproved transaction fixture")
	}
	p.options.Source = reviewPortableSource{files}
	v := &reviewPortableValidator{}
	p.options.Validation = v
	job, _ := contract.NewUUID()
	token, _ := contract.NewUUID()
	itemID, _ := contract.NewUUID()
	prepared, err := p.Prepare(context.Background(), Lease{JobID: job, Token: token, Revision: packages.PinnedRevision}, PendingItem{ID: itemID, PackagePath: "problems/reviewer-portable", Ordinal: 1})
	if err == nil || prepared != nil || v.calls != 1 {
		t.Fatal("portable-only control flow produced a database registration candidate")
	}
	var facts int
	if db.Admin.QueryRow(`SELECT (SELECT count(*) FROM judge.platform_problems)+(SELECT count(*) FROM judge.package_artifacts)+(SELECT count(*) FROM judge.package_validation_runs)`).Scan(&facts) != nil || facts != 0 {
		t.Fatal("portable-only report persisted problem or qualification history")
	}
}
