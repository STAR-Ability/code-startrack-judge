package main

import (
	"context"
	"database/sql"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/imports"
	"github.com/STAR-Ability/code-startrack-judge/internal/packages"
	"github.com/STAR-Ability/code-startrack-judge/internal/problems"
	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
	"github.com/STAR-Ability/code-startrack-judge/internal/runtime/restclient"
	"github.com/STAR-Ability/code-startrack-judge/internal/validation"
)

const acceptanceLicenseText = "Synthetic package license retained for offline receipt control-flow qualification.\n"
const acceptanceStatement = "Public acceptance statement.\n"

// Fixed source/mature/runtime mocks are available only in this Go test binary.
// Their synthetic PASSED facts belong to its disposable database and never
// authorize production execution or represent legal/sandbox qualification.
type acceptanceSource struct{}

func (acceptanceSource) Ready(context.Context) bool { return true }
func (acceptanceSource) Acquire(_ context.Context, revision, path string) (imports.SourceSnapshot, error) {
	if revision != packages.PinnedRevision || path != "problems/acceptance" {
		return imports.SourceSnapshot{}, imports.ErrSourceUnavailable
	}
	return imports.SourceSnapshot{Files: []packages.File{
		{Path: "problem.yaml", Data: []byte("name: Public acceptance\n")},
		{Path: ".timelimit", Data: []byte("1\n")},
		{Path: "LICENSE", Data: []byte(acceptanceLicenseText)},
		{Path: "problem_statement/problem.md", Data: []byte(acceptanceStatement)},
		{Path: "data/sample/a.in", Data: []byte("1\n")},
		{Path: "data/sample/a.ans", Data: []byte("2\n")},
		{Path: "data/secret/b.in", Data: []byte(acceptancePrivate + " hidden input\n")},
		{Path: "data/secret/b.ans", Data: []byte(acceptancePrivate + " hidden answer\n")},
		{Path: "input_validators/check.py", Data: []byte("# " + acceptancePrivate + "\nraise SystemExit(42)\n")},
		{Path: "submissions/accepted/main.cpp", Data: []byte("// " + acceptancePrivate + " reference\nint main(){return 0;}\n")},
	}}, nil
}

type acceptanceMature struct {
	runtime *acceptanceRuntime
	calls   atomic.Int64
}

func (m *acceptanceMature) Snapshot(ctx context.Context) validation.MatureSnapshot {
	snapshot := m.runtime.Snapshot(ctx)
	return validation.MatureSnapshot{Qualified: snapshot.Qualified, Identity: snapshot.Identity, ProblemtoolsVersion: validation.ProblemtoolsVersion, ProblemtoolsRevision: packages.CheckerRevision, HelperProfile: validation.HelperProfile}
}
func (m *acceptanceMature) Verify(_ context.Context, input validation.MatureInput) (validation.MatureOutcome, error) {
	m.calls.Add(1)
	parts := []validation.PartOutcome{}
	for _, part := range []string{"STRUCTURE", "STATEMENT", "TEST_DATA", "VALIDATORS", "REFERENCES"} {
		parts = append(parts, validation.PartOutcome{Part: part, Passed: true})
	}
	return validation.MatureOutcome{Identity: input.Identity, Completed: true, Parts: parts, RawLog: []byte(acceptancePrivate + " /w/secret mature helper log")}, nil
}
func (runtime *acceptanceRuntime) ValidateProgramsWithEvidence(ctx context.Context, input judgeruntime.ValidationInput, sink judgeruntime.ValidationEvidenceFunc) (judgeruntime.ValidationOutcome, error) {
	runtime.validationCalls.Add(1)
	result := judgeruntime.ValidationOutcome{ValidatorsPassed: true, ReferencesPassed: true}
	for _, group := range []struct {
		kind     string
		programs []judgeruntime.Program
	}{{"VALIDATOR", input.InputValidators}, {"REFERENCE", input.AcceptedReferences}} {
		for _, program := range group.programs {
			if _, err := runtime.store.ReadBlob(ctx, program.File.SHA256, program.File.SizeBytes, judgeruntime.MaxFileBytes); err != nil {
				return result, err
			}
			for _, test := range input.Cases {
				for _, ref := range []judgeruntime.BlobRef{test.Input, test.Answer} {
					if _, err := runtime.store.ReadBlob(ctx, ref.SHA256, ref.SizeBytes, judgeruntime.MaxFileBytes); err != nil {
						return result, err
					}
				}
				status, exit := restclient.Accepted, 0
				if group.kind == "VALIDATOR" {
					status, exit = restclient.NonzeroExit, 42
					result.ValidatorCaseCount++
				} else {
					result.ReferenceCaseCount++
				}
				evidence := judgeruntime.ValidationEvidence{Kind: group.kind, Case: judgeruntime.ProgramCaseEvidence{SourceSHA256: program.File.SHA256, Ordinal: test.Ordinal, Passed: true, Verdict: contract.VerdictAC, Status: status, ExitCode: exit, CPUTimeNS: uint64(time.Millisecond), WallTimeNS: uint64(time.Millisecond), MemoryBytes: 256}}
				if err := sink(ctx, evidence); err != nil {
					return result, err
				}
			}
		}
	}
	return result, nil
}

func (f *acceptanceFixture) startImportWorker(t *testing.T) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	worker := &imports.Worker{Repository: f.importRepo, Pipeline: f.pipeline, Ready: f.pipeline.Ready, PollInterval: 10 * time.Millisecond}
	go func() { done <- worker.Run(ctx) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(15 * time.Second):
				t.Error("real import acceptance worker did not drain")
			}
		})
	}
	t.Cleanup(stop)
	return stop
}
func (f *acceptanceFixture) importJob(t *testing.T, request contract.ImportRequest) contract.ImportJob {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	if testDeadline, ok := t.Deadline(); ok && testDeadline.Before(deadline) {
		deadline = testDeadline
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	status, raw, err := f.call(ctx, http.MethodPost, "/internal/v2/problem-imports", request.RequestID, request)
	queued := acceptanceDecode[contract.ImportJob](t, status, raw, err, 202)
	last := queued
	for ctx.Err() == nil {
		status, raw, err = f.call(ctx, http.MethodGet, "/internal/v2/problem-imports/"+string(queued.ImportJobID), acceptanceUUID(t), nil)
		job := acceptanceDecode[contract.ImportJob](t, status, raw, err, 200)
		last = job
		if job.Status == contract.ImportSucceeded || job.Status == contract.ImportFailed {
			return job
		}
		select {
		case <-ctx.Done():
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Fatalf("real import acceptance job never reached a durable terminal state: status=%s revision=%d", last.Status, last.Revision)
	return contract.ImportJob{}
}
func (f *acceptanceFixture) importAndPublish(t *testing.T) {
	t.Helper()
	stop := f.startImportWorker(t)
	defer stop()
	request := contract.ImportRequest{RequestID: acceptanceUUID(t), Source: "OJ_LAB", RepositoryURL: packages.RepositoryURL, Revision: packages.PinnedRevision, PackagePaths: []string{"problems/acceptance"}}
	rejected := f.importJob(t, request)
	if rejected.Status != contract.ImportFailed || len(rejected.Items) != 1 || rejected.Items[0].LicenseStatus != "REVIEW_REQUIRED" || f.mature.calls.Load() != 0 || f.runtime.validationCalls.Load() != 0 {
		t.Fatal("automatic collection bypassed offline rights review or executed unapproved programs")
	}
	var rejectedID, previousID, sourceHash string
	var normalizedHash sql.NullString
	if f.db.Admin.QueryRow(`SELECT e.id::text,e.license_evidence_id::text,e.source_sha256::text,e.normalized_sha256::text FROM judge.rejected_package_evidence e JOIN judge.import_items i ON i.id=e.import_item_id WHERE i.import_job_id=$1`, string(rejected.ImportJobID)).Scan(&rejectedID, &previousID, &sourceHash, &normalizedHash) != nil {
		t.Fatal("automatic rights rejection lost exact retained source evidence")
	}
	previous := contract.UUID(previousID)
	receipt := problems.LicenseApproval{EvidenceID: acceptanceUUID(t), RejectedEvidenceID: contract.UUID(rejectedID), PreviousEvidenceID: &previous, RepositoryURL: packages.RepositoryURL, SourceRevision: packages.PinnedRevision, PackagePath: "problems/acceptance", SourceSHA256: sourceHash, Scope: "PACKAGE", Notice: "Synthetic human review fixture attribution", SourceURL: packages.RepositoryURL + "/tree/" + packages.PinnedRevision + "/problems/acceptance", LicenseFiles: []problems.LicenseFile{{Path: "LICENSE", SHA256: canonical.HashBytes([]byte(acceptanceLicenseText))}}, Coverage: "Inert fixture package coverage", ThirdPartyReview: "Synthetic fixture contains no supplied external license authority", ApprovalEvidence: "Explicit trusted ADMIN control-flow fixture; no legal qualification claim"}
	if normalizedHash.Valid {
		receipt.NormalizedSHA256 = &normalizedHash.String
	}
	if _, err := problems.ApproveLicense(context.Background(), f.problemRepo, f.store, "ADMIN:caller-spoof", receipt); err == nil {
		t.Fatal("runtime DB credential forged trusted reviewer authority")
	}
	acceptanceApproveLicense(t, f, receipt)
	status, raw, err := f.call(context.Background(), http.MethodPost, "/internal/v2/problem-imports", request.RequestID, request)
	old := acceptanceDecode[contract.ImportJob](t, status, raw, err, 200)
	if old.ImportJobID != rejected.ImportJobID || old.Status != contract.ImportFailed {
		t.Fatal("new license review rewrote historical rejected import")
	}
	request.RequestID = acceptanceUUID(t)
	validated := f.importJob(t, request)
	if validated.Status != contract.ImportSucceeded || len(validated.Items) != 1 || validated.Items[0].Status != "VALIDATED" || validated.Items[0].ProblemID == nil || *validated.Items[0].ProblemID != "1" || validated.Items[0].ProblemVersionID == nil || f.mature.calls.Load() != 1 || f.runtime.validationCalls.Load() != 1 {
		t.Fatal("reviewed exact package failed real technical validation registration")
	}
	f.version = *validated.Items[0].ProblemVersionID
	f.statement = acceptanceStatement
	var state string
	var current sql.NullString
	if f.db.Admin.QueryRow(`SELECT status,current_version_id::text FROM judge.platform_problems WHERE id=1`).Scan(&state, &current) != nil || state != "DRAFT" || current.Valid {
		t.Fatal("technical validation published the package without explicit management operation")
	}
	publish := contract.PublishRequest{RequestID: acceptanceUUID(t), ProblemVersionID: f.version}
	status, raw, err = f.call(context.Background(), http.MethodPost, "/internal/v2/problems/1/publish", publish.RequestID, publish)
	public := acceptanceDecode[contract.PlatformProblemDetail](t, status, raw, err, 200)
	if public.Statement.Content != acceptanceStatement || len(public.Samples) != 1 || public.Samples[0].Input != "1\n" || public.Samples[0].Output != "2\n" || public.License.SourceURL != receipt.SourceURL || public.License.Notice != receipt.Notice {
		t.Fatal("public projection lost approved statement/sample/license attribution")
	}
	status, raw, err = f.call(context.Background(), http.MethodGet, "/internal/v2/catalog-snapshots?limit=10", acceptanceUUID(t), nil)
	snapshot := acceptanceDecode[contract.CatalogSnapshotPage](t, status, raw, err, 200)
	if len(snapshot.Items) != 1 || snapshot.Items[0].Problem.ProblemRef.ProblemVersionID == nil || *snapshot.Items[0].Problem.ProblemRef.ProblemVersionID != f.version {
		t.Fatal("published imported version missing from immutable catalog snapshot")
	}
	if n, err := f.registry.Collect(context.Background(), time.Now().Add(time.Hour), 100); err != nil || n != 0 {
		t.Fatal("GC deleted immutable approved/rejected import or validation evidence")
	}
}

func TestPortableAcceptanceImportRightsValidationPublishAndSnapshot(t *testing.T) {
	f := newAcceptanceFixture(t, true)
	f.importAndPublish(t)
	request := f.request(t, contract.VerdictAC)
	f.backend.expect(request)
	accepted := f.submit(t, request, 202)
	stop := f.startTaskWorker(t)
	final := f.awaitTask(t, accepted.JudgeTaskID, contract.JudgeCompleted)
	stop()
	f.drainCallbacks(t)
	if final.Result == nil || final.Result.TotalTestCount != 2 || final.Result.Verdict != contract.VerdictAC {
		t.Fatal("imported published package did not become exact frozen judge input")
	}
	var runs, automatic, verified int
	if f.db.Admin.QueryRow(`SELECT (SELECT count(*) FROM judge.package_validation_runs),(SELECT count(*) FROM judge.license_evidence WHERE status='REVIEW_REQUIRED'),(SELECT count(*) FROM judge.license_evidence WHERE status='VERIFIED')`).Scan(&runs, &automatic, &verified) != nil || runs != 1 || automatic != 1 || verified != 1 {
		t.Fatal("end-to-end import overwrote rights history or duplicated qualification")
	}
}
