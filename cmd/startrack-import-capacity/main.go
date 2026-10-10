// SPDX-License-Identifier: Apache-2.0

// This fixed operator-only binary qualifies disposable authored imports. It has
// no HTTP listener, caller-selected source, publication operation, or ADMIN role.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/config"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/imports"
	"github.com/STAR-Ability/code-startrack-judge/internal/packages"
	importstore "github.com/STAR-Ability/code-startrack-judge/internal/persistence/imports"
	"github.com/STAR-Ability/code-startrack-judge/internal/persistence/migrate"
	problemstore "github.com/STAR-Ability/code-startrack-judge/internal/persistence/problems"
	"github.com/STAR-Ability/code-startrack-judge/internal/processguard"
	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
	"github.com/STAR-Ability/code-startrack-judge/internal/storage"
	"github.com/STAR-Ability/code-startrack-judge/internal/testutil/importcapacity"
	"github.com/STAR-Ability/code-startrack-judge/internal/validation"
	"github.com/STAR-Ability/code-startrack-judge/migrations"
)

const privateDirectory = "/var/lib/startrack/private"

var databaseName = regexp.MustCompile(`^judge_capacity_[a-z0-9_]+$`)
var errQualification = errors.New("fixed import capacity qualification failed")

type report struct {
	SchemaVersion    int          `json:"schemaVersion"`
	Scope            string       `json:"scope"`
	SyntheticFixture bool         `json:"syntheticFixture"`
	Phase            string       `json:"phase"`
	Passed           bool         `json:"passed"`
	Code             string       `json:"code"`
	UID              int          `json:"uid"`
	Cgroup           string       `json:"cgroup"`
	DeclaredLimits   string       `json:"declaredLimits"`
	Cases            []caseReport `json:"cases"`
}

type caseReport struct {
	Name                       string `json:"name"`
	PackagePath                string `json:"packagePath"`
	JobID                      string `json:"jobId"`
	Status                     string `json:"status"`
	SourceFiles                int    `json:"sourceFiles"`
	SourceRegularBytes         int64  `json:"sourceRegularBytes"`
	SourceArchiveBytes         int64  `json:"sourceArchiveBytes"`
	SourceSHA256               string `json:"sourceSha256"`
	NormalizedFiles            int    `json:"normalizedFiles"`
	NormalizedRegularBytes     int64  `json:"normalizedRegularBytes"`
	NormalizedArchiveBytes     int64  `json:"normalizedArchiveBytes"`
	NormalizedSHA256           string `json:"normalizedSha256"`
	ManifestSHA256             string `json:"manifestSha256"`
	RejectedEvidenceID         string `json:"rejectedEvidenceId"`
	PreviousLicenseEvidenceID  string `json:"previousLicenseEvidenceId"`
	ApprovedLicenseEvidenceID  string `json:"approvedLicenseEvidenceId"`
	LicenseTextSHA256          string `json:"licenseTextSha256"`
	ValidationRunID            string `json:"validationRunId"`
	ProblemID                  string `json:"problemId"`
	ProblemVersionID           string `json:"problemVersionId"`
	CheckpointsPassed          int    `json:"checkpointsPassed"`
	ProgramEvidenceCount       uint64 `json:"programEvidenceCount"`
	SampleTextBytes            int64  `json:"sampleTextBytes"`
	ExpectedOversizeRejection  bool   `json:"expectedOversizeRejection"`
	OversizeRejectedEvidenceID string `json:"oversizeRejectedEvidenceId"`
	RejectionStage             string `json:"rejectionStage"`
	RejectionCode              string `json:"rejectionCode"`
	StoredSampleBytes          int64  `json:"storedSampleBytes"`
	DetailEnvelopeBytes        int64  `json:"detailEnvelopeBytes"`
	DetailHTTPStatus           int    `json:"detailHTTPStatus"`
	DetailResponseBytes        int    `json:"detailResponseBytes"`
	DetailResponseCode         string `json:"detailResponseCode"`
	NoPublication              bool   `json:"noPublication"`
}

func phaseArgument(args []string) (string, error) {
	if len(args) != 2 || args[0] != "--phase" || (args[1] != "reject" && args[1] != "validate") {
		return "", errQualification
	}
	return args[1], nil
}

// Every environment key is allowlisted, including otherwise innocuous unknown
// keys: a runner can never silently inherit reviewer, Backend, or runtime keys.
func validEnvironment(environment []string) bool {
	allowed := map[string]bool{"JUDGE_QUALIFICATION_ONLY": true, "JUDGE_DATABASE_URL": true, "JUDGE_SCHEDULER_TOKEN": true, "JUDGE_PRIVATE_STORAGE_DIR": true, "PATH": true, "LANG": true, "TZ": true, "HOME": true, "TMPDIR": true}
	seen := make(map[string]bool)
	for _, entry := range environment {
		key, _, found := strings.Cut(entry, "=")
		if !found || !allowed[key] || seen[key] {
			return false
		}
		seen[key] = true
	}
	return true
}

func disposableDSN(raw string) bool {
	if config.ValidateDatabaseURL(raw) != nil {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && u.User.Username() == "judge_runtime" && databaseName.MatchString(strings.TrimPrefix(u.Path, "/")) && u.Query().Get("sslcert") == "" && u.Query().Get("sslkey") == ""
}

func processBoundary() bool {
	if runtime.GOOS != "linux" || os.Getuid() != 20000 || os.Geteuid() != 20000 || os.Getgid() != 20000 || os.Getegid() != 20000 || os.Getenv("JUDGE_QUALIFICATION_ONLY") != "true" || os.Getenv("JUDGE_PRIVATE_STORAGE_DIR") != privateDirectory || !validEnvironment(os.Environ()) || !disposableDSN(os.Getenv("JUDGE_DATABASE_URL")) || !config.ValidServiceToken(os.Getenv("JUDGE_SCHEDULER_TOKEN")) {
		return false
	}
	groups, err := os.Getgroups()
	if err != nil {
		return false
	}
	group := false
	for _, id := range groups {
		group = group || id == 20002
	}
	contents, err := os.ReadFile("/proc/self/cgroup")
	return group && err == nil && strings.TrimSpace(string(contents)) == "0::/service"
}

func main() {
	phase, err := phaseArgument(os.Args[1:])
	r := report{SchemaVersion: 1, Scope: "DISPOSABLE_SYNTHETIC_API_IMPORT_CAPACITY", SyntheticFixture: true, Phase: phase, Code: "IMPORT_CAPACITY_GUARD_FAILED", UID: os.Geteuid(), DeclaredLimits: importcapacity.DeclaredLimits(), Cases: []caseReport{}}
	if err == nil && processguard.Harden() == nil && processBoundary() {
		r.Cgroup = "/service"
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		ctx, cancel := context.WithTimeout(ctx, 70*time.Minute)
		err = qualify(ctx, &r)
		cancel()
		stop()
		if err == nil {
			r.Passed, r.Code = true, "IMPORT_CAPACITY_PASSED"
		}
	}
	contents, marshalErr := json.Marshal(r)
	if marshalErr != nil || len(contents) > 64<<10 {
		fmt.Fprintln(os.Stderr, "IMPORT_CAPACITY_REPORT_FAILED")
		os.Exit(1)
	}
	fmt.Println(string(contents))
	if !r.Passed {
		os.Exit(1)
	}
}

type acquisitionFact struct {
	files int
	bytes int64
	calls int
}

type fixedSource struct {
	mu    sync.Mutex
	facts map[string]acquisitionFact
}

func (*fixedSource) Ready(ctx context.Context) bool { return ctx != nil && ctx.Err() == nil }
func (s *fixedSource) Acquire(ctx context.Context, revision, packagePath string) (imports.SourceSnapshot, error) {
	if revision != packages.PinnedRevision {
		return imports.SourceSnapshot{}, imports.ErrSourceUnsupported
	}
	for _, name := range importcapacity.Names() {
		fixedPath, _ := importcapacity.Path(name)
		if packagePath != fixedPath {
			continue
		}
		fixture, err := importcapacity.Build(ctx, name)
		if err != nil {
			return imports.SourceSnapshot{}, imports.ErrSourceUnavailable
		}
		s.mu.Lock()
		fact := s.facts[packagePath]
		fact.files, fact.bytes, fact.calls = len(fixture.Files), fixture.SourceRegularBytes, fact.calls+1
		s.facts[packagePath] = fact
		s.mu.Unlock()
		return imports.SourceSnapshot{Files: fixture.Files}, nil
	}
	return imports.SourceSnapshot{}, imports.ErrSourceUnsupported
}

type validationFact struct {
	calls       int
	checkpoints int
	events      uint64
	passed      bool
}

type observedValidator struct {
	actual *validation.Validator
	mu     sync.Mutex
	facts  map[string]validationFact
}

func (v *observedValidator) Ready(ctx context.Context) bool { return v.actual.Ready(ctx) }
func (v *observedValidator) Validate(ctx context.Context, request validation.Request) (validation.Report, error) {
	if request.Candidate == nil || request.Candidate.Manifest == nil || request.RecordEvidence == nil {
		return validation.Report{}, errQualification
	}
	candidate := request.Candidate
	name := ""
	for _, fixedName := range importcapacity.Names() {
		fixedPath, _ := importcapacity.Path(fixedName)
		if candidate.Manifest.Source.PackagePath == fixedPath {
			name = fixedName
		}
	}
	regular := int64(len(candidate.ManifestJSON))
	for _, file := range candidate.NormalizedFiles {
		regular += int64(len(file.Data))
	}
	if name == "" || !candidate.ManifestReady || candidate.Manifest.Limits.TimeLimitMS != 2000 || candidate.Manifest.Limits.MemoryLimitBytes != 256<<20 || name == importcapacity.MemberPayload && (len(candidate.NormalizedFiles)+1 != packages.MaxFiles || regular != packages.MaxTotalBytes) {
		return validation.Report{}, errQualification
	}
	result, err := v.actual.Validate(ctx, request)
	checkpoints := 0
	for _, checkpoint := range []validation.Checkpoint{result.Results.Structure, result.Results.Statement, result.Results.TestData, result.Results.Validators, result.Results.ReferenceSolutions} {
		if checkpoint.Passed && len(checkpoint.Evidence) > 0 {
			checkpoints++
		}
	}
	v.mu.Lock()
	fact := v.facts[candidate.Manifest.Source.PackagePath]
	fact.calls++
	fact.checkpoints, fact.events, fact.passed = checkpoints, result.ProgramEvidenceCount, err == nil && result.Status == "PASSED" && result.Results.AllPassed() && len(result.Errors) == 0
	v.facts[candidate.Manifest.Source.PackagePath] = fact
	v.mu.Unlock()
	return result, err
}

func qualify(ctx context.Context, result *report) error {
	result.Code = "IMPORT_CAPACITY_DATABASE_FAILED"
	db, err := migrate.Open(ctx, os.Getenv("JUDGE_DATABASE_URL"))
	if err != nil {
		return errQualification
	}
	defer db.Close()
	if verifyDatabase(ctx, db, result.Phase) != nil {
		return errQualification
	}
	store, err := storage.New(privateDirectory)
	if err != nil {
		return errQualification
	}
	defer store.Close()
	registry, err := storage.NewRegistry(db, store)
	if err != nil {
		return errQualification
	}
	scheduler, err := judgeruntime.NewSchedulerClient(os.Getenv("JUDGE_SCHEDULER_TOKEN"), store)
	if err != nil {
		return errQualification
	}
	defer scheduler.Close()
	mature, err := validation.NewMatureClient(scheduler)
	if err != nil {
		return errQualification
	}
	actual, err := validation.New(validation.Options{Engine: scheduler, Mature: mature})
	if err != nil {
		return errQualification
	}
	source := &fixedSource{facts: make(map[string]acquisitionFact)}
	validator := &observedValidator{actual: actual, facts: make(map[string]validationFact)}
	repository := importstore.New(db)
	pipeline, err := imports.NewPipeline(imports.PipelineOptions{DB: db, Source: source, Registry: registry, Problems: problemstore.New(db, registry), Validation: validator})
	if err != nil {
		return errQualification
	}
	result.Code = "IMPORT_CAPACITY_READINESS_FAILED"
	readyCtx, stopReady := context.WithTimeout(ctx, 5*time.Minute)
	for !pipeline.Ready(readyCtx) {
		select {
		case <-readyCtx.Done():
			stopReady()
			return errQualification
		case <-time.After(time.Second):
		}
	}
	stopReady()
	workerCtx, stopWorker := context.WithCancel(ctx)
	workerDone := make(chan error, 1)
	worker := &imports.Worker{Repository: repository, Pipeline: pipeline, Ready: pipeline.Ready, PollInterval: 100 * time.Millisecond}
	go func() { workerDone <- worker.Run(workerCtx) }()
	defer func() { stopWorker(); <-workerDone }()
	service := imports.New(repository, pipeline.Ready)
	for _, name := range importcapacity.Names() {
		path, _ := importcapacity.Path(name)
		caseResult := caseReport{Name: name, PackagePath: path, LicenseTextSHA256: canonical.HashBytes([]byte(importcapacity.LicenseText))}
		result.Cases = append(result.Cases, caseResult)
		current := &result.Cases[len(result.Cases)-1]
		result.Code = "IMPORT_CAPACITY_RECEIPT_FAILED"
		if result.Phase == "validate" && previousRejection(ctx, db, store, current, true) != nil {
			return errQualification
		}
		result.Code = "IMPORT_CAPACITY_ADMISSION_FAILED"
		id, err := contract.NewUUID()
		if err != nil {
			return errQualification
		}
		job, created, err := service.Submit(ctx, contract.ImportRequest{RequestID: id, Source: "OJ_LAB", RepositoryURL: packages.RepositoryURL, Revision: packages.PinnedRevision, PackagePaths: contract.Array[string]{path}})
		if err != nil || !created {
			return errQualification
		}
		current.JobID = string(job.ImportJobID)
		result.Code = "IMPORT_CAPACITY_WORKER_FAILED"
		caseCtx, cancelCase := context.WithTimeout(ctx, 30*time.Minute)
		job, err = awaitJob(caseCtx, service, job.ImportJobID)
		cancelCase()
		current.Status = string(job.Status)
		if err != nil || job.Validate() != nil || len(job.Items) != 1 {
			return errQualification
		}
		source.mu.Lock()
		acquired := source.facts[path]
		source.mu.Unlock()
		if acquired.calls != 1 {
			return errQualification
		}
		current.SourceFiles, current.SourceRegularBytes = acquired.files, acquired.bytes
		result.Code = "IMPORT_CAPACITY_EVIDENCE_FAILED"
		if result.Phase == "reject" {
			if job.Status != contract.ImportFailed || job.Items[0].Status != "REJECTED" || job.Items[0].LicenseStatus != "REVIEW_REQUIRED" || previousRejection(ctx, db, store, current, false) != nil {
				return errQualification
			}
			validator.mu.Lock()
			calls := validator.facts[path].calls
			validator.mu.Unlock()
			if calls != 0 {
				return errQualification
			}
		} else if name == importcapacity.SampleHeavy {
			if !expectedOversizeOutcome(job) || oversizeEvidence(ctx, db, store, current) != nil {
				return errQualification
			}
			validator.mu.Lock()
			calls := validator.facts[path].calls
			validator.mu.Unlock()
			if calls != 0 {
				return errQualification
			}
			current.ExpectedOversizeRejection = true
		} else {
			if job.Status != contract.ImportSucceeded || job.Items[0].Status != "VALIDATED" || validatedEvidence(ctx, db, store, current, job.Items[0]) != nil {
				return errQualification
			}
			validator.mu.Lock()
			fact := validator.facts[path]
			validator.mu.Unlock()
			expectedEvents := uint64(6)
			if name == importcapacity.SampleSupported {
				expectedEvents = 9
			}
			if fact.calls != 1 || !fact.passed || fact.checkpoints != 5 || fact.events != expectedEvents {
				return errQualification
			}
			current.CheckpointsPassed, current.ProgramEvidenceCount = fact.checkpoints, fact.events
			result.Code = "IMPORT_CAPACITY_DETAIL_MEASUREMENT_FAILED"
			if measureDetail(ctx, problemstore.New(db, registry), current) != nil {
				return errQualification
			}
		}
		if verifyNoPublication(ctx, db) != nil {
			return errQualification
		}
		current.NoPublication = true
	}
	return nil
}

// The oversized case must reach the bounded public-projection guard with rights
// already approved. A validation failure or an unreviewed package is not this
// expected qualification outcome.
func expectedOversizeOutcome(job contract.ImportJob) bool {
	if job.Status != contract.ImportFailed || len(job.Items) != 1 {
		return false
	}
	item := job.Items[0]
	path, _ := importcapacity.Path(importcapacity.SampleHeavy)
	return item.PackagePath == path && item.Status == "REJECTED" && item.LicenseStatus == "VERIFIED" && item.ValidationStatus == "FAILED" && item.ProblemID == nil && item.ProblemVersionID == nil && len(item.Errors) == 1 && item.Errors[0].Code == "PACKAGE_UNSUPPORTED" && !item.Errors[0].Retryable
}

func awaitJob(ctx context.Context, service *imports.Service, id contract.UUID) (contract.ImportJob, error) {
	for {
		job, err := service.Get(ctx, id)
		if err != nil {
			return job, errQualification
		}
		if job.Status == contract.ImportFailed || job.Status == contract.ImportPartial || job.Status == contract.ImportSucceeded {
			return job, nil
		}
		select {
		case <-ctx.Done():
			return job, errQualification
		case <-time.After(time.Second):
		}
	}
}

func verifyDatabase(ctx context.Context, db *sql.DB, phase string) error {
	var name, role, session string
	var unsafe bool
	if db.QueryRowContext(ctx, `SELECT current_database(),current_user,session_user,
 r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolinherit OR r.rolreplication OR r.rolbypassrls
 OR EXISTS(SELECT 1 FROM pg_auth_members WHERE member=r.oid OR roleid=r.oid)
 OR EXISTS(SELECT 1 FROM pg_database WHERE datdba=r.oid)
 OR EXISTS(SELECT 1 FROM pg_class WHERE relowner=r.oid)
 OR EXISTS(SELECT 1 FROM pg_namespace WHERE nspowner=r.oid)
 FROM pg_roles r WHERE r.rolname=current_user`).Scan(&name, &role, &session, &unsafe) != nil || !databaseName.MatchString(name) || role != "judge_runtime" || session != role || unsafe {
		return errQualification
	}
	shipped, err := migrate.Load(migrations.Files)
	if err != nil {
		return errQualification
	}
	status, err := migrate.Inspect(ctx, db, shipped)
	if err != nil || status.Applied != 5 || status.Available != 5 || status.Dirty || !status.Initialized {
		return errQualification
	}
	var jobs, rejected, licenses, approved, business int
	if db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM judge.import_jobs),(SELECT count(*) FROM judge.rejected_package_evidence),(SELECT count(*) FROM judge.license_evidence),(SELECT count(*) FROM judge.license_evidence WHERE status='VERIFIED'),(SELECT count(*) FROM judge.platform_problems)+(SELECT count(*) FROM judge.judge_tasks)+(SELECT count(*) FROM judge.package_artifacts)+(SELECT count(*) FROM judge.catalog_snapshots)+(SELECT count(*) FROM judge.import_attempt_evidence)`).Scan(&jobs, &rejected, &licenses, &approved, &business) != nil || business != 0 {
		return errQualification
	}
	caseCount := len(importcapacity.Names())
	if phase == "reject" && (jobs != 0 || rejected != 0 || licenses != 0 || approved != 0) || phase == "validate" && (jobs != caseCount || rejected != caseCount || licenses != 2*caseCount || approved != caseCount) {
		return errQualification
	}
	return verifyNoPublication(ctx, db)
}

func verifyNoPublication(ctx context.Context, db *sql.DB) error {
	var clean bool
	if db.QueryRowContext(ctx, `SELECT (SELECT catalog_version=1 FROM judge.catalog_state WHERE singleton_id=1) AND NOT EXISTS(SELECT 1 FROM judge.platform_problems WHERE status<>'DRAFT' OR current_version_id IS NOT NULL OR public_updated_at IS NOT NULL) AND NOT EXISTS(SELECT 1 FROM judge.problem_versions WHERE first_published_at IS NOT NULL) AND NOT EXISTS(SELECT 1 FROM judge.catalog_snapshots)`).Scan(&clean) != nil || !clean {
		return errQualification
	}
	return nil
}
