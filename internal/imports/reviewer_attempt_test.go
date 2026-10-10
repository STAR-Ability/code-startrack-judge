// SPDX-License-Identifier: Apache-2.0

package imports_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/imports"
	problemstore "github.com/STAR-Ability/code-startrack-judge/internal/persistence/problems"
	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
	"github.com/STAR-Ability/code-startrack-judge/internal/runtime/restclient"
	"github.com/STAR-Ability/code-startrack-judge/internal/storage"
	"github.com/STAR-Ability/code-startrack-judge/internal/testutil/postgres"
	"github.com/STAR-Ability/code-startrack-judge/internal/validation"
)

type reviewAttemptPrepared func(context.Context, *sql.Tx, imports.PendingItem) (imports.ItemResult, error)

func (f reviewAttemptPrepared) Apply(ctx context.Context, tx *sql.Tx, item imports.PendingItem) (imports.ItemResult, error) {
	return f(ctx, tx, item)
}

// This produces only a synthetic observed prefix. It supplies no execution
// proof and intentionally cannot produce a terminal validation report.
type reviewInterruptedPrefixValidator struct{ expected *bytes.Buffer }

func (v reviewInterruptedPrefixValidator) Validate(ctx context.Context, request validation.Request) (validation.Report, error) {
	for i := 0; i < 6000; i++ {
		event := judgeruntime.ValidationEvidence{Kind: "REFERENCE", Case: judgeruntime.ProgramCaseEvidence{SourceSHA256: request.Candidate.Manifest.ReferenceSolutions[0].File.SHA256, Ordinal: i%2 + 1, Passed: true, Verdict: contract.VerdictAC, Status: restclient.Accepted, DiagnosticCode: "SYNTHETIC_PREFIX_" + strconv.Itoa(i)}}
		if err := request.RecordEvidence(ctx, event); err != nil {
			return validation.Report{}, err
		}
		line, _ := json.Marshal(event)
		v.expected.Write(append(line, '\n'))
	}
	return validation.Report{Status: "RUNNING", StartedAt: time.Now(), RawLog: []byte("PRIVATE_REVIEW_INTERRUPTED_LOG\x00\xff\n"), ProgramEvidenceSHA256: "", ProgramEvidenceCount: 0}, &judgeruntime.Failure{Code: "MATURE_OPERATION_INTERRUPTED", Ambiguous: true}
}

func TestReviewInterruptedAuditRetainsExactPrivatePrefixAndDiagnostics(t *testing.T) {
	db := postgres.New(t)
	_, registry, store := reviewRegistrationPipelineWithStore(t, db, false)
	var expected bytes.Buffer
	pipeline, err := imports.NewPipeline(imports.PipelineOptions{DB: db.Runtime, Source: &fixedSource{snapshot: candidateSource()}, Registry: registry, Problems: problemstore.New(db.Runtime, registry), Validation: reviewInterruptedPrefixValidator{&expected}})
	if err != nil {
		t.Fatal(err)
	}
	repository, job := acceptedJob(t, db.Runtime, []string{"problems/private"})
	lease, err := repository.Claim(context.Background())
	if err != nil || lease == nil {
		t.Fatal("cannot reserve synthetic interrupted audit")
	}
	before, err := repository.Get(context.Background(), job.ImportJobID)
	if err != nil {
		t.Fatal(err)
	}
	var beforeExpiry time.Time
	if db.Admin.QueryRow(`SELECT lease_expires_at FROM judge.import_jobs WHERE id=$1`, job.ImportJobID).Scan(&beforeExpiry) != nil {
		t.Fatal("cannot inspect initial reservation deadline")
	}
	prepared, validationErr := pipeline.Prepare(context.Background(), *lease, lease.Items[0])
	var ambiguous *judgeruntime.Failure
	if prepared == nil || !errors.As(validationErr, &ambiguous) || !ambiguous.Ambiguous {
		t.Fatal("synthetic interruption lost its counted-recovery error")
	}
	if err := repository.RetainAttempt(context.Background(), *lease, lease.Items[0], prepared); err != nil {
		t.Fatal("cannot retain synthetic incomplete audit", err)
	}
	if err := repository.CompleteItem(context.Background(), *lease, lease.Items[0], prepared); err == nil {
		t.Fatal("incomplete attempt evidence completed an import item")
	}
	after, err := repository.Get(context.Background(), job.ImportJobID)
	beforeJSON, _ := json.Marshal(before)
	afterJSON, _ := json.Marshal(after)
	if err != nil || !bytes.Equal(beforeJSON, afterJSON) || bytes.Contains(afterJSON, []byte("PRIVATE_")) || bytes.Contains(afterJSON, []byte("sha256/")) {
		t.Fatal("private attempt audit changed or leaked public import facts")
	}
	var afterExpiry time.Time
	if db.Admin.QueryRow(`SELECT lease_expires_at FROM judge.import_jobs WHERE id=$1`, job.ImportJobID).Scan(&afterExpiry) != nil || !beforeExpiry.Equal(afterExpiry) {
		t.Fatal("attempt retention extended its execution reservation")
	}
	var object storage.Object
	var provenance []byte
	if err := db.Runtime.QueryRow(`SELECT o.object_key,o.sha256::text,o.size_bytes,a.provenance FROM judge.import_attempt_evidence a JOIN judge.private_objects o ON o.object_key=a.validation_log_key WHERE a.import_item_id=$1`, lease.Items[0].ID).Scan(&object.Key, &object.SHA256, &object.SizeBytes, &provenance); err != nil {
		t.Fatal("cannot inspect retained incomplete private log", err)
	}
	log, err := store.Read(context.Background(), object, 32<<20)
	if err != nil {
		t.Fatal("incomplete private log bytes are unavailable")
	}
	var sealed struct {
		Complete bool              `json:"complete"`
		Report   validation.Report `json:"partialReport"`
		Chunks   []struct {
			ObjectKey string `json:"objectKey"`
			SHA256    string `json:"sha256"`
			SizeBytes int64  `json:"sizeBytes"`
		} `json:"validationEvidenceChunks"`
	}
	if json.Unmarshal(log, &sealed) != nil || sealed.Complete || sealed.Report.Status != "RUNNING" || !bytes.Equal(sealed.Report.RawLog, []byte("PRIVATE_REVIEW_INTERRUPTED_LOG\x00\xff\n")) || len(sealed.Chunks) < 2 {
		t.Fatal("incomplete report lost original diagnostics or its chunked prefix")
	}
	var actual bytes.Buffer
	for _, chunk := range sealed.Chunks {
		part, err := store.Read(context.Background(), storage.Object{Key: chunk.ObjectKey, SHA256: chunk.SHA256, SizeBytes: chunk.SizeBytes}, 1<<20)
		if err != nil {
			t.Fatal("retained incomplete journal chunk is unavailable")
		}
		actual.Write(part)
	}
	var facts struct {
		Complete     bool          `json:"complete"`
		FencingToken contract.UUID `json:"fencingToken"`
		SHA256       string        `json:"programEvidenceSha256"`
		Count        uint64        `json:"programEvidenceCount"`
	}
	digest := sha256.Sum256(expected.Bytes())
	if json.Unmarshal(provenance, &facts) != nil || facts.Complete || facts.FencingToken != lease.Token || facts.Count != 6000 || facts.SHA256 != hex.EncodeToString(digest[:]) || !bytes.Equal(actual.Bytes(), expected.Bytes()) {
		t.Fatal("attempt audit invented completeness or changed observed prefix bytes")
	}
	for name, change := range map[string]string{
		"missing_chunks": "provenance - 'validationEvidenceChunks'",
		"missing_fence":  "provenance - 'fencingToken'",
		"null_fence":     "jsonb_set(provenance,'{fencingToken}','null'::jsonb)",
		"complete_claim": "jsonb_set(provenance,'{complete}','true'::jsonb)",
	} {
		t.Run(name, func(t *testing.T) {
			clone, _ := contract.NewUUID()
			// CHECK must reject the malformed provenance before uniqueness can
			// mask the missing-key defect on this same reserved attempt.
			_, err := db.Runtime.Exec(`INSERT INTO judge.import_attempt_evidence(id,import_item_id,attempt_token,recovery_count,repository_url,source_revision,package_path,failure_stage,source_archive_key,source_sha256,normalized_archive_key,normalized_sha256,license_evidence_id,provenance,source_metadata,adaptations,errors,validation_log_key,evidence_sha256)
SELECT $1,import_item_id,attempt_token,recovery_count,repository_url,source_revision,package_path,failure_stage,source_archive_key,source_sha256,normalized_archive_key,normalized_sha256,license_evidence_id,`+change+`,source_metadata,adaptations,errors,validation_log_key,evidence_sha256 FROM judge.import_attempt_evidence WHERE import_item_id=$2`, clone, lease.Items[0].ID)
			var state interface{ SQLState() string }
			if !errors.As(err, &state) || state.SQLState() != "23514" {
				t.Fatal("malformed attempt provenance was not rejected by its CHECK")
			}
		})
	}
	if _, err := registry.Collect(context.Background(), time.Now().Add(time.Hour), 100); err != nil {
		t.Fatal("cannot collect unrelated incomplete audit stages")
	}
	if registry.Verify(context.Background(), object) != nil {
		t.Fatal("GC deleted incomplete original diagnostics")
	}
	for _, chunk := range sealed.Chunks {
		if registry.Verify(context.Background(), storage.Object{Key: chunk.ObjectKey, SHA256: chunk.SHA256, SizeBytes: chunk.SizeBytes}) != nil {
			t.Fatal("GC deleted incomplete private journal evidence")
		}
	}
	var invented int
	if db.Runtime.QueryRow(`SELECT (SELECT count(*) FROM judge.rejected_package_evidence)+(SELECT count(*) FROM judge.package_validation_runs)+(SELECT count(*) FROM judge.package_artifacts)+(SELECT count(*) FROM judge.platform_problems)`).Scan(&invented) != nil || invented != 0 {
		t.Fatal("incomplete audit invented terminal rejection or qualification history")
	}
}

func TestReviewAttemptExpiryDuringApplyRollsBackPrivateOwnershipAndRequiresFreshRecovery(t *testing.T) {
	db := postgres.New(t)
	_, registry := reviewRegistrationPipeline(t, db, false)
	var expected bytes.Buffer
	pipeline, err := imports.NewPipeline(imports.PipelineOptions{DB: db.Runtime, Source: &fixedSource{snapshot: candidateSource()}, Registry: registry, Problems: problemstore.New(db.Runtime, registry), Validation: reviewInterruptedPrefixValidator{&expected}})
	if err != nil {
		t.Fatal(err)
	}
	repository, job := acceptedJob(t, db.Runtime, []string{"problems/private"})
	lease, err := repository.Claim(context.Background())
	if err != nil || lease == nil {
		t.Fatal("cannot reserve synthetic audit rollback")
	}
	prepared, validationErr := pipeline.Prepare(context.Background(), *lease, lease.Items[0])
	if prepared == nil || validationErr == nil {
		t.Fatal("synthetic incomplete attempt lost its private preparation")
	}
	before, err := repository.Get(context.Background(), job.ImportJobID)
	if err != nil {
		t.Fatal(err)
	}
	counts := func() [4]int {
		t.Helper()
		var value [4]int
		if db.Runtime.QueryRow(`SELECT (SELECT count(*) FROM judge.private_objects),(SELECT count(*) FROM judge.private_object_stages),(SELECT count(*) FROM judge.private_object_references),(SELECT count(*) FROM judge.import_attempt_evidence)`).Scan(&value[0], &value[1], &value[2], &value[3]) != nil {
			t.Fatal("cannot inspect synthetic audit rollback facts")
		}
		return value
	}
	beforeCounts := counts()
	if _, err := db.Admin.Exec(`UPDATE judge.import_jobs SET lease_expires_at=clock_timestamp()+interval '1 second' WHERE id=$1`, job.ImportJobID); err != nil {
		t.Fatal("cannot shorten synthetic audit rollback reservation")
	}
	registered := false
	delayed := reviewAttemptPrepared(func(ctx context.Context, tx *sql.Tx, item imports.PendingItem) (imports.ItemResult, error) {
		result, err := prepared.Apply(ctx, tx, item)
		if err != nil {
			return result, err
		}
		var references int
		var live bool
		if tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM judge.private_object_references WHERE owner_type='IMPORT_ATTEMPT'),lease_expires_at>clock_timestamp() FROM judge.import_jobs WHERE id=$1`, job.ImportJobID).Scan(&references, &live) != nil || references < 4 || !live {
			return imports.ItemResult{}, errors.New("synthetic audit did not register private ownership under a live fence")
		}
		registered = true
		if _, err := tx.ExecContext(ctx, `SELECT pg_sleep(1.1)`); err != nil {
			return imports.ItemResult{}, err
		}
		return result, nil
	})
	if err := repository.RetainAttempt(context.Background(), *lease, lease.Items[0], delayed); err == nil || !registered {
		t.Fatal("attempt audit crossing its deadline was not rejected after private registration")
	}
	after, err := repository.Get(context.Background(), job.ImportJobID)
	beforeJSON, _ := json.Marshal(before)
	afterJSON, _ := json.Marshal(after)
	if err != nil || !bytes.Equal(beforeJSON, afterJSON) || counts() != beforeCounts {
		t.Fatal("expired audit leaked ownership, consumed staging or changed public facts")
	}
	recovered, err := repository.Claim(context.Background())
	if err != nil || recovered == nil || recovered.Token == lease.Token {
		t.Fatal("expired audit did not require a fresh recovery reservation")
	}
	var recoveryCount int
	if db.Runtime.QueryRow(`SELECT attempt_count FROM judge.import_jobs WHERE id=$1`, job.ImportJobID).Scan(&recoveryCount) != nil || recoveryCount != 1 {
		t.Fatal("fresh audit recovery bypassed the counted reservation budget")
	}
	fresh, validationErr := pipeline.Prepare(context.Background(), *recovered, recovered.Items[0])
	if fresh == nil || validationErr == nil || repository.RetainAttempt(context.Background(), *recovered, recovered.Items[0], fresh) != nil {
		t.Fatal("fresh live recovery could not preserve its independent incomplete audit")
	}
	var audits, qualified int
	if db.Runtime.QueryRow(`SELECT count(*) FROM judge.import_attempt_evidence WHERE attempt_token=$1 AND recovery_count=1`, recovered.Token).Scan(&audits) != nil || audits != 1 {
		t.Fatal("recovered audit lost its new fence or counted recovery identity")
	}
	if db.Runtime.QueryRow(`SELECT (SELECT count(*) FROM judge.rejected_package_evidence)+(SELECT count(*) FROM judge.package_validation_runs)+(SELECT count(*) FROM judge.package_artifacts)+(SELECT count(*) FROM judge.platform_problems)`).Scan(&qualified) != nil || qualified != 0 {
		t.Fatal("audit rollback or recovery invented terminal qualification history")
	}
}
