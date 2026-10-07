package problems

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
)

// WorkflowError is deliberately bounded; driver messages and private facts
// cannot cross the service/HTTP boundary.
type WorkflowError struct {
	Code string `json:"code"`
}

func (e *WorkflowError) Error() string      { return "problem workflow: " + e.Code }
func (e *WorkflowError) PublicCode() string { return e.Code }
func workflowError(code string) error       { return &WorkflowError{Code: code} }

type OperationOutcome struct {
	Result json.RawMessage
	Replay bool
}

// Operation holds a nonblocking, transaction-scoped key lock. Terminal results
// and deterministic failures commit with the business mutation, never after it.
func (r *Repository) Operation(ctx context.Context, operation string, requestID contract.UUID, hash string, problemID contract.ID, ready func(context.Context) bool, apply func(*Tx) (any, error)) (OperationOutcome, error) {
	var out OperationOutcome
	var frozenError error
	err := r.WithTx(ctx, nil, func(tx *Tx) error {
		var locked bool
		if err := tx.DB().QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))`, operation+":"+strings.ToLower(string(requestID))).Scan(&locked); err != nil {
			return err
		}
		if !locked {
			return workflowError("REQUEST_IN_PROGRESS")
		}
		var storedHash, status string
		var result, failure []byte
		err := tx.DB().QueryRowContext(ctx, `SELECT request_hash,status,result,error FROM judge.operation_requests WHERE operation=$1 AND request_id=$2`, operation, string(requestID)).Scan(&storedHash, &status, &result, &failure)
		if err == nil {
			if storedHash != hash {
				return workflowError("IDEMPOTENCY_CONFLICT")
			}
			if status == "PROCESSING" {
				return workflowError("REQUEST_IN_PROGRESS")
			}
			out.Replay = true
			out.Result = result
			if status == "FAILED" {
				var e WorkflowError
				if json.Unmarshal(failure, &e) != nil || e.Code == "" {
					return errors.New("invalid frozen operation error")
				}
				frozenError = &e
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if ready != nil && !ready(ctx) {
			return workflowError("JUDGE_UNAVAILABLE")
		}
		_, err = tx.DB().ExecContext(ctx, `INSERT INTO judge.operation_requests(operation,request_id,request_hash,problem_id,status) VALUES($1,$2,$3,(SELECT id FROM judge.platform_problems WHERE id=$4),'PROCESSING')`, operation, string(requestID), hash, string(problemID))
		if err != nil {
			return err
		}
		value, err := apply(tx)
		if err != nil {
			var domain *WorkflowError
			if !errors.As(err, &domain) {
				return err
			}
			frozenError = domain
			body, _ := json.Marshal(domain)
			_, err = tx.DB().ExecContext(ctx, `UPDATE judge.operation_requests SET status='FAILED',error=$3::jsonb,updated_at=clock_timestamp() WHERE operation=$1 AND request_id=$2`, operation, string(requestID), string(body))
			return err
		}
		out.Result, err = json.Marshal(value)
		if err != nil {
			return err
		}
		_, err = tx.DB().ExecContext(ctx, `UPDATE judge.operation_requests SET status='SUCCEEDED',result=$3::jsonb,updated_at=clock_timestamp() WHERE operation=$1 AND request_id=$2`, operation, string(requestID), string(out.Result))
		return err
	})
	if err != nil {
		return out, err
	}
	return out, frozenError
}

func (tx *Tx) lockWorkflowProblem(id contract.ID) (contract.PlatformProblemStatus, *contract.UUID, error) {
	var status contract.PlatformProblemStatus
	var current sql.NullString
	err := tx.DB().QueryRowContext(tx.ctx, `SELECT status,current_version_id::text FROM judge.platform_problems WHERE id=$1 FOR NO KEY UPDATE`, string(id)).Scan(&status, &current)
	if errors.Is(err, sql.ErrNoRows) {
		return status, nil, workflowError("PROBLEM_NOT_FOUND")
	}
	if err != nil {
		return status, nil, err
	}
	if current.Valid {
		id := contract.UUID(current.String)
		return status, &id, nil
	}
	return status, nil, nil
}

func (tx *Tx) CheckEligibility(id contract.ID, versionID contract.UUID) error {
	var mode, statement, licenseStatus string
	var sampleCount, tests, samples, secrets, accepted int64
	var selected, approved bool
	err := tx.DB().QueryRowContext(tx.ctx, `SELECT v.judge_mode,v.statement_content,jsonb_array_length(v.samples),l.status,
 a.validation_run_id IS NOT NULL AND r.status='PASSED' AND r.errors='[]'::jsonb,
 COALESCE(l.reviewed_at IS NOT NULL AND btrim(l.reviewed_by)<>'' AND btrim(l.notice)<>'' AND btrim(l.source_url)<>''
 AND l.license_scope IN ('PACKAGE','REPOSITORY_INHERITED') AND jsonb_array_length(l.license_files)>0
 AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(l.license_files) f WHERE jsonb_typeof(f)<>'object' OR COALESCE(f->>'path','')='' OR COALESCE(f->>'sha256','') !~ '^[0-9a-f]{64}$')
 AND l.evidence->>'policy'='ADMIN_HUMAN_OFFLINE_V1' AND l.evidence->>'sourceSha256'=a.source_sha256::text
 AND COALESCE(l.evidence->>'coverage','')<>'' AND COALESCE(l.evidence->>'thirdPartyReview','')<>'' AND COALESCE(l.evidence->>'approvalEvidence','')<>'',false),
 (SELECT count(*) FROM judge.problem_test_cases WHERE package_artifact_id=a.id),
 (SELECT count(*) FROM judge.problem_test_cases WHERE package_artifact_id=a.id AND visibility='SAMPLE'),
 (SELECT count(*) FROM judge.problem_test_cases WHERE package_artifact_id=a.id AND visibility='SECRET'),
 (SELECT count(*) FROM judge.reference_solutions WHERE package_artifact_id=a.id AND role='ACCEPTED')
 FROM judge.problem_versions v JOIN judge.package_artifacts a ON a.id=v.package_artifact_id
 JOIN judge.license_evidence l ON l.id=a.license_evidence_id LEFT JOIN judge.package_validation_runs r ON r.id=a.validation_run_id AND r.package_artifact_id=a.id
 WHERE v.problem_id=$1 AND v.id=$2`, string(id), string(versionID)).Scan(&mode, &statement, &sampleCount, &licenseStatus, &selected, &approved, &tests, &samples, &secrets, &accepted)
	if errors.Is(err, sql.ErrNoRows) {
		return workflowError("PROBLEM_VERSION_CONFLICT")
	}
	if err != nil {
		return err
	}
	if licenseStatus != "VERIFIED" || !approved {
		return workflowError("PACKAGE_LICENSE_MISSING")
	}
	if mode != "BATCH_PASS_FAIL" {
		return workflowError("PACKAGE_UNSUPPORTED")
	}
	if !selected || strings.TrimSpace(statement) == "" || sampleCount == 0 || tests == 0 || samples == 0 || secrets == 0 || accepted == 0 {
		return workflowError("PACKAGE_INVALID")
	}
	return nil
}

func (tx *Tx) PublishVersion(id contract.ID, versionID contract.UUID) (contract.PlatformProblemDetail, error) {
	status, current, err := tx.lockWorkflowProblem(id)
	if err != nil {
		return contract.PlatformProblemDetail{}, err
	}
	if err := tx.CheckEligibility(id, versionID); err != nil {
		return contract.PlatformProblemDetail{}, err
	}
	if status == contract.ProblemPublished && current != nil && strings.EqualFold(string(*current), string(versionID)) {
		return tx.PublicDetail(id, &versionID, false)
	}
	// All writers lock the problem before the singleton catalog row. Public
	// timestamps advance even if the clock has sub-microsecond resolution.
	var version string
	if err := tx.DB().QueryRowContext(tx.ctx, `UPDATE judge.catalog_state SET catalog_version=catalog_version+1,updated_at=clock_timestamp() WHERE singleton_id=1 RETURNING catalog_version::text`).Scan(&version); err != nil {
		return contract.PlatformProblemDetail{}, err
	}
	_, err = tx.DB().ExecContext(tx.ctx, `UPDATE judge.problem_versions SET first_published_at=clock_timestamp() WHERE problem_id=$1 AND id=$2 AND first_published_at IS NULL`, string(id), string(versionID))
	if err != nil {
		return contract.PlatformProblemDetail{}, err
	}
	_, err = tx.DB().ExecContext(tx.ctx, `UPDATE judge.platform_problems SET status='PUBLISHED',current_version_id=$2,public_updated_at=GREATEST(clock_timestamp(),COALESCE(public_updated_at+interval '1 microsecond','-infinity'::timestamptz)),updated_at=clock_timestamp(),withdrawn_at=NULL,withdrawal_reason=NULL WHERE id=$1`, string(id), string(versionID))
	if err != nil {
		return contract.PlatformProblemDetail{}, err
	}
	return tx.PublicDetail(id, &versionID, false)
}

func (tx *Tx) WithdrawProblem(id contract.ID, reason string) (contract.WithdrawResponse, error) {
	out := contract.WithdrawResponse{ProblemID: id, Status: contract.ProblemWithdrawn}
	status, current, err := tx.lockWorkflowProblem(id)
	if err != nil {
		return out, err
	}
	if current == nil {
		return out, workflowError("PROBLEM_NOT_SUBMITTABLE")
	}
	if status == contract.ProblemWithdrawn {
		err = tx.DB().QueryRowContext(tx.ctx, `SELECT catalog_version::text FROM judge.catalog_state WHERE singleton_id=1`).Scan(&out.CatalogVersion)
		return out, err
	}
	if err := tx.DB().QueryRowContext(tx.ctx, `UPDATE judge.catalog_state SET catalog_version=catalog_version+1,updated_at=clock_timestamp() WHERE singleton_id=1 RETURNING catalog_version::text`).Scan(&out.CatalogVersion); err != nil {
		return out, err
	}
	_, err = tx.DB().ExecContext(tx.ctx, `UPDATE judge.platform_problems SET status='WITHDRAWN',withdrawal_reason=$2,withdrawn_at=clock_timestamp(),public_updated_at=GREATEST(clock_timestamp(),public_updated_at+interval '1 microsecond'),updated_at=clock_timestamp() WHERE id=$1`, string(id), reason)
	return out, err
}
