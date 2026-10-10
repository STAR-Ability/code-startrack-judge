// Package imports implements durable fixed-source jobs in the Judge schema.
package imports

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	domain "github.com/STAR-Ability/code-startrack-judge/internal/imports"
)

type Repository struct{ db *sql.DB }

func New(db *sql.DB) *Repository { return &Repository{db: db} }

type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

const jobColumns = `id::text,request_id::text,request_hash,status,revision,source,repository_url,source_revision,package_count,completed_package_count,error,created_at,updated_at,finished_at`

func readJob(ctx context.Context, q queryer, where string, arg any) (contract.ImportJob, string, error) {
	var job contract.ImportJob
	var hash string
	var rawError []byte
	var created, updated time.Time
	var finished sql.NullTime
	err := q.QueryRowContext(ctx, "SELECT "+jobColumns+" FROM judge.import_jobs WHERE "+where, arg).Scan(&job.ImportJobID, &job.RequestID, &hash, &job.Status, &job.Revision, &job.Source, &job.RepositoryURL, &job.SourceRevision, &job.PackageCount, &job.CompletedPackageCount, &rawError, &created, &updated, &finished)
	if errors.Is(err, sql.ErrNoRows) {
		return job, "", domain.ErrNotFound
	}
	if err != nil {
		return job, "", domain.ErrUnavailable
	}
	job.TaskBase.Status = string(job.Status)
	job.CreatedAt, job.UpdatedAt = contract.UTC(created), contract.UTC(updated)
	if finished.Valid {
		value := contract.UTC(finished.Time)
		job.FinishedAt = &value
	}
	if len(rawError) != 0 && string(rawError) != "null" {
		if json.Unmarshal(rawError, &job.Error) != nil {
			return job, "", domain.ErrUnavailable
		}
		if job.Error != nil {
			safe, ok := domain.PublicDiagnostic(job.Error.Code)
			if !ok {
				return job, "", domain.ErrUnavailable
			}
			job.Error = &safe
		}
	}
	rows, err := q.QueryContext(ctx, `SELECT package_path,status,problem_id::text,problem_version_id::text,license_status,validation_status,errors FROM judge.import_items WHERE import_job_id=$1 ORDER BY ordinal`, job.ImportJobID)
	if err != nil {
		return job, "", domain.ErrUnavailable
	}
	defer rows.Close()
	job.Items = make(contract.Array[contract.ImportItem], 0, job.PackageCount)
	for rows.Next() {
		var item contract.ImportItem
		var problem, version sql.NullString
		var raw []byte
		if rows.Scan(&item.PackagePath, &item.Status, &problem, &version, &item.LicenseStatus, &item.ValidationStatus, &raw) != nil {
			return job, "", domain.ErrUnavailable
		}
		if problem.Valid {
			id := contract.ID(problem.String)
			item.ProblemID = &id
		}
		if version.Valid {
			id := contract.UUID(version.String)
			item.ProblemVersionID = &id
		}
		if json.Unmarshal(raw, &item.Errors) != nil {
			return job, "", domain.ErrUnavailable
		}
		item.Errors, err = domain.NormalizeDiagnostics(item.Errors)
		if err != nil {
			return job, "", err
		}
		job.Items = append(job.Items, item)
	}
	if rows.Err() != nil || job.Validate() != nil {
		return job, "", domain.ErrUnavailable
	}
	return job, hash, nil
}

func (r *Repository) consistentRead(ctx context.Context, where string, arg any) (contract.ImportJob, string, error) {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return contract.ImportJob{}, "", domain.ErrUnavailable
	}
	defer tx.Rollback()
	job, hash, err := readJob(ctx, tx, where, arg)
	if err != nil {
		return job, "", err
	}
	if tx.Commit() != nil {
		return job, "", domain.ErrUnavailable
	}
	return job, hash, nil
}
func (r *Repository) FindByRequest(ctx context.Context, id contract.UUID) (contract.ImportJob, string, error) {
	return r.consistentRead(ctx, "request_id=$1", id)
}
func (r *Repository) Get(ctx context.Context, id contract.UUID) (contract.ImportJob, error) {
	job, _, err := r.consistentRead(ctx, "id=$1", id)
	return job, err
}

func (r *Repository) Accept(ctx context.Context, request contract.ImportRequest, hash string) (contract.ImportJob, bool, error) {
	if request.Validate() != nil {
		return contract.ImportJob{}, false, contract.Invalid("import")
	}
	raw, _ := json.Marshal(request)
	expected, err := canonical.RequestHash("IMPORT", nil, raw)
	if err != nil || expected != hash {
		return contract.ImportJob{}, false, contract.Invalid("requestHash")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return contract.ImportJob{}, false, domain.ErrUnavailable
	}
	defer tx.Rollback()
	id, err := contract.NewUUID()
	if err != nil {
		return contract.ImportJob{}, false, domain.ErrUnavailable
	}
	var inserted string
	err = tx.QueryRowContext(ctx, `INSERT INTO judge.import_jobs(id,request_id,request_hash,source,repository_url,source_revision,status,package_count) VALUES($1,$2,$3,$4,$5,$6,'QUEUED',$7) ON CONFLICT(request_id) DO NOTHING RETURNING id::text`, id, request.RequestID, hash, request.Source, request.RepositoryURL, request.Revision, len(request.PackagePaths)).Scan(&inserted)
	created := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return contract.ImportJob{}, false, domain.ErrUnavailable
	}
	if created {
		for index, path := range request.PackagePaths {
			itemID, err := contract.NewUUID()
			if err != nil {
				return contract.ImportJob{}, false, domain.ErrUnavailable
			}
			if _, err = tx.ExecContext(ctx, `INSERT INTO judge.import_items(id,import_job_id,ordinal,package_path,status,license_status,validation_status) VALUES($1,$2,$3,$4,'PENDING','PENDING','PENDING')`, itemID, id, index+1, path); err != nil {
				return contract.ImportJob{}, false, domain.ErrUnavailable
			}
		}
	}
	job, existingHash, err := readJob(ctx, tx, "request_id=$1", request.RequestID)
	if err != nil {
		return job, false, err
	}
	if existingHash != hash {
		return contract.ImportJob{}, false, domain.ErrConflict
	}
	if tx.Commit() != nil {
		return contract.ImportJob{}, false, domain.ErrUnavailable
	}
	return job, created, nil
}

func (r *Repository) Claim(ctx context.Context) (*domain.Lease, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, domain.ErrUnavailable
	}
	defer tx.Rollback()
	var lease domain.Lease
	var status string
	var attempts int
	err = tx.QueryRowContext(ctx, `SELECT id::text,source_revision,status,attempt_count FROM judge.import_jobs WHERE status='QUEUED' OR (status='RUNNING' AND lease_expires_at<=clock_timestamp()) ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(&lease.JobID, &lease.Revision, &status, &attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, domain.ErrUnavailable
	}
	rows, err := tx.QueryContext(ctx, `SELECT id::text,ordinal,package_path FROM judge.import_items WHERE import_job_id=$1 AND status='PENDING' ORDER BY ordinal`, lease.JobID)
	if err != nil {
		return nil, domain.ErrUnavailable
	}
	for rows.Next() {
		var item domain.PendingItem
		if rows.Scan(&item.ID, &item.Ordinal, &item.PackagePath) != nil {
			rows.Close()
			return nil, domain.ErrUnavailable
		}
		lease.Items = append(lease.Items, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, domain.ErrUnavailable
	}
	if status == "RUNNING" && attempts == 3 {
		for _, item := range lease.Items {
			result := interruption(item.PackagePath)
			if err := writeItem(ctx, tx, lease, item, result); err != nil {
				return nil, err
			}
		}
		if err := summarize(ctx, tx, lease.JobID); err != nil {
			return nil, err
		}
		if tx.Commit() != nil {
			return nil, domain.ErrUnavailable
		}
		return nil, nil
	}
	lease.Token, err = contract.NewUUID()
	if err != nil {
		return nil, domain.ErrUnavailable
	}
	if status == "RUNNING" {
		attempts++
	}
	_, err = tx.ExecContext(ctx, `UPDATE judge.import_jobs SET status='RUNNING',revision=revision+1,started_at=COALESCE(started_at,clock_timestamp()),updated_at=clock_timestamp(),lease_owner=$2,lease_expires_at=clock_timestamp()+interval '180 seconds',attempt_count=$3 WHERE id=$1`, lease.JobID, lease.Token, attempts)
	if err != nil || tx.Commit() != nil {
		return nil, domain.ErrUnavailable
	}
	return &lease, nil
}

func (r *Repository) Heartbeat(ctx context.Context, lease domain.Lease) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.ErrUnavailable
	}
	defer tx.Rollback()
	// Acquire the row before evaluating the deadline. PostgreSQL can evaluate a
	// volatile UPDATE predicate before waiting on an unchanged locked tuple.
	var locked string
	err = tx.QueryRowContext(ctx, `SELECT id::text FROM judge.import_jobs WHERE id=$1 FOR UPDATE`, lease.JobID).Scan(&locked)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrLeaseLost
	}
	if err != nil {
		return domain.ErrUnavailable
	}
	result, err := tx.ExecContext(ctx, `UPDATE judge.import_jobs SET lease_expires_at=clock_timestamp()+interval '180 seconds' WHERE id=$1 AND status='RUNNING' AND lease_owner=$2 AND lease_expires_at>clock_timestamp()`, lease.JobID, lease.Token)
	if err != nil {
		return domain.ErrUnavailable
	}
	n, err := result.RowsAffected()
	if err != nil {
		return domain.ErrUnavailable
	}
	if n != 1 {
		return domain.ErrLeaseLost
	}
	if tx.Commit() != nil {
		return domain.ErrUnavailable
	}
	return nil
}

func (r *Repository) CompleteItem(ctx context.Context, lease domain.Lease, item domain.PendingItem, prepared domain.Prepared) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.ErrUnavailable
	}
	defer tx.Rollback()
	var id string
	err = tx.QueryRowContext(ctx, `SELECT id::text FROM judge.import_jobs WHERE id=$1 AND status='RUNNING' AND lease_owner=$2 AND lease_expires_at>clock_timestamp() FOR UPDATE`, lease.JobID, lease.Token).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrLeaseLost
	}
	if err != nil {
		return domain.ErrUnavailable
	}
	var actualPath string
	var ordinal int
	err = tx.QueryRowContext(ctx, `SELECT package_path,ordinal FROM judge.import_items WHERE id=$1 AND import_job_id=$2 AND status='PENDING' FOR UPDATE`, item.ID, lease.JobID).Scan(&actualPath, &ordinal)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrLeaseLost
	}
	if err != nil || actualPath != item.PackagePath || ordinal != item.Ordinal {
		return domain.ErrUnavailable
	}
	if prepared == nil {
		return domain.ErrUnavailable
	}
	result, err := prepared.Apply(ctx, tx, item)
	if err != nil {
		return err
	}
	if err := writeItem(ctx, tx, lease, item, result); err != nil {
		return err
	}
	// The preparation registration must still fit within the lease. This final
	// check also prevents an expired owner committing before another claim.
	err = tx.QueryRowContext(ctx, `SELECT id::text FROM judge.import_jobs WHERE id=$1 AND status='RUNNING' AND lease_owner=$2 AND lease_expires_at>clock_timestamp()`, lease.JobID, lease.Token).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrLeaseLost
	}
	if err != nil {
		return domain.ErrUnavailable
	}
	if err := summarize(ctx, tx, lease.JobID); err != nil {
		return err
	}
	if tx.Commit() != nil {
		return domain.ErrUnavailable
	}
	return nil
}

// RetainAttempt appends incomplete private evidence under the live reservation.
// It never writes item/job status, revision, counters or validation qualification.
func (r *Repository) RetainAttempt(ctx context.Context, lease domain.Lease, item domain.PendingItem, prepared domain.Prepared) error {
	if prepared == nil || lease.JobID.Validate() != nil || lease.Token.Validate() != nil || item.ID.Validate() != nil {
		return domain.ErrUnavailable
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.ErrUnavailable
	}
	defer tx.Rollback()
	var id string
	var recoveryCount int
	// Evaluate the live clock only after the potentially waiting tuple lock.
	err = tx.QueryRowContext(ctx, `SELECT id::text FROM judge.import_jobs WHERE id=$1 FOR UPDATE`, lease.JobID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrLeaseLost
	}
	if err != nil {
		return domain.ErrUnavailable
	}
	err = tx.QueryRowContext(ctx, `SELECT attempt_count FROM judge.import_jobs WHERE id=$1 AND status='RUNNING' AND lease_owner=$2 AND lease_expires_at>clock_timestamp()`, lease.JobID, lease.Token).Scan(&recoveryCount)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrLeaseLost
	}
	if err != nil {
		return domain.ErrUnavailable
	}
	var actualPath string
	var ordinal int
	err = tx.QueryRowContext(ctx, `SELECT package_path,ordinal FROM judge.import_items WHERE id=$1 AND import_job_id=$2 AND status='PENDING' FOR UPDATE`, item.ID, lease.JobID).Scan(&actualPath, &ordinal)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrLeaseLost
	}
	if err != nil || actualPath != item.PackagePath || ordinal != item.Ordinal {
		return domain.ErrUnavailable
	}
	result, err := prepared.Apply(ctx, tx, item)
	if err != nil {
		return err
	}
	e := result.Evidence
	if result.Item.Status != "REJECTED" || result.Item.PackagePath != item.PackagePath || result.Item.Validate() != nil || e == nil || e.FailureStage != "VALIDATION_FAILED" || e.Provenance["complete"] != false || e.Provenance["fencingToken"] != lease.Token || !reflect.DeepEqual(e.Errors, result.Item.Errors) {
		return domain.ErrUnavailable
	}
	safeErrors, err := domain.NormalizeDiagnostics(e.Errors)
	if err != nil {
		return err
	}
	copy := *e
	copy.Errors = safeErrors
	rawErrors, err := json.Marshal(safeErrors)
	if err != nil {
		return domain.ErrUnavailable
	}
	if err := writeEvidence(ctx, tx, lease, item, &copy, rawErrors, &recoveryCount); err != nil {
		return err
	}
	err = tx.QueryRowContext(ctx, `SELECT id::text FROM judge.import_jobs WHERE id=$1 AND status='RUNNING' AND lease_owner=$2 AND lease_expires_at>clock_timestamp()`, lease.JobID, lease.Token).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrLeaseLost
	}
	if err != nil || tx.Commit() != nil {
		return domain.ErrUnavailable
	}
	return nil
}

func interruption(path string) domain.ItemResult {
	errors := contract.Array[contract.TaskError]{{Code: "IMPORT_INTERRUPTED", Message: "Import recovery reservations were exhausted", Retryable: false}}
	return domain.ItemResult{Item: contract.ImportItem{PackagePath: path, Status: "REJECTED", LicenseStatus: "PENDING", ValidationStatus: "PENDING", Errors: errors}, Evidence: &domain.RejectedEvidence{FailureStage: "SOURCE_UNAVAILABLE", Provenance: map[string]any{"recoveryExhausted": true}, SourceMetadata: map[string]any{}, Adaptations: []any{}, Errors: errors}}
}

func writeItem(ctx context.Context, tx *sql.Tx, lease domain.Lease, item domain.PendingItem, result domain.ItemResult) error {
	if result.Item.PackagePath != item.PackagePath || result.Item.Status == "PENDING" || result.Item.Validate() != nil || len(result.Item.Errors) > 16 {
		return domain.ErrUnavailable
	}
	if (result.Item.Status == "REJECTED") != (result.Evidence != nil) {
		return domain.ErrUnavailable
	}
	if result.Evidence != nil && !reflect.DeepEqual(result.Evidence.Errors, result.Item.Errors) {
		return domain.ErrUnavailable
	}
	if result.Evidence != nil && result.Evidence.Provenance["complete"] == false {
		return domain.ErrUnavailable
	}
	safeErrors, err := domain.NormalizeDiagnostics(result.Item.Errors)
	if err != nil {
		return err
	}
	result.Item.Errors = safeErrors
	if result.Evidence != nil {
		copy := *result.Evidence
		copy.Errors = safeErrors
		result.Evidence = &copy
	}
	rawErrors, err := json.Marshal(result.Item.Errors)
	if err != nil {
		return domain.ErrUnavailable
	}
	_, err = tx.ExecContext(ctx, `UPDATE judge.import_items SET status=$2,problem_id=$3,problem_version_id=$4,license_status=$5,validation_status=$6,errors=$7,updated_at=clock_timestamp() WHERE id=$1`, item.ID, result.Item.Status, result.Item.ProblemID, result.Item.ProblemVersionID, result.Item.LicenseStatus, result.Item.ValidationStatus, rawErrors)
	if err != nil {
		return domain.ErrUnavailable
	}
	if result.Evidence != nil {
		return writeEvidence(ctx, tx, lease, item, result.Evidence, rawErrors, nil)
	}
	return nil
}

func writeEvidence(ctx context.Context, tx *sql.Tx, lease domain.Lease, item domain.PendingItem, e *domain.RejectedEvidence, rawErrors []byte, recoveryCount *int) error {
	if e.Provenance == nil || e.SourceMetadata == nil || e.Adaptations == nil || len(e.Errors) == 0 {
		return domain.ErrUnavailable
	}
	raw, err := json.Marshal(struct {
		RepositoryURL  string `json:"repositoryUrl"`
		SourceRevision string `json:"sourceRevision"`
		PackagePath    string `json:"packagePath"`
		*domain.RejectedEvidence
	}{contract.PackageRepository, lease.Revision, item.PackagePath, e})
	if err != nil || len(raw) > 64<<20 {
		return domain.ErrUnavailable
	}
	hash, err := canonical.HashJSON(raw)
	if err != nil {
		return domain.ErrUnavailable
	}
	provenance, _ := json.Marshal(e.Provenance)
	metadata, _ := json.Marshal(e.SourceMetadata)
	adaptations, _ := json.Marshal(e.Adaptations)
	id := e.ID
	if id == "" {
		id, err = contract.NewUUID()
	}
	if err != nil || id.Validate() != nil {
		return domain.ErrUnavailable
	}
	arguments := []any{id, item.ID, contract.PackageRepository, lease.Revision, item.PackagePath, e.FailureStage, e.SourceArchiveKey, e.SourceSHA256, e.NormalizedArchiveKey, e.NormalizedSHA256, e.LicenseEvidenceID, provenance, metadata, adaptations, rawErrors, e.ValidationLogKey, hash}
	statement := `INSERT INTO judge.rejected_package_evidence(id,import_item_id,repository_url,source_revision,package_path,failure_stage,source_archive_key,source_sha256,normalized_archive_key,normalized_sha256,license_evidence_id,provenance,source_metadata,adaptations,errors,validation_log_key,evidence_sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`
	if recoveryCount != nil {
		statement = `INSERT INTO judge.import_attempt_evidence(id,import_item_id,repository_url,source_revision,package_path,failure_stage,source_archive_key,source_sha256,normalized_archive_key,normalized_sha256,license_evidence_id,provenance,source_metadata,adaptations,errors,validation_log_key,evidence_sha256,attempt_token,recovery_count) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`
		arguments = append(arguments, lease.Token, *recoveryCount)
	}
	_, err = tx.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return domain.ErrUnavailable
	}
	return nil
}

func summarize(ctx context.Context, tx *sql.Tx, id contract.UUID) error {
	var total, done, passed int
	err := tx.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER(WHERE status<>'PENDING'),count(*) FILTER(WHERE status='VALIDATED') FROM judge.import_items WHERE import_job_id=$1`, id).Scan(&total, &done, &passed)
	if err != nil || total == 0 {
		return domain.ErrUnavailable
	}
	status := "RUNNING"
	var diagnostic *contract.TaskError
	if done == total {
		switch {
		case passed == total:
			status = "SUCCEEDED"
		case passed == 0:
			status = "FAILED"
		default:
			status = "PARTIAL"
		}
		if status != "SUCCEEDED" {
			diagnostic = &contract.TaskError{Code: "PACKAGE_INVALID", Message: "One or more packages were rejected; inspect item errors", Retryable: false}
		}
	}
	raw, _ := json.Marshal(diagnostic)
	_, err = tx.ExecContext(ctx, `UPDATE judge.import_jobs SET completed_package_count=$2,status=$3,revision=revision+1,updated_at=clock_timestamp(),error=NULLIF($4::jsonb,'null'::jsonb),finished_at=CASE WHEN $3='RUNNING' THEN NULL ELSE clock_timestamp() END,lease_owner=CASE WHEN $3='RUNNING' THEN lease_owner ELSE NULL END,lease_expires_at=CASE WHEN $3='RUNNING' THEN lease_expires_at ELSE NULL END WHERE id=$1`, id, done, status, raw)
	if err != nil {
		return domain.ErrUnavailable
	}
	return nil
}
