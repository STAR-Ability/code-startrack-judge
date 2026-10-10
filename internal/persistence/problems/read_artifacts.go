package problems

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
)

// LoadArtifact returns private frozen execution facts, never a public DTO.
// An absent lifecycle identity is an integrity error, not a guessed byte size.
func (tx *Tx) LoadArtifact(id contract.UUID) (Artifact, error) {
	if id.Validate() != nil {
		return Artifact{}, ErrInvalid
	}
	var artifact Artifact
	var contextJSON json.RawMessage
	err := tx.db.QueryRowContext(tx.ctx, `SELECT a.id::text,a.problem_id::text,a.content_identity_id::text,c.source_identity_id::text,
 a.source,a.repository_url,a.package_path,a.source_revision,a.adapter_version,
 a.source_archive_key,a.source_sha256::text,coalesce(s.size_bytes,-1),
 a.normalized_archive_key,a.normalized_sha256::text,coalesce(n.size_bytes,-1),
 a.manifest,a.source_metadata,a.license_evidence_id::text,a.validation_context,
 c.manifest_sha256::text,a.evidence_set_hash::text,a.validation_run_id::text,a.created_at
 FROM judge.package_artifacts a JOIN judge.package_content_identities c ON c.id=a.content_identity_id
 LEFT JOIN judge.private_objects s ON s.object_key=a.source_archive_key
 LEFT JOIN judge.private_objects n ON n.object_key=a.normalized_archive_key WHERE a.id=$1`, string(id)).Scan(
		&artifact.ID, &artifact.Spec.ProblemID, &artifact.ContentIdentityID, &artifact.SourceIdentityID,
		&artifact.Spec.Identity.Source, &artifact.Spec.Identity.RepositoryURL, &artifact.Spec.Identity.PackagePath, &artifact.Spec.SourceRevision, &artifact.Spec.AdapterVersion,
		&artifact.Spec.SourceArchive.Key, &artifact.Spec.SourceArchive.SHA256, &artifact.Spec.SourceArchive.SizeBytes,
		&artifact.Spec.NormalizedArchive.Key, &artifact.Spec.NormalizedArchive.SHA256, &artifact.Spec.NormalizedArchive.SizeBytes,
		&artifact.Spec.Manifest, &artifact.Spec.SourceMetadata, &artifact.Spec.LicenseEvidenceID, &contextJSON,
		&artifact.ManifestSHA256, &artifact.EvidenceSetHash, &artifact.ValidationRunID, &artifact.CreatedAt)
	if err != nil {
		return Artifact{}, dbError(err)
	}
	if json.Unmarshal(contextJSON, &artifact.Spec.ValidationContext) != nil || artifact.Spec.SourceArchive.Validate() != nil || artifact.Spec.NormalizedArchive.Validate() != nil {
		return Artifact{}, ErrIntegrity
	}
	return artifact, nil
}

func (tx *Tx) ListTests(artifactID contract.UUID) ([]TestCase, error) {
	if artifactID.Validate() != nil {
		return nil, ErrInvalid
	}
	rows, err := tx.db.QueryContext(tx.ctx, `SELECT id::text,package_artifact_id::text,ordinal,visibility,input_object_key,input_sha256::text,input_size_bytes,answer_object_key,answer_sha256::text,answer_size_bytes,validation_group FROM judge.problem_test_cases WHERE package_artifact_id=$1 ORDER BY ordinal`, string(artifactID))
	if err != nil {
		return nil, dbError(err)
	}
	defer rows.Close()
	out := make([]TestCase, 0)
	for rows.Next() {
		var test TestCase
		if err := rows.Scan(&test.ID, &test.PackageArtifactID, &test.Ordinal, &test.Visibility, &test.Input.Key, &test.Input.SHA256, &test.Input.SizeBytes, &test.Answer.Key, &test.Answer.SHA256, &test.Answer.SizeBytes, &test.ValidationGroup); err != nil {
			return nil, dbError(err)
		}
		if test.Input.Validate() != nil || test.Answer.Validate() != nil {
			return nil, ErrIntegrity
		}
		out = append(out, test)
	}
	return out, dbError(rows.Err())
}

func (tx *Tx) ListReferences(artifactID contract.UUID) ([]ReferenceSolution, error) {
	if artifactID.Validate() != nil {
		return nil, ErrInvalid
	}
	rows, err := tx.db.QueryContext(tx.ctx, `SELECT r.id::text,r.package_artifact_id::text,r.role,r.language_id,r.source_object_key,r.source_sha256::text,coalesce(o.size_bytes,-1),r.upstream_path FROM judge.reference_solutions r LEFT JOIN judge.private_objects o ON o.object_key=r.source_object_key WHERE r.package_artifact_id=$1 ORDER BY r.upstream_path,r.id`, string(artifactID))
	if err != nil {
		return nil, dbError(err)
	}
	defer rows.Close()
	out := make([]ReferenceSolution, 0)
	for rows.Next() {
		var reference ReferenceSolution
		if err := rows.Scan(&reference.ID, &reference.PackageArtifactID, &reference.Role, &reference.LanguageID, &reference.Source.Key, &reference.Source.SHA256, &reference.Source.SizeBytes, &reference.UpstreamPath); err != nil {
			return nil, dbError(err)
		}
		if reference.Source.Validate() != nil {
			return nil, ErrIntegrity
		}
		out = append(out, reference)
	}
	return out, dbError(rows.Err())
}

func (r *Repository) LoadArtifact(ctx context.Context, id contract.UUID) (Artifact, error) {
	var out Artifact
	err := r.WithTx(ctx, &sql.TxOptions{ReadOnly: true}, func(tx *Tx) error { var err error; out, err = tx.LoadArtifact(id); return err })
	return out, err
}
func (r *Repository) ListTests(ctx context.Context, id contract.UUID) ([]TestCase, error) {
	var out []TestCase
	err := r.WithTx(ctx, &sql.TxOptions{ReadOnly: true}, func(tx *Tx) error { var err error; out, err = tx.ListTests(id); return err })
	return out, err
}
func (r *Repository) ListReferences(ctx context.Context, id contract.UUID) ([]ReferenceSolution, error) {
	var out []ReferenceSolution
	err := r.WithTx(ctx, &sql.TxOptions{ReadOnly: true}, func(tx *Tx) error { var err error; out, err = tx.ListReferences(id); return err })
	return out, err
}
