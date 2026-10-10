// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/packages"
	"github.com/STAR-Ability/code-startrack-judge/internal/storage"
	"github.com/STAR-Ability/code-startrack-judge/internal/testutil/importcapacity"
)

type archiveFacts struct {
	files        int
	regularBytes int64
	manifest     *packages.Manifest
	manifestSHA  string
}

type contextReader struct {
	ctx context.Context
	in  io.Reader
}

func (r contextReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.in.Read(data)
}

// Scan the retained USTAR without a second complete archive allocation. Hashes
// cover actual bytes through the same handle as member counts and manifest data.
func scanArchive(ctx context.Context, input io.Reader, object storage.Object, normalized bool) (archiveFacts, error) {
	facts := archiveFacts{}
	if object.Validate() != nil || object.SizeBytes > packages.MaxArchiveBytes {
		return facts, errQualification
	}
	digest := sha256.New()
	limited := &io.LimitedReader{R: contextReader{ctx, input}, N: object.SizeBytes + 1}
	stream := io.TeeReader(limited, digest)
	archive := tar.NewReader(stream)
	seen := make(map[string]bool)
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || header.Format != tar.FormatUSTAR || header.Typeflag != tar.TypeReg || packages.ValidatePath(header.Name) != nil || seen[header.Name] || header.Size < 0 || header.Size > packages.MaxFileBytes || facts.files >= packages.MaxFiles || facts.regularBytes+header.Size > packages.MaxTotalBytes {
			return facts, errQualification
		}
		seen[header.Name] = true
		facts.files++
		facts.regularBytes += header.Size
		if normalized && header.Name == packages.ReservedManifestPath {
			raw, err := io.ReadAll(io.LimitReader(archive, packages.MaxFileBytes+1))
			if err != nil || int64(len(raw)) != header.Size || canonical.ValidateJSON(raw) != nil {
				return facts, errQualification
			}
			var manifest packages.Manifest
			decoder := json.NewDecoder(strings.NewReader(string(raw)))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&manifest) != nil || packages.ValidateManifest(manifest) != nil {
				return facts, errQualification
			}
			facts.manifest, facts.manifestSHA = &manifest, canonical.HashBytes(raw)
		} else if _, err := io.Copy(io.Discard, archive); err != nil {
			return facts, errQualification
		}
	}
	if _, err := io.Copy(io.Discard, stream); err != nil || object.SizeBytes+1-limited.N != object.SizeBytes || hex.EncodeToString(digest.Sum(nil)) != object.SHA256 || normalized && facts.manifest == nil {
		return facts, errQualification
	}
	return facts, nil
}

func retainedArchive(ctx context.Context, store *storage.Store, object storage.Object, normalized bool) (archiveFacts, error) {
	if store.Verify(ctx, object) != nil {
		return archiveFacts{}, errQualification
	}
	root, err := os.OpenRoot(privateDirectory)
	if err != nil {
		return archiveFacts{}, errQualification
	}
	defer root.Close()
	parts := strings.Split(object.Key, "/")
	for index := 1; index < len(parts); index++ {
		info, err := root.Lstat(strings.Join(parts[:index], "/"))
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return archiveFacts{}, errQualification
		}
	}
	info, err := root.Lstat(object.Key)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0400 {
		return archiveFacts{}, errQualification
	}
	file, err := root.Open(object.Key)
	if err != nil {
		return archiveFacts{}, errQualification
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || opened.Size() != object.SizeBytes {
		return archiveFacts{}, errQualification
	}
	return scanArchive(ctx, file, object, normalized)
}

func archiveEvidence(ctx context.Context, store *storage.Store, current *caseReport, source, normalized storage.Object) error {
	sourceFacts, err := retainedArchive(ctx, store, source, false)
	if err != nil {
		return errQualification
	}
	normalizedFacts, err := retainedArchive(ctx, store, normalized, true)
	if err != nil || normalizedFacts.manifest.Source != packages.PinnedSource(current.PackagePath) || normalizedFacts.manifest.Limits.TimeLimitMS != 2000 || normalizedFacts.manifest.Limits.MemoryLimitBytes != 256<<20 || len(normalizedFacts.manifest.Files)+1 != normalizedFacts.files {
		return errQualification
	}
	if current.SourceFiles != 0 && (sourceFacts.files != current.SourceFiles || sourceFacts.regularBytes != current.SourceRegularBytes) {
		return errQualification
	}
	if current.SourceSHA256 != "" && (source.SHA256 != current.SourceSHA256 || normalized.SHA256 != current.NormalizedSHA256) {
		return errQualification
	}
	if current.Name == importcapacity.MemberPayload && (sourceFacts.files != packages.MaxFiles-2 || normalizedFacts.files != packages.MaxFiles || normalizedFacts.regularBytes != packages.MaxTotalBytes) {
		return errQualification
	}
	current.SampleTextBytes = 0
	for _, test := range normalizedFacts.manifest.Tests {
		if test.Visibility == "SAMPLE" {
			current.SampleTextBytes += test.Input.SizeBytes + test.Answer.SizeBytes
		}
	}
	if current.Name == importcapacity.SampleHeavy || current.Name == importcapacity.SampleSupported {
		sampleBytes := int64(importcapacity.SampleBytes)
		if current.Name == importcapacity.SampleSupported {
			sampleBytes = importcapacity.SupportedSampleBytes
		}
		largeSamples := 0
		for _, test := range normalizedFacts.manifest.Tests {
			if test.Visibility == "SAMPLE" && test.Input.SizeBytes == sampleBytes && test.Answer.SizeBytes == sampleBytes {
				largeSamples++
			}
		}
		if sourceFacts.files != 16 || normalizedFacts.files != 18 || largeSamples != 1 || current.SampleTextBytes != 2*sampleBytes+6 {
			return errQualification
		}
	}
	current.SourceFiles, current.SourceRegularBytes = sourceFacts.files, sourceFacts.regularBytes
	current.SourceArchiveBytes, current.SourceSHA256 = source.SizeBytes, source.SHA256
	current.NormalizedFiles, current.NormalizedRegularBytes = normalizedFacts.files, normalizedFacts.regularBytes
	current.NormalizedArchiveBytes, current.NormalizedSHA256 = normalized.SizeBytes, normalized.SHA256
	current.ManifestSHA256 = normalizedFacts.manifestSHA
	return nil
}

func previousRejection(ctx context.Context, db *sql.DB, store *storage.Store, current *caseReport, approval bool) error {
	var source, normalized storage.Object
	var jobID string
	var automatic bool
	err := db.QueryRowContext(ctx, `SELECT r.id::text,r.license_evidence_id::text,i.import_job_id::text,
 r.source_archive_key,r.source_sha256::text,s.size_bytes,r.normalized_archive_key,r.normalized_sha256::text,n.size_bytes,
 e.status='REVIEW_REQUIRED' AND e.evidence->>'policy'='AUTOMATIC_COLLECTION_REQUIRES_ADMIN_V1' AND e.evidence->'licenseTexts'->>'LICENSE'=$4
 AND j.status='FAILED' AND i.status='REJECTED' AND i.license_status='REVIEW_REQUIRED' AND r.failure_stage='LICENSE_REVIEW'
 AND e.evidence->>'sourceSha256'=r.source_sha256::text AND e.evidence->>'normalizedSha256'=r.normalized_sha256::text
 AND EXISTS(SELECT 1 FROM judge.private_object_references WHERE owner_type='REJECTED' AND owner_id=r.id AND role='SOURCE' AND object_key=r.source_archive_key)
 AND EXISTS(SELECT 1 FROM judge.private_object_references WHERE owner_type='REJECTED' AND owner_id=r.id AND role='NORMALIZED' AND object_key=r.normalized_archive_key)
 FROM judge.rejected_package_evidence r JOIN judge.import_items i ON i.id=r.import_item_id JOIN judge.import_jobs j ON j.id=i.import_job_id
 JOIN judge.license_evidence e ON e.id=r.license_evidence_id JOIN judge.private_objects s ON s.object_key=r.source_archive_key JOIN judge.private_objects n ON n.object_key=r.normalized_archive_key
 WHERE r.repository_url=$1 AND r.source_revision=$2 AND r.package_path=$3 AND r.failure_stage='LICENSE_REVIEW'`, packages.RepositoryURL, packages.PinnedRevision, current.PackagePath, importcapacity.LicenseText).Scan(&current.RejectedEvidenceID, &current.PreviousLicenseEvidenceID, &jobID, &source.Key, &source.SHA256, &source.SizeBytes, &normalized.Key, &normalized.SHA256, &normalized.SizeBytes, &automatic)
	if err != nil || !automatic || !approval && jobID != current.JobID || archiveEvidence(ctx, store, current, source, normalized) != nil {
		return errQualification
	}
	if approval {
		if db.QueryRowContext(ctx, `SELECT id::text FROM judge.license_evidence WHERE previous_evidence_id=$1 AND repository_url=$2 AND source_revision=$3 AND package_path=$4 AND status='VERIFIED' AND reviewed_by IS NOT NULL AND reviewed_at IS NOT NULL AND evidence->>'policy'='ADMIN_HUMAN_OFFLINE_V1' AND evidence->>'sourceSha256'=$5 AND evidence->>'normalizedSha256'=$6 AND EXISTS(SELECT 1 FROM jsonb_array_elements(license_files) f WHERE f->>'path'='LICENSE' AND f->>'sha256'=$7)`, current.PreviousLicenseEvidenceID, packages.RepositoryURL, packages.PinnedRevision, current.PackagePath, source.SHA256, normalized.SHA256, current.LicenseTextSHA256).Scan(&current.ApprovedLicenseEvidenceID) != nil || contract.UUID(current.ApprovedLicenseEvidenceID).Validate() != nil || current.ApprovedLicenseEvidenceID == current.PreviousLicenseEvidenceID {
			return errQualification
		}
	}
	return nil
}

func oversizeEvidence(ctx context.Context, db *sql.DB, store *storage.Store, current *caseReport) error {
	if current.Name != importcapacity.SampleHeavy || current.RejectedEvidenceID == "" || current.PreviousLicenseEvidenceID == "" || current.ApprovedLicenseEvidenceID == "" {
		return errQualification
	}
	var source, normalized storage.Object
	var valid bool
	err := db.QueryRowContext(ctx, `SELECT r.id::text,r.failure_stage,r.errors->0->>'code',
 r.source_archive_key,r.source_sha256::text,s.size_bytes,r.normalized_archive_key,r.normalized_sha256::text,n.size_bytes,
 j.status='FAILED' AND i.status='REJECTED' AND i.license_status='VERIFIED' AND i.validation_status='FAILED'
 AND i.problem_id IS NULL AND i.problem_version_id IS NULL AND jsonb_array_length(i.errors)=1
 AND i.errors->0->>'code'='PACKAGE_UNSUPPORTED' AND i.errors->0->>'retryable'='false' AND r.errors=i.errors
 AND r.failure_stage='UNSUPPORTED' AND r.validation_log_key IS NULL AND NOT (r.provenance ? 'validation')
 AND s.sha256=r.source_sha256 AND n.sha256=r.normalized_sha256
 AND e.id=$7 AND e.status='VERIFIED' AND e.previous_evidence_id=$5 AND e.reviewed_by IS NOT NULL AND e.reviewed_at IS NOT NULL
 AND e.repository_url=r.repository_url AND e.source_revision=r.source_revision AND e.package_path=r.package_path
 AND e.evidence->>'policy'='ADMIN_HUMAN_OFFLINE_V1' AND e.evidence->>'sourceSha256'=r.source_sha256::text AND e.evidence->>'normalizedSha256'=r.normalized_sha256::text
 AND EXISTS(SELECT 1 FROM jsonb_array_elements(e.license_files) f WHERE f->>'path'='LICENSE' AND f->>'sha256'=$6)
 AND (SELECT count(*) FROM judge.rejected_package_evidence WHERE import_item_id=i.id)=1
 AND (SELECT count(*) FROM judge.private_object_references WHERE owner_type='REJECTED' AND owner_id=r.id)=2
 AND EXISTS(SELECT 1 FROM judge.private_object_references WHERE owner_type='REJECTED' AND owner_id=r.id AND role='SOURCE' AND object_key=r.source_archive_key)
 AND EXISTS(SELECT 1 FROM judge.private_object_references WHERE owner_type='REJECTED' AND owner_id=r.id AND role='NORMALIZED' AND object_key=r.normalized_archive_key)
 AND NOT EXISTS(SELECT 1 FROM judge.platform_problems WHERE repository_url=r.repository_url AND package_path=r.package_path)
 AND NOT EXISTS(SELECT 1 FROM judge.package_artifacts WHERE repository_url=r.repository_url AND source_revision=r.source_revision AND package_path=r.package_path)
 AND NOT EXISTS(SELECT 1 FROM judge.package_validation_runs WHERE source_sha256=r.source_sha256 OR normalized_sha256=r.normalized_sha256)
 AND NOT EXISTS(SELECT 1 FROM judge.import_attempt_evidence WHERE import_item_id=i.id)
 FROM judge.rejected_package_evidence r JOIN judge.import_items i ON i.id=r.import_item_id JOIN judge.import_jobs j ON j.id=i.import_job_id
 JOIN judge.license_evidence e ON e.id=r.license_evidence_id JOIN judge.private_objects s ON s.object_key=r.source_archive_key JOIN judge.private_objects n ON n.object_key=r.normalized_archive_key
 WHERE i.import_job_id=$1 AND r.repository_url=$2 AND r.source_revision=$3 AND r.package_path=$4`, current.JobID, packages.RepositoryURL, packages.PinnedRevision, current.PackagePath, current.PreviousLicenseEvidenceID, current.LicenseTextSHA256, current.ApprovedLicenseEvidenceID).Scan(&current.OversizeRejectedEvidenceID, &current.RejectionStage, &current.RejectionCode, &source.Key, &source.SHA256, &source.SizeBytes, &normalized.Key, &normalized.SHA256, &normalized.SizeBytes, &valid)
	if err != nil || !valid || current.OversizeRejectedEvidenceID == current.RejectedEvidenceID || archiveEvidence(ctx, store, current, source, normalized) != nil {
		return errQualification
	}
	return nil
}

func validatedEvidence(ctx context.Context, db *sql.DB, store *storage.Store, current *caseReport, item contract.ImportItem) error {
	if item.ProblemID == nil || item.ProblemVersionID == nil {
		return errQualification
	}
	var source, normalized storage.Object
	var artifactID, manifestSHA string
	var valid bool
	err := db.QueryRowContext(ctx, `SELECT p.id::text,v.id::text,a.id::text,r.id::text,c.manifest_sha256::text,
 a.source_archive_key,a.source_sha256::text,s.size_bytes,a.normalized_archive_key,a.normalized_sha256::text,n.size_bytes,
 p.status='DRAFT' AND p.current_version_id IS NULL AND p.latest_version_id=v.id AND v.first_published_at IS NULL
 AND v.time_limit_ms=2000 AND v.memory_limit_bytes=268435456 AND r.status='PASSED' AND r.errors='[]'::jsonb
 AND r.source_sha256=a.source_sha256 AND r.normalized_sha256=a.normalized_sha256 AND a.validation_context->>'imageDigest'=r.image_digest
 AND r.results @> '{"structure":{"passed":true},"statement":{"passed":true},"testData":{"passed":true},"validators":{"passed":true},"referenceSolutions":{"passed":true}}'
 AND e.id=$4 AND e.status='VERIFIED' AND e.previous_evidence_id=$3 AND e.evidence->>'policy'='ADMIN_HUMAN_OFFLINE_V1'
 AND EXISTS(SELECT 1 FROM judge.private_object_references WHERE owner_type='ARTIFACT' AND owner_id=a.id AND role='SOURCE' AND object_key=a.source_archive_key)
 AND EXISTS(SELECT 1 FROM judge.private_object_references WHERE owner_type='ARTIFACT' AND owner_id=a.id AND role='NORMALIZED' AND object_key=a.normalized_archive_key)
 AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(a.manifest->'files') f WHERE NOT EXISTS(SELECT 1 FROM judge.private_object_references o WHERE o.owner_type='ARTIFACT' AND o.owner_id=a.id AND o.role='FILE' AND o.object_key='sha256/'||left(f->>'normalizedSha256',2)||'/'||(f->>'normalizedSha256')))
 AND EXISTS(SELECT 1 FROM judge.private_object_references WHERE owner_type='VALIDATION' AND owner_id=r.id AND role='EVIDENCE_LOG')
 AND EXISTS(SELECT 1 FROM judge.private_object_references WHERE owner_type='VALIDATION' AND owner_id=r.id AND role='LOG' AND object_key=r.log_object_key)
 FROM judge.platform_problems p JOIN judge.problem_versions v ON v.problem_id=p.id JOIN judge.package_artifacts a ON a.id=v.package_artifact_id
 JOIN judge.package_content_identities c ON c.id=a.content_identity_id JOIN judge.package_validation_runs r ON r.id=a.validation_run_id AND r.package_artifact_id=a.id
 JOIN judge.license_evidence e ON e.id=a.license_evidence_id JOIN judge.private_objects s ON s.object_key=a.source_archive_key JOIN judge.private_objects n ON n.object_key=a.normalized_archive_key
 WHERE p.id=$1 AND v.id=$2`, string(*item.ProblemID), string(*item.ProblemVersionID), current.PreviousLicenseEvidenceID, current.ApprovedLicenseEvidenceID).Scan(&current.ProblemID, &current.ProblemVersionID, &artifactID, &current.ValidationRunID, &manifestSHA, &source.Key, &source.SHA256, &source.SizeBytes, &normalized.Key, &normalized.SHA256, &normalized.SizeBytes, &valid)
	if err != nil || !valid || archiveEvidence(ctx, store, current, source, normalized) != nil || manifestSHA != current.ManifestSHA256 {
		return errQualification
	}
	// Verify each distinct durable private object. Empty asset deduplication is
	// observed honestly; the eight large source buffers have distinct hashes.
	rows, err := db.QueryContext(ctx, `SELECT DISTINCT o.object_key,o.sha256::text,o.size_bytes FROM judge.private_objects o JOIN judge.private_object_references r ON r.object_key=o.object_key WHERE r.owner_type='ARTIFACT' AND r.owner_id=$1 OR r.owner_type='VALIDATION' AND r.owner_id=$2`, artifactID, current.ValidationRunID)
	if err != nil {
		return errQualification
	}
	defer rows.Close()
	for rows.Next() {
		var object storage.Object
		if rows.Scan(&object.Key, &object.SHA256, &object.SizeBytes) != nil || store.Verify(ctx, object) != nil {
			return errQualification
		}
	}
	if rows.Err() != nil {
		return errQualification
	}
	return nil
}
