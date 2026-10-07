package problems

import (
	"archive/tar"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"path"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	persistence "github.com/STAR-Ability/code-startrack-judge/internal/persistence/problems"
	"github.com/STAR-Ability/code-startrack-judge/internal/storage"
)

// LicenseApproval is a private offline human review receipt, never an import
// API DTO. The command supplies authenticated operator identity separately.
type LicenseApproval struct {
	EvidenceID         contract.UUID  `json:"evidenceId"`
	RejectedEvidenceID contract.UUID  `json:"rejectedEvidenceId"`
	PreviousEvidenceID *contract.UUID `json:"previousEvidenceId"`
	RepositoryURL      string         `json:"repositoryUrl"`
	SourceRevision     string         `json:"sourceRevision"`
	PackagePath        string         `json:"packagePath"`
	SourceSHA256       string         `json:"sourceSha256"`
	NormalizedSHA256   *string        `json:"normalizedSha256"`
	Scope              string         `json:"scope"`
	SPDXID             *string        `json:"spdxId"`
	Notice             string         `json:"notice"`
	SourceURL          string         `json:"sourceUrl"`
	LicenseFiles       []LicenseFile  `json:"licenseFiles"`
	// Parent repository licenses are retained verbatim in the immutable evidence
	// because they need not be package archive members. Human review attests their
	// exact fixed-commit origin and coverage; the command checks their checksums.
	RepositoryLicenseTexts map[string]string `json:"repositoryLicenseTexts"`
	Coverage               string            `json:"coverage"`
	ThirdPartyReview       string            `json:"thirdPartyReview"`
	ApprovalEvidence       string            `json:"approvalEvidence"`
}
type LicenseFile struct {
	Path   string  `json:"path"`
	SHA256 string  `json:"sha256"`
	SPDXID *string `json:"spdxId"`
}

var reviewSHA = regexp.MustCompile(`^[0-9a-f]{64}$`)
var reviewCommit = regexp.MustCompile(`^[0-9a-f]{40}$`)

func runtimeValidateLicenseReviewerAuthority(ctx context.Context, tx *persistence.Tx) error {
	var actor string
	var unsafe bool
	if err := tx.DB().QueryRowContext(ctx, `SELECT current_user,rolsuper OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication OR rolbypassrls
 OR EXISTS(SELECT 1 FROM pg_auth_members WHERE member=r.oid OR roleid=r.oid)
 OR EXISTS(SELECT 1 FROM pg_database WHERE datdba=r.oid)
 OR EXISTS(SELECT 1 FROM pg_class WHERE relowner=r.oid)
 OR EXISTS(SELECT 1 FROM pg_namespace WHERE nspowner=r.oid)
 OR NOT (current_setting('log_statement')='none'
   AND current_setting('log_min_error_statement')='panic'
   AND current_setting('log_min_duration_statement')='-1'
   AND current_setting('log_min_duration_sample')='-1'
   AND current_setting('log_duration')='off'
   AND current_setting('log_parameter_max_length')='0'
   AND current_setting('log_parameter_max_length_on_error')='0'
   AND current_setting('log_transaction_sample_rate')='0'
   AND current_setting('log_error_verbosity')='terse'
   AND current_setting('log_min_messages')='panic'
   AND COALESCE(current_setting('pgaudit.log',true),'none')='none'
   AND COALESCE(current_setting('pgaudit.role',true),'')='')
 FROM pg_roles r WHERE rolname=current_user`).Scan(&actor, &unsafe); err != nil {
		return err
	}
	if actor != "judge_license_reviewer" || unsafe {
		return &Error{Code: "SERVICE_UNAUTHORIZED"}
	}
	return nil
}

func reviewText(value string, max int) bool {
	return utf8.ValidString(value) && strings.TrimSpace(value) != "" && len(value) <= max && strings.IndexFunc(value, func(r rune) bool { return r == 0 }) < 0
}
func reviewPath(value string) bool {
	return value != "" && value != "." && path.Clean(value) == value && !path.IsAbs(value) && !strings.ContainsAny(value, "\\:%") && strings.IndexFunc(value, unicode.IsControl) < 0 && !strings.HasPrefix(value, "../") && len(value) <= 4096
}
func (a LicenseApproval) Validate() error {
	if a.EvidenceID.Validate() != nil || a.RejectedEvidenceID.Validate() != nil || (a.PreviousEvidenceID != nil && a.PreviousEvidenceID.Validate() != nil) || a.RepositoryURL != contract.PackageRepository || !reviewCommit.MatchString(a.SourceRevision) || !contract.ValidPackagePath(a.PackagePath) || !reviewSHA.MatchString(a.SourceSHA256) || (a.NormalizedSHA256 != nil && !reviewSHA.MatchString(*a.NormalizedSHA256)) {
		return contract.Invalid("licenseReview")
	}
	if (a.Scope != "PACKAGE" && a.Scope != "REPOSITORY_INHERITED") || !reviewText(a.Notice, 65536) || !reviewText(a.Coverage, 65536) || !reviewText(a.ThirdPartyReview, 65536) || !reviewText(a.ApprovalEvidence, 65536) || a.SourceURL != a.RepositoryURL+"/tree/"+a.SourceRevision+"/"+a.PackagePath || len(a.LicenseFiles) < 1 || len(a.LicenseFiles) > 32 {
		return contract.Invalid("licenseReview")
	}
	if a.SPDXID != nil && !reviewText(*a.SPDXID, 128) {
		return contract.Invalid("spdxId")
	}
	seen := map[string]bool{}
	for _, file := range a.LicenseFiles {
		if !reviewPath(file.Path) || !reviewSHA.MatchString(file.SHA256) || seen[file.Path] || (file.SPDXID != nil && !reviewText(*file.SPDXID, 128)) {
			return contract.Invalid("licenseFiles")
		}
		seen[file.Path] = true
	}
	if len(a.RepositoryLicenseTexts) > 32 || (a.Scope == "PACKAGE" && len(a.RepositoryLicenseTexts) != 0) {
		return contract.Invalid("repositoryLicenseTexts")
	}
	for name, text := range a.RepositoryLicenseTexts {
		if !seen[name] || !reviewPath(name) || !reviewText(text, 1<<20) {
			return contract.Invalid("repositoryLicenseTexts")
		}
	}
	return nil
}

// ApproveLicense must only be called by the trusted offline command. It checks
// the dedicated DB identity as a second boundary, and never reads actor fields
// from a receipt. DB column grants prevent automatic runtime approval.
func ApproveLicense(ctx context.Context, repo *persistence.Repository, store *storage.Store, reviewer string, a LicenseApproval) (contract.UUID, error) {
	if err := a.Validate(); err != nil {
		return "", err
	}
	if !reviewText(reviewer, 256) || store == nil {
		return "", contract.Invalid("reviewer")
	}
	var source, normalized storage.Object
	var sourceRevision, packagePath, repositoryURL string
	var normalizedKey, normalizedHash sql.NullString
	var retainedPrevious sql.NullString
	err := repo.WithTx(ctx, &sql.TxOptions{ReadOnly: true}, func(tx *persistence.Tx) error {
		if err := runtimeValidateLicenseReviewerAuthority(ctx, tx); err != nil {
			return err
		}
		return tx.DB().QueryRowContext(ctx, `SELECT e.repository_url,e.source_revision,e.package_path,e.source_archive_key,e.source_sha256,e.normalized_archive_key,e.normalized_sha256,e.license_evidence_id::text,
 o.size_bytes,COALESCE(n.size_bytes,0) FROM judge.rejected_package_evidence e
 JOIN judge.private_objects o ON o.object_key=e.source_archive_key LEFT JOIN judge.private_objects n ON n.object_key=e.normalized_archive_key WHERE e.id=$1`, string(a.RejectedEvidenceID)).Scan(&repositoryURL, &sourceRevision, &packagePath, &source.Key, &source.SHA256, &normalizedKey, &normalizedHash, &retainedPrevious, &source.SizeBytes, &normalized.SizeBytes)
	})
	if err != nil {
		return "", bounded(err)
	}
	if repositoryURL != a.RepositoryURL || sourceRevision != a.SourceRevision || packagePath != a.PackagePath || source.SHA256 != a.SourceSHA256 || normalizedHash.Valid != (a.NormalizedSHA256 != nil) || (normalizedHash.Valid && normalizedHash.String != *a.NormalizedSHA256) {
		return "", contract.Invalid("sourceEvidence")
	}
	if normalizedHash.Valid {
		normalized.Key = normalizedKey.String
		normalized.SHA256 = normalizedHash.String
		if err := store.Verify(ctx, normalized); err != nil {
			return "", bounded(err)
		}
	}
	archive, err := store.Read(ctx, source, 512<<20)
	if err != nil {
		return "", bounded(err)
	}
	texts, err := reviewLicenseTexts(archive, a)
	if err != nil {
		return "", err
	}
	if a.PreviousEvidenceID == nil && retainedPrevious.Valid {
		id := contract.UUID(retainedPrevious.String)
		a.PreviousEvidenceID = &id
	}
	files, _ := json.Marshal(a.LicenseFiles)
	receipt, _ := json.Marshal(a)
	receiptHash, err := canonical.HashJSON(receipt)
	if err != nil {
		return "", bounded(err)
	}
	evidence, _ := json.Marshal(map[string]any{"policy": "ADMIN_HUMAN_OFFLINE_V1", "rejectedEvidenceId": a.RejectedEvidenceID, "sourceSha256": a.SourceSHA256, "normalizedSha256": a.NormalizedSHA256, "coverage": a.Coverage, "thirdPartyReview": a.ThirdPartyReview, "approvalEvidence": a.ApprovalEvidence, "receiptSha256": receiptHash, "licenseTexts": texts})
	err = repo.WithTx(ctx, nil, func(tx *persistence.Tx) error {
		if err := runtimeValidateLicenseReviewerAuthority(ctx, tx); err != nil {
			return err
		}
		if a.PreviousEvidenceID != nil {
			var matches bool
			if err := tx.DB().QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM judge.license_evidence WHERE id=$1 AND repository_url=$2 AND source_revision=$3 AND package_path=$4)`, string(*a.PreviousEvidenceID), a.RepositoryURL, a.SourceRevision, a.PackagePath).Scan(&matches); err != nil {
				return err
			}
			if !matches {
				return contract.Invalid("previousEvidenceId")
			}
		}
		var stored []byte
		err := tx.DB().QueryRowContext(ctx, `SELECT evidence FROM judge.license_evidence WHERE id=$1`, string(a.EvidenceID)).Scan(&stored)
		if err == nil {
			var old struct {
				ReceiptSHA256 string `json:"receiptSha256"`
			}
			if json.Unmarshal(stored, &old) != nil || old.ReceiptSHA256 != receiptHash {
				return &Error{Code: "IDEMPOTENCY_CONFLICT"}
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		result, err := tx.DB().ExecContext(ctx, `INSERT INTO judge.license_evidence(id,repository_url,source_revision,package_path,previous_evidence_id,status,license_scope,spdx_id,notice,source_url,license_files,evidence,reviewed_by,reviewed_at)
 VALUES($1,$2,$3,$4,$5,'VERIFIED',$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12,clock_timestamp()) ON CONFLICT(id) DO NOTHING`, string(a.EvidenceID), a.RepositoryURL, a.SourceRevision, a.PackagePath, a.PreviousEvidenceID, a.Scope, a.SPDXID, a.Notice, a.SourceURL, string(files), string(evidence), reviewer)
		if err != nil {
			return err
		}
		inserted, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if inserted == 1 {
			return nil
		}
		var existingHash string
		if err := tx.DB().QueryRowContext(ctx, `SELECT COALESCE(evidence->>'receiptSha256','') FROM judge.license_evidence WHERE id=$1`, string(a.EvidenceID)).Scan(&existingHash); err != nil {
			return err
		}
		if existingHash != receiptHash {
			return &Error{Code: "IDEMPOTENCY_CONFLICT"}
		}
		return nil
	})
	return a.EvidenceID, bounded(err)
}

func reviewLicenseTexts(archive []byte, a LicenseApproval) (map[string]string, error) {
	needed := map[string]LicenseFile{}
	for _, file := range a.LicenseFiles {
		needed[file.Path] = file
	}
	texts := map[string]string{}
	seen := map[string]bool{}
	reader := tar.NewReader(bytes.NewReader(archive))
	var total int64
	count := 0
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil || header == nil || header.Typeflag != tar.TypeReg || !reviewPath(header.Name) || seen[header.Name] || header.Size < 0 || header.Size > 64<<20 {
			return nil, contract.Invalid("sourceArchive")
		}
		seen[header.Name] = true
		count++
		total += header.Size
		if count > 65536 || total > 512<<20 {
			return nil, contract.Invalid("sourceArchive")
		}
		if file, ok := needed[header.Name]; ok {
			if header.Size > 1<<20 {
				return nil, contract.Invalid("licenseFiles")
			}
			content, err := io.ReadAll(io.LimitReader(reader, (1<<20)+1))
			if err != nil || canonical.HashBytes(content) != file.SHA256 || !reviewText(string(content), 1<<20) {
				return nil, contract.Invalid("licenseFiles")
			}
			texts[file.Path] = string(content)
		}
	}
	for _, file := range a.LicenseFiles {
		if _, exists := texts[file.Path]; exists {
			if _, duplicate := a.RepositoryLicenseTexts[file.Path]; duplicate {
				return nil, contract.Invalid("repositoryLicenseTexts")
			}
			continue
		}
		text, exists := a.RepositoryLicenseTexts[file.Path]
		if !exists || a.Scope != "REPOSITORY_INHERITED" || canonical.HashBytes([]byte(text)) != file.SHA256 {
			return nil, contract.Invalid("licenseFiles")
		}
		texts[file.Path] = text
	}
	return texts, nil
}
