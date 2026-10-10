package problems

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/storage"
)

var (
	ErrNotFound        = errors.New("problem fact not found")
	ErrIntegrity       = errors.New("immutable problem integrity conflict")
	ErrInvalid         = errors.New("invalid immutable problem record")
	ErrUnavailable     = errors.New("problem persistence unavailable")
	shaPattern         = regexp.MustCompile(`^[0-9a-f]{64}$`)
	imagePattern       = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	diagnosticPattern  = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	commitPattern      = regexp.MustCompile(`^[0-9a-f]{40}$`)
	packagePathPattern = regexp.MustCompile(`^problems/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$`)
)

// ObjectVerifier additionally retains each private object in the same database
// transaction as its owner. A filesystem verifier alone cannot satisfy this
// interface, because it cannot protect accepted bytes from orphan collection.
type ObjectVerifier interface {
	Verify(context.Context, storage.Object) error
	Retain(context.Context, *sql.Tx, storage.Object, string, contract.UUID, string) error
	LockObjects(context.Context, *sql.Tx, []storage.Object) error
}

type Repository struct {
	db      *sql.DB
	objects ObjectVerifier
}
type Tx struct {
	db      *sql.Tx
	ctx     context.Context
	objects ObjectVerifier
}

func New(db *sql.DB, objects ObjectVerifier) *Repository { return &Repository{db, objects} }
func (tx *Tx) DB() *sql.Tx                               { return tx.db }

func (tx *Tx) LockObjects(objects []storage.Object) error {
	if tx.objects == nil {
		return ErrUnavailable
	}
	return tx.objects.LockObjects(tx.ctx, tx.db, objects)
}

// InTx joins an existing domain transaction; its owner alone commits/rolls back.
func (repository *Repository) InTx(ctx context.Context, db *sql.Tx) *Tx {
	return &Tx{db: db, ctx: ctx, objects: repository.objects}
}
func (repository *Repository) WithTx(ctx context.Context, options *sql.TxOptions, fn func(*Tx) error) error {
	if repository.db == nil || fn == nil {
		return ErrUnavailable
	}
	db, err := repository.db.BeginTx(ctx, options)
	if err != nil {
		return dbError(err)
	}
	defer db.Rollback()
	if err := fn(&Tx{db, ctx, repository.objects}); err != nil {
		return err
	}
	return dbError(db.Commit())
}

func dbError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	// Driver diagnostics can contain SQL, objects or private source. Do not
	// expose those errors through domain handlers or ordinary logging.
	return ErrUnavailable
}

func validIdentity(identity Identity) bool {
	if identity.Source != "OJ_LAB" || identity.RepositoryURL != contract.PackageRepository || !packagePathPattern.MatchString(identity.PackagePath) {
		return false
	}
	for _, part := range strings.Split(identity.PackagePath, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}

func (tx *Tx) EnsureProblem(identity Identity) (Problem, error) {
	if !validIdentity(identity) {
		return Problem{}, ErrInvalid
	}
	_, err := tx.db.ExecContext(tx.ctx, `INSERT INTO judge.platform_problems(source,repository_url,package_path,status) VALUES($1,$2,$3,'DRAFT') ON CONFLICT(source,repository_url,package_path) DO NOTHING`, identity.Source, identity.RepositoryURL, identity.PackagePath)
	if err != nil {
		return Problem{}, dbError(err)
	}
	var id contract.ID
	err = tx.db.QueryRowContext(tx.ctx, `SELECT id::text FROM judge.platform_problems WHERE source=$1 AND repository_url=$2 AND package_path=$3 FOR NO KEY UPDATE`, identity.Source, identity.RepositoryURL, identity.PackagePath).Scan(&id)
	if err != nil {
		return Problem{}, dbError(err)
	}
	return tx.LoadProblem(id, false)
}

func (tx *Tx) LoadProblem(id contract.ID, forUpdate bool) (Problem, error) {
	if id.Validate() != nil {
		return Problem{}, ErrInvalid
	}
	query := `SELECT id::text,source,repository_url,package_path,status,current_version_id::text,latest_version_id::text,created_at,updated_at,public_updated_at,withdrawn_at,withdrawal_reason FROM judge.platform_problems WHERE id=$1`
	if forUpdate {
		query += " FOR NO KEY UPDATE"
	}
	var problem Problem
	err := tx.db.QueryRowContext(tx.ctx, query, string(id)).Scan(&problem.ID, &problem.Identity.Source, &problem.Identity.RepositoryURL, &problem.Identity.PackagePath, &problem.Status, &problem.CurrentVersionID, &problem.LatestVersionID, &problem.CreatedAt, &problem.UpdatedAt, &problem.PublicUpdatedAt, &problem.WithdrawnAt, &problem.WithdrawalReason)
	return problem, dbError(err)
}

func jsonObject(raw json.RawMessage) (json.RawMessage, error) {
	encoded, err := canonical.Canonicalize(raw)
	if err != nil || len(encoded) == 0 || encoded[0] != '{' {
		return nil, ErrInvalid
	}
	return encoded, nil
}

func (tx *Tx) RegisterArtifact(spec ArtifactSpec) (Artifact, bool, error) {
	if tx.objects == nil || spec.ProblemID.Validate() != nil || !validIdentity(spec.Identity) || !commitPattern.MatchString(spec.SourceRevision) || spec.AdapterVersion == "" || len(spec.AdapterVersion) > 64 || spec.LicenseEvidenceID.Validate() != nil {
		return Artifact{}, false, ErrInvalid
	}
	if err := tx.LockObjects([]storage.Object{spec.SourceArchive, spec.NormalizedArchive}); err != nil {
		return Artifact{}, false, err
	}
	problem, err := tx.LoadProblem(spec.ProblemID, true)
	if err != nil {
		return Artifact{}, false, err
	}
	if problem.Identity != spec.Identity {
		return Artifact{}, false, ErrIntegrity
	}
	manifest, err := jsonObject(spec.Manifest)
	if err != nil {
		return Artifact{}, false, err
	}
	spec.Manifest = manifest
	sourceMetadata, err := jsonObject(spec.SourceMetadata)
	if err != nil {
		return Artifact{}, false, err
	}
	spec.SourceMetadata = sourceMetadata
	for _, object := range []storage.Object{spec.SourceArchive, spec.NormalizedArchive} {
		if object.Validate() != nil || !strings.HasPrefix(object.Key, "sha256/") {
			return Artifact{}, false, ErrInvalid
		}
		if err := tx.objects.Verify(tx.ctx, object); err != nil {
			return Artifact{}, false, err
		}
	}
	context := spec.ValidationContext
	if context.AdapterVersion != spec.AdapterVersion || context.SourceSHA256 != spec.SourceArchive.SHA256 || context.NormalizedSHA256 != spec.NormalizedArchive.SHA256 || !validContext(context) {
		return Artifact{}, false, ErrInvalid
	}
	var approved bool
	err = tx.db.QueryRowContext(tx.ctx, `SELECT EXISTS(SELECT 1 FROM judge.license_evidence WHERE id=$1 AND repository_url=$2 AND source_revision=$3 AND package_path=$4 AND status='VERIFIED')`, string(spec.LicenseEvidenceID), spec.Identity.RepositoryURL, spec.SourceRevision, spec.Identity.PackagePath).Scan(&approved)
	if err != nil {
		return Artifact{}, false, dbError(err)
	}
	if !approved {
		return Artifact{}, false, ErrIntegrity
	}
	manifestHash, _ := canonical.HashJSON(manifest)
	contextJSON, _ := json.Marshal(context)
	evidenceJSON, _ := json.Marshal(struct {
		LicenseEvidenceID contract.UUID     `json:"licenseEvidenceId"`
		ValidationContext ValidationContext `json:"validationContext"`
	}{spec.LicenseEvidenceID, context})
	evidenceHash, err := canonical.HashJSON(evidenceJSON)
	if err != nil {
		return Artifact{}, false, ErrInvalid
	}
	sourceID, err := contract.NewUUID()
	if err != nil {
		return Artifact{}, false, ErrUnavailable
	}
	_, err = tx.db.ExecContext(tx.ctx, `INSERT INTO judge.package_source_identities(id,repository_url,source_revision,package_path,source_sha256) VALUES($1,$2,$3,$4,$5) ON CONFLICT(repository_url,source_revision,package_path) DO NOTHING`, string(sourceID), spec.Identity.RepositoryURL, spec.SourceRevision, spec.Identity.PackagePath, spec.SourceArchive.SHA256)
	if err != nil {
		return Artifact{}, false, dbError(err)
	}
	var sourceSHA string
	err = tx.db.QueryRowContext(tx.ctx, `SELECT id::text,source_sha256::text FROM judge.package_source_identities WHERE repository_url=$1 AND source_revision=$2 AND package_path=$3 FOR UPDATE`, spec.Identity.RepositoryURL, spec.SourceRevision, spec.Identity.PackagePath).Scan(&sourceID, &sourceSHA)
	if err != nil {
		return Artifact{}, false, dbError(err)
	}
	if sourceSHA != spec.SourceArchive.SHA256 {
		return Artifact{}, false, ErrIntegrity
	}
	contentID, err := contract.NewUUID()
	if err != nil {
		return Artifact{}, false, ErrUnavailable
	}
	_, err = tx.db.ExecContext(tx.ctx, `INSERT INTO judge.package_content_identities(id,source_identity_id,adapter_version,source_format,manifest_version,normalized_sha256,manifest_sha256,manifest) VALUES($1,$2,$3,'oj-lab-v1','0.2.0',$4,$5,$6::jsonb) ON CONFLICT(source_identity_id,adapter_version) DO NOTHING`, string(contentID), string(sourceID), spec.AdapterVersion, spec.NormalizedArchive.SHA256, manifestHash, string(manifest))
	if err != nil {
		return Artifact{}, false, dbError(err)
	}
	var normalizedSHA, storedManifestHash string
	var storedManifest json.RawMessage
	err = tx.db.QueryRowContext(tx.ctx, `SELECT id::text,normalized_sha256::text,manifest_sha256::text,manifest FROM judge.package_content_identities WHERE source_identity_id=$1 AND adapter_version=$2 FOR UPDATE`, string(sourceID), spec.AdapterVersion).Scan(&contentID, &normalizedSHA, &storedManifestHash, &storedManifest)
	if err != nil {
		return Artifact{}, false, dbError(err)
	}
	storedManifest, err = jsonObject(storedManifest)
	if err != nil || normalizedSHA != spec.NormalizedArchive.SHA256 || storedManifestHash != manifestHash || !bytes.Equal(storedManifest, manifest) {
		return Artifact{}, false, ErrIntegrity
	}
	artifactID, err := contract.NewUUID()
	if err != nil {
		return Artifact{}, false, ErrUnavailable
	}
	result, err := tx.db.ExecContext(tx.ctx, `INSERT INTO judge.package_artifacts(id,problem_id,content_identity_id,source,repository_url,source_revision,package_path,source_format,adapter_version,manifest_version,source_archive_key,source_sha256,normalized_archive_key,normalized_sha256,manifest,source_metadata,license_evidence_id,validation_context,evidence_set_hash) VALUES($1,$2,$3,$4,$5,$6,$7,'oj-lab-v1',$8,'0.2.0',$9,$10,$11,$12,$13::jsonb,$14::jsonb,$15,$16::jsonb,$17) ON CONFLICT(repository_url,source_revision,package_path,adapter_version,evidence_set_hash) DO NOTHING`, string(artifactID), string(spec.ProblemID), string(contentID), spec.Identity.Source, spec.Identity.RepositoryURL, spec.SourceRevision, spec.Identity.PackagePath, spec.AdapterVersion, spec.SourceArchive.Key, spec.SourceArchive.SHA256, spec.NormalizedArchive.Key, spec.NormalizedArchive.SHA256, string(manifest), string(sourceMetadata), string(spec.LicenseEvidenceID), string(contextJSON), evidenceHash)
	if err != nil {
		return Artifact{}, false, dbError(err)
	}
	count, _ := result.RowsAffected()
	artifact := Artifact{Spec: spec, ContentIdentityID: contentID, SourceIdentityID: sourceID, ManifestSHA256: manifestHash, EvidenceSetHash: evidenceHash}
	var storedProblemID contract.ID
	var storedContentID contract.UUID
	var sourceKey, normalizedKey string
	var storedMetadata, storedContext json.RawMessage
	var licenseID contract.UUID
	err = tx.db.QueryRowContext(tx.ctx, `SELECT id::text,problem_id::text,content_identity_id::text,source_archive_key,normalized_archive_key,source_metadata,license_evidence_id::text,validation_context,validation_run_id::text,created_at FROM judge.package_artifacts WHERE repository_url=$1 AND source_revision=$2 AND package_path=$3 AND adapter_version=$4 AND evidence_set_hash=$5 FOR UPDATE`, spec.Identity.RepositoryURL, spec.SourceRevision, spec.Identity.PackagePath, spec.AdapterVersion, evidenceHash).Scan(&artifact.ID, &storedProblemID, &storedContentID, &sourceKey, &normalizedKey, &storedMetadata, &licenseID, &storedContext, &artifact.ValidationRunID, &artifact.CreatedAt)
	if err != nil {
		return Artifact{}, false, dbError(err)
	}
	storedMetadata, err = jsonObject(storedMetadata)
	if err != nil {
		return Artifact{}, false, ErrIntegrity
	}
	storedContext, _ = jsonObject(storedContext)
	canonicalContext, _ := jsonObject(contextJSON)
	if storedProblemID != spec.ProblemID || storedContentID != contentID || sourceKey != spec.SourceArchive.Key || normalizedKey != spec.NormalizedArchive.Key || !bytes.Equal(storedMetadata, sourceMetadata) || licenseID != spec.LicenseEvidenceID || !bytes.Equal(storedContext, canonicalContext) {
		return Artifact{}, false, ErrIntegrity
	}
	for role, object := range map[string]storage.Object{"SOURCE": spec.SourceArchive, "NORMALIZED": spec.NormalizedArchive} {
		if err := tx.objects.Retain(tx.ctx, tx.db, object, "ARTIFACT", artifact.ID, role); err != nil {
			return Artifact{}, false, err
		}
	}
	return artifact, count == 0, nil
}

func validateVersionSpec(spec VersionSpec) error {
	if !validText(spec.Title, 256) || spec.StatementFormat != "MARKDOWN" || !utf8.ValidString(spec.StatementContent) || spec.JudgeMode != "BATCH_PASS_FAIL" || len(spec.Tags) > 32 || len(spec.LanguageIDs) == 0 {
		return ErrInvalid
	}
	for _, value := range []*string{spec.StatementInput, spec.StatementOutput, spec.RatingBasis} {
		if value != nil && !utf8.ValidString(*value) {
			return ErrInvalid
		}
	}
	for _, sample := range spec.Samples {
		if !utf8.ValidString(sample.Input) || !utf8.ValidString(sample.Output) {
			return ErrInvalid
		}
	}
	for _, values := range [][]string{spec.Tags, spec.LanguageIDs} {
		seen := map[string]bool{}
		for _, value := range values {
			if !validText(value, 128) || seen[value] {
				return ErrInvalid
			}
			seen[value] = true
		}
	}
	if spec.DifficultyScale == contract.DifficultyUnrated {
		if spec.Difficulty != nil {
			return ErrInvalid
		}
	} else if spec.DifficultyScale != contract.DifficultyPlatform || spec.Difficulty == nil || *spec.Difficulty <= 0 || *spec.Difficulty > contract.MaxSafeInteger || spec.RatingBasis == nil || strings.TrimSpace(*spec.RatingBasis) == "" {
		return ErrInvalid
	}
	for _, value := range []int64{spec.TimeLimitMs, spec.WallLimitMs, spec.MemoryLimitBytes, spec.OutputLimitBytes} {
		if value <= 0 || value > contract.MaxSafeInteger {
			return ErrInvalid
		}
	}
	if spec.WallLimitMs < spec.TimeLimitMs {
		return ErrInvalid
	}
	if _, err := jsonObject(spec.CheckerConfig); err != nil {
		return err
	}
	return nil
}

func MetadataHash(spec VersionSpec) (string, error) {
	if err := validateVersionSpec(spec); err != nil {
		return "", err
	}
	if spec.Samples == nil {
		spec.Samples = []contract.Sample{}
	}
	if spec.Tags == nil {
		spec.Tags = []string{}
	}
	encoded, err := json.Marshal(spec)
	if err != nil {
		return "", ErrInvalid
	}
	hash, err := canonical.HashJSON(encoded)
	if err != nil {
		return "", ErrInvalid
	}
	return hash, nil
}

func (tx *Tx) CreateVersion(spec VersionSpec) (Version, error) {
	if spec.ProblemID.Validate() != nil || spec.PackageArtifactID.Validate() != nil {
		return Version{}, ErrInvalid
	}
	if _, err := tx.LoadProblem(spec.ProblemID, true); err != nil {
		return Version{}, err
	}
	if spec.BaseVersionID != nil {
		if _, err := tx.LoadVersion(spec.ProblemID, *spec.BaseVersionID); err != nil {
			return Version{}, err
		}
	}
	if err := validateVersionSpec(spec); err != nil {
		return Version{}, err
	}
	// Check before INSERT/latest-pointer writes and before allocating the full
	// metadata JSON. Deterministic workflow failures may otherwise be frozen
	// in a transaction that commits earlier business writes.
	if err := tx.checkVersionDetail(spec); err != nil {
		return Version{}, err
	}
	metadataHash, err := MetadataHash(spec)
	if err != nil {
		return Version{}, err
	}
	samples, _ := json.Marshal(nonNilSamples(spec.Samples))
	tags, _ := json.Marshal(nonNilStrings(spec.Tags))
	languages, _ := json.Marshal(nonNilStrings(spec.LanguageIDs))
	id, err := contract.NewUUID()
	if err != nil {
		return Version{}, ErrUnavailable
	}
	var number int64
	if err := tx.db.QueryRowContext(tx.ctx, `SELECT coalesce(max(version_number),0)+1 FROM judge.problem_versions WHERE problem_id=$1`, string(spec.ProblemID)).Scan(&number); err != nil {
		return Version{}, dbError(err)
	}
	_, err = tx.db.ExecContext(tx.ctx, `INSERT INTO judge.problem_versions(id,problem_id,version_number,package_artifact_id,base_version_id,title,statement_format,statement_content,statement_input,statement_output,samples,tags,difficulty,difficulty_scale,rating_basis,time_limit_ms,wall_limit_ms,memory_limit_bytes,output_limit_bytes,language_ids,judge_mode,checker_config,metadata_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,ARRAY(SELECT jsonb_array_elements_text($12::jsonb)),$13,$14,$15,$16,$17,$18,$19,ARRAY(SELECT jsonb_array_elements_text($20::jsonb)),$21,$22::jsonb,$23)`, string(id), string(spec.ProblemID), number, string(spec.PackageArtifactID), spec.BaseVersionID, spec.Title, spec.StatementFormat, spec.StatementContent, spec.StatementInput, spec.StatementOutput, string(samples), string(tags), spec.Difficulty, string(spec.DifficultyScale), spec.RatingBasis, spec.TimeLimitMs, spec.WallLimitMs, spec.MemoryLimitBytes, spec.OutputLimitBytes, string(languages), spec.JudgeMode, string(spec.CheckerConfig), metadataHash)
	if err != nil {
		return Version{}, dbError(err)
	}
	_, err = tx.db.ExecContext(tx.ctx, `UPDATE judge.platform_problems SET latest_version_id=$2,updated_at=clock_timestamp() WHERE id=$1`, string(spec.ProblemID), string(id))
	if err != nil {
		return Version{}, dbError(err)
	}
	return tx.LoadVersion(spec.ProblemID, id)
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
func nonNilSamples(values []contract.Sample) []contract.Sample {
	if values == nil {
		return []contract.Sample{}
	}
	return values
}

func (tx *Tx) LoadVersion(problemID contract.ID, id contract.UUID) (Version, error) {
	if problemID.Validate() != nil || id.Validate() != nil {
		return Version{}, ErrInvalid
	}
	var version Version
	var samples, tags, languages json.RawMessage
	err := tx.db.QueryRowContext(tx.ctx, `SELECT id::text,problem_id::text,version_number,package_artifact_id::text,base_version_id::text,title,statement_format,statement_content,statement_input,statement_output,samples,to_jsonb(tags),difficulty,difficulty_scale,rating_basis,time_limit_ms,wall_limit_ms,memory_limit_bytes,output_limit_bytes,to_jsonb(language_ids),judge_mode,checker_config,metadata_hash::text,first_published_at,created_at FROM judge.problem_versions WHERE problem_id=$1 AND id=$2`, string(problemID), string(id)).Scan(&version.ID, &version.Spec.ProblemID, &version.VersionNumber, &version.Spec.PackageArtifactID, &version.Spec.BaseVersionID, &version.Spec.Title, &version.Spec.StatementFormat, &version.Spec.StatementContent, &version.Spec.StatementInput, &version.Spec.StatementOutput, &samples, &tags, &version.Spec.Difficulty, &version.Spec.DifficultyScale, &version.Spec.RatingBasis, &version.Spec.TimeLimitMs, &version.Spec.WallLimitMs, &version.Spec.MemoryLimitBytes, &version.Spec.OutputLimitBytes, &languages, &version.Spec.JudgeMode, &version.Spec.CheckerConfig, &version.MetadataHash, &version.FirstPublishedAt, &version.CreatedAt)
	if err != nil {
		return Version{}, dbError(err)
	}
	if json.Unmarshal(samples, &version.Spec.Samples) != nil || json.Unmarshal(tags, &version.Spec.Tags) != nil || json.Unmarshal(languages, &version.Spec.LanguageIDs) != nil {
		return Version{}, ErrIntegrity
	}
	return version, nil
}

func (tx *Tx) AppendTests(tests []TestCase) error {
	if tx.objects == nil {
		return ErrInvalid
	}
	objects := make([]storage.Object, 0, 2*len(tests))
	for _, test := range tests {
		objects = append(objects, test.Input, test.Answer)
	}
	if err := tx.LockObjects(objects); err != nil {
		return err
	}
	for _, test := range tests {
		if test.ID.Validate() != nil || test.PackageArtifactID.Validate() != nil || test.Ordinal < 1 {
			return ErrInvalid
		}
		for role, object := range map[string]storage.Object{"INPUT": test.Input, "ANSWER": test.Answer} {
			if !strings.HasPrefix(object.Key, "sha256/") {
				return ErrInvalid
			}
			if err := tx.objects.Retain(tx.ctx, tx.db, object, "TEST", test.ID, role); err != nil {
				return err
			}
		}
		_, err := tx.db.ExecContext(tx.ctx, `INSERT INTO judge.problem_test_cases(id,package_artifact_id,ordinal,visibility,input_object_key,answer_object_key,input_sha256,answer_sha256,input_size_bytes,answer_size_bytes,validation_group) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, string(test.ID), string(test.PackageArtifactID), test.Ordinal, test.Visibility, test.Input.Key, test.Answer.Key, test.Input.SHA256, test.Answer.SHA256, test.Input.SizeBytes, test.Answer.SizeBytes, test.ValidationGroup)
		if err != nil {
			return dbError(err)
		}
	}
	return nil
}

func (tx *Tx) AppendReferences(references []ReferenceSolution) error {
	if tx.objects == nil {
		return ErrInvalid
	}
	objects := make([]storage.Object, 0, len(references))
	for _, reference := range references {
		objects = append(objects, reference.Source)
	}
	if err := tx.LockObjects(objects); err != nil {
		return err
	}
	for _, reference := range references {
		if reference.ID.Validate() != nil || reference.PackageArtifactID.Validate() != nil || !strings.HasPrefix(reference.Source.Key, "sha256/") || storage.ValidRelativePath(reference.UpstreamPath) != nil {
			return ErrInvalid
		}
		if err := tx.objects.Retain(tx.ctx, tx.db, reference.Source, "REFERENCE", reference.ID, "SOURCE"); err != nil {
			return err
		}
		_, err := tx.db.ExecContext(tx.ctx, `INSERT INTO judge.reference_solutions(id,package_artifact_id,role,language_id,source_object_key,source_sha256,upstream_path) VALUES($1,$2,$3,$4,$5,$6,$7)`, string(reference.ID), string(reference.PackageArtifactID), reference.Role, reference.LanguageID, reference.Source.Key, reference.Source.SHA256, reference.UpstreamPath)
		if err != nil {
			return dbError(err)
		}
	}
	return nil
}
