// SPDX-License-Identifier: Apache-2.0

package imports

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/packages"
	problemstore "github.com/STAR-Ability/code-startrack-judge/internal/persistence/problems"
	"github.com/STAR-Ability/code-startrack-judge/internal/storage"
	"github.com/STAR-Ability/code-startrack-judge/internal/validation"
)

type PackageValidator interface {
	Validate(context.Context, validation.Request) (validation.Report, error)
}

type PipelineOptions struct {
	DB         *sql.DB
	Source     Source
	Registry   *storage.Registry
	Problems   *problemstore.Repository
	Validation PackageValidator
}

type ImportPipeline struct {
	options PipelineOptions
	mu      sync.Mutex
	// A whole-source acquisition failure is stable for this reservation. It
	// rejects every remaining item without repeatedly fetching the same source.
	sourceFailures map[contract.UUID]error
}

func NewPipeline(options PipelineOptions) (*ImportPipeline, error) {
	if options.DB == nil || options.Source == nil || options.Registry == nil || options.Problems == nil || options.Validation == nil {
		return nil, ErrUnavailable
	}
	return &ImportPipeline{options: options, sourceFailures: make(map[contract.UUID]error)}, nil
}

// Ready reports genuine qualification without acquisition or execution. Test
// validators lacking this capability cannot advertise a production workflow.
func (p *ImportPipeline) Ready(ctx context.Context) bool {
	validator, ok := p.options.Validation.(interface{ Ready(context.Context) bool })
	if !ok || !validator.Ready(ctx) {
		return false
	}
	if source, ok := p.options.Source.(interface{ Ready(context.Context) bool }); ok {
		return source.Ready(ctx)
	}
	return false
}

type stagedCandidate struct {
	pipeline          *ImportPipeline
	lease             Lease
	item              PendingItem
	candidate         *packages.Artifact
	license           collectedLicense
	stages            map[string]storage.StagedObject
	source            *storage.StagedObject
	normalized        *storage.StagedObject
	log               *storage.StagedObject
	licenseID         contract.UUID
	licenseStatus     string
	report            *validation.Report
	rejection         *RejectedEvidence
	diagnostic        contract.TaskError
	journal           *evidenceJournal
	attemptIncomplete bool
}

func (p *ImportPipeline) stage(ctx context.Context, data []byte) (storage.StagedObject, error) {
	object, err := storage.Blob(canonical.HashBytes(data), int64(len(data)))
	if err != nil {
		return storage.StagedObject{}, err
	}
	return p.options.Registry.StageImmutable(ctx, bytes.NewReader(data), object)
}

func (p *ImportPipeline) Prepare(ctx context.Context, lease Lease, item PendingItem) (Prepared, error) {
	if lease.JobID.Validate() != nil || lease.Token.Validate() != nil || item.ID.Validate() != nil || !contract.ValidPackagePath(item.PackagePath) {
		return nil, ErrUnavailable
	}
	prepared := &stagedCandidate{pipeline: p, lease: lease, item: item, stages: make(map[string]storage.StagedObject), licenseStatus: "PENDING"}
	p.mu.Lock()
	sourceErr := p.sourceFailures[lease.Token]
	p.mu.Unlock()
	var snapshot SourceSnapshot
	var err error
	if sourceErr == nil {
		snapshot, sourceErr = p.options.Source.Acquire(ctx, lease.Revision, item.PackagePath)
		if errors.Is(sourceErr, ErrSourceUnavailable) || errors.Is(sourceErr, ErrSourceUnsupported) {
			p.mu.Lock()
			// Keep only the active reservation's bounded failure marker.
			p.sourceFailures = map[contract.UUID]error{lease.Token: sourceErr}
			p.mu.Unlock()
		}
	}
	if sourceErr != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		code, stage := "IMPORT_SOURCE_UNAVAILABLE", "SOURCE_UNAVAILABLE"
		if errors.Is(sourceErr, ErrSourceUnsupported) {
			code, stage = "PACKAGE_UNSUPPORTED", "UNSUPPORTED"
		} else if !errors.Is(sourceErr, ErrSourceUnavailable) {
			code, stage = "PACKAGE_INVALID", "INVALID_STRUCTURE"
		}
		return prepared.reject(stage, code)
	}
	// Retain only the collected license facts. The adapter takes its own sealed
	// source copy, so retaining acquisition buffers throughout validation would
	// unnecessarily duplicate the entire admitted package in the API process.
	prepared.license = automaticLicense(snapshot)
	candidate, adaptationErr := packages.Adapt(packages.PinnedSource(item.PackagePath), snapshot.Files)
	snapshot = SourceSnapshot{}
	prepared.candidate = candidate
	// Retain bounded original/derived archives even when adaptation failed.
	if candidate != nil && len(candidate.SourceArchive) != 0 {
		stage, err := p.stage(ctx, candidate.SourceArchive)
		if err != nil {
			return nil, err
		}
		prepared.source = &stage
	}
	if candidate != nil && len(candidate.NormalizedArchive) != 0 {
		stage, err := p.stage(ctx, candidate.NormalizedArchive)
		if err != nil {
			return nil, err
		}
		prepared.normalized = &stage
	}
	if candidate == nil || len(candidate.SourceArchive) == 0 {
		return prepared.reject("INVALID_STRUCTURE", "PACKAGE_INVALID")
	}
	prepared.licenseID, err = p.approvedLicense(ctx, lease, item, candidate)
	if err != nil {
		return nil, err
	}
	if prepared.licenseID != "" {
		prepared.licenseStatus = "VERIFIED"
	} else {
		prepared.licenseStatus = prepared.license.status
	}
	if adaptationErr != nil || !candidate.ManifestReady {
		code, stage := "PACKAGE_INVALID", "INVALID_STRUCTURE"
		var adaptation *packages.AdaptError
		if errors.As(adaptationErr, &adaptation) {
			code, stage = adaptation.Code, adaptation.Stage
		}
		return prepared.reject(stage, code)
	}
	if prepared.licenseID == "" {
		return prepared.reject("LICENSE_REVIEW", "PACKAGE_LICENSE_MISSING")
	}
	for _, file := range candidate.NormalizedFiles {
		stage, err := p.stage(ctx, file.Data)
		if err != nil {
			return nil, err
		}
		prepared.stages[file.Path] = stage
	}
	prepared.journal = newEvidenceJournal(p)
	validationCtx, cancel := context.WithCancel(ctx)
	renewed := make(chan struct{})
	go func() {
		defer close(renewed)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-validationCtx.Done():
				return
			case <-ticker.C:
				for _, stage := range prepared.allStages() {
					if p.options.Registry.Renew(validationCtx, stage) != nil {
						cancel()
						return
					}
				}
			}
		}
	}()
	report, validationErr := p.options.Validation.Validate(validationCtx, validation.Request{JobID: lease.JobID, ItemID: item.ID, FencingToken: lease.Token, Candidate: candidate, RecordEvidence: prepared.journal.Record})
	cancel()
	<-renewed
	if validationErr != nil {
		retentionCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		logTruncated := len(report.RawLog) > validation.MaxPrivateLogBytes
		if logTruncated {
			report.RawLog = append([]byte(nil), report.RawLog[:validation.MaxPrivateLogBytes]...)
		}
		checksum, count, err := prepared.journal.SealIncomplete(retentionCtx)
		if err != nil {
			return nil, validationErr
		}
		// Preserve observed diagnostics independently of the helper's terminal
		// count. An interrupted report cannot qualify an artifact or version.
		prepared.report = &report
		sealed, err := json.Marshal(struct {
			Complete bool              `json:"complete"`
			Report   validation.Report `json:"partialReport"`
			Chunks   []evidenceChunk   `json:"validationEvidenceChunks"`
		}{false, report, prepared.journal.Chunks()})
		if err != nil || len(sealed) > 32<<20 {
			return nil, validationErr
		}
		stage, err := p.stage(retentionCtx, sealed)
		if err != nil {
			return nil, validationErr
		}
		prepared.log = &stage
		if _, err := prepared.reject("VALIDATION_FAILED", "PACKAGE_VALIDATION_FAILED"); err != nil {
			return nil, validationErr
		}
		prepared.rejection.Provenance["complete"] = false
		prepared.attemptIncomplete = true
		prepared.rejection.Provenance["rawLogTruncated"] = logTruncated
		prepared.rejection.Provenance["fencingToken"] = lease.Token
		prepared.rejection.Provenance["programEvidenceSha256"] = checksum
		prepared.rejection.Provenance["programEvidenceCount"] = count
		return prepared, validationErr
	}
	if err := prepared.journal.Seal(ctx, report.ProgramEvidenceSHA256, report.ProgramEvidenceCount); err != nil {
		return nil, err
	}
	if (report.Status != "PASSED" && report.Status != "FAILED") || report.Results.Validate() != nil || report.StartedAt.IsZero() || report.FinishedAt.Before(report.StartedAt) || len(report.RawLog) > validation.MaxPrivateLogBytes {
		return nil, ErrUnavailable
	}
	prepared.report = &report
	for _, chunk := range prepared.journal.Stages() {
		key, sha := chunk.Object.Key, chunk.Object.SHA256
		report.Results.ReferenceSolutions.Evidence = append(report.Results.ReferenceSolutions.Evidence, validation.Evidence{Check: "PROGRAM_EVIDENCE_CHUNK", SubjectSHA256: &sha, LogObjectKey: &key, Summary: "Ordered exact-profile program and case evidence retained privately."})
	}
	if len(report.RawLog) != 0 || prepared.journal.Count() != 0 {
		sealed, err := json.Marshal(struct {
			Report validation.Report `json:"report"`
			Chunks []evidenceChunk   `json:"validationEvidenceChunks"`
		}{report, prepared.journal.Chunks()})
		if err != nil || len(sealed) > 32<<20 {
			return nil, ErrUnavailable
		}
		stage, err := p.stage(ctx, sealed)
		if err != nil {
			return nil, err
		}
		prepared.log = &stage
	}
	if report.Status == "FAILED" {
		return prepared.reject("VALIDATION_FAILED", "PACKAGE_VALIDATION_FAILED")
	}
	if !report.Results.AllPassed() || len(report.Errors) != 0 {
		return nil, ErrUnavailable
	}
	return prepared, nil
}

func (c *stagedCandidate) allStages() []storage.StagedObject {
	stages := make([]storage.StagedObject, 0, len(c.stages)+3)
	for _, stage := range c.stages {
		stages = append(stages, stage)
	}
	for _, stage := range []*storage.StagedObject{c.source, c.normalized, c.log} {
		if stage != nil {
			stages = append(stages, *stage)
		}
	}
	if c.journal != nil {
		stages = append(stages, c.journal.Stages()...)
	}
	return stages
}

func (c *stagedCandidate) reject(stage, code string) (Prepared, error) {
	diagnostic, ok := PublicDiagnostic(code)
	if !ok {
		return nil, ErrUnavailable
	}
	id, err := contract.NewUUID()
	if err != nil {
		return nil, ErrUnavailable
	}
	c.diagnostic = diagnostic
	c.rejection = &RejectedEvidence{ID: id, FailureStage: stage, Provenance: map[string]any{"repositoryUrl": packages.RepositoryURL, "sourceRevision": c.lease.Revision, "packagePath": c.item.PackagePath, "adapterVersion": packages.AdapterVersion}, SourceMetadata: map[string]any{}, Adaptations: []any{}, Errors: contract.Array[contract.TaskError]{diagnostic}}
	if c.candidate != nil && c.candidate.Manifest != nil {
		c.rejection.SourceMetadata = c.candidate.Manifest.SourceMetadata
		if c.rejection.SourceMetadata == nil {
			c.rejection.SourceMetadata = map[string]any{}
		}
		for _, adaptation := range c.candidate.Manifest.Adaptations {
			c.rejection.Adaptations = append(c.rejection.Adaptations, adaptation)
		}
	}
	if c.report != nil {
		// Complete private checkpoint/error evidence remains outside public DTOs.
		c.rejection.Provenance["validation"] = c.report.Results
		c.rejection.Provenance["validationContext"] = c.report.Context
		c.rejection.Provenance["validationErrors"] = c.report.Errors
		c.rejection.Provenance["validationEvidenceChunks"] = c.journal.Chunks()
		c.rejection.Provenance["programEvidenceSha256"] = c.report.ProgramEvidenceSHA256
		c.rejection.Provenance["programEvidenceCount"] = c.report.ProgramEvidenceCount
	}
	for _, pair := range []struct {
		stage *storage.StagedObject
		key   **string
		sha   **string
	}{{c.source, &c.rejection.SourceArchiveKey, &c.rejection.SourceSHA256}, {c.normalized, &c.rejection.NormalizedArchiveKey, &c.rejection.NormalizedSHA256}} {
		if pair.stage != nil {
			key, sha := pair.stage.Object.Key, pair.stage.Object.SHA256
			*pair.key, *pair.sha = &key, &sha
		}
	}
	if c.log != nil {
		key := c.log.Object.Key
		c.rejection.ValidationLogKey = &key
	}
	return c, nil
}

func (p *ImportPipeline) approvedLicense(ctx context.Context, lease Lease, item PendingItem, candidate *packages.Artifact) (contract.UUID, error) {
	var id contract.UUID
	err := p.options.DB.QueryRowContext(ctx, `SELECT id::text FROM judge.license_evidence
 WHERE repository_url=$1 AND source_revision=$2 AND package_path=$3 AND status='VERIFIED'
 AND reviewed_by IS NOT NULL AND reviewed_at IS NOT NULL
 AND evidence->>'policy'='ADMIN_HUMAN_OFFLINE_V1' AND evidence->>'sourceSha256'=$4
 AND (evidence->>'normalizedSha256' IS NULL OR evidence->>'normalizedSha256'=$5)
 ORDER BY reviewed_at DESC,id DESC LIMIT 1`, packages.RepositoryURL, lease.Revision, item.PackagePath, candidate.SourceSHA256, candidate.NormalizedSHA256).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", ErrUnavailable
	}
	return id, nil
}

type collectedLicense struct {
	status   string
	scope    string
	files    []map[string]any
	evidence map[string]any
}

func automaticLicense(snapshot SourceSnapshot) collectedLicense {
	result := collectedLicense{status: "MISSING", scope: "UNKNOWN", files: []map[string]any{}, evidence: map[string]any{"policy": "AUTOMATIC_COLLECTION_REQUIRES_ADMIN_V1", "licenseTexts": map[string]string{}}}
	texts := result.evidence["licenseTexts"].(map[string]string)
	collect := func(files []packages.File, repository bool) {
		for _, file := range files {
			name := strings.ToUpper(path.Base(file.Path))
			if name != "LICENSE" && name != "LICENSE.MD" && name != "LICENSE.TXT" && name != "NOTICE" && name != "COPYING" {
				continue
			}
			if len(file.Data) > 1<<20 || !utf8.Valid(file.Data) || strings.ContainsRune(string(file.Data), 0) {
				continue
			}
			key := file.Path
			if repository {
				key = "repository/" + key
			}
			result.files = append(result.files, map[string]any{"path": key, "sha256": canonical.HashBytes(file.Data), "spdxId": nil})
			texts[key] = string(file.Data)
			result.status = "REVIEW_REQUIRED"
			if !repository {
				result.scope = "PACKAGE"
			} else if result.scope == "UNKNOWN" {
				result.scope = "REPOSITORY_INHERITED"
			}
		}
	}
	collect(snapshot.Files, false)
	collect(snapshot.RepositoryLicenses, true)
	return result
}

func (c *stagedCandidate) persistLicense(ctx context.Context, tx *sql.Tx) error {
	if c.licenseID != "" || c.candidate == nil || c.source == nil {
		return nil
	}
	id, err := contract.NewUUID()
	if err != nil {
		return ErrUnavailable
	}
	collected := c.license
	collected.evidence["sourceSha256"] = c.candidate.SourceSHA256
	if c.candidate.NormalizedSHA256 != "" {
		collected.evidence["normalizedSha256"] = c.candidate.NormalizedSHA256
	}
	files, _ := json.Marshal(collected.files)
	evidence, err := json.Marshal(collected.evidence)
	if err != nil || len(evidence) > 8<<20 || len(collected.files) > 32 {
		return ErrUnavailable
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO judge.license_evidence(id,repository_url,source_revision,package_path,status,license_scope,notice,source_url,license_files,evidence)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb)`, id, packages.RepositoryURL, c.lease.Revision, c.item.PackagePath, collected.status, collected.scope, "Final ADMIN approval and asset coverage review are required.", packages.RepositoryURL+"/tree/"+c.lease.Revision+"/"+c.item.PackagePath, files, evidence)
	if err != nil {
		return ErrUnavailable
	}
	c.licenseID = id
	return nil
}

func (c *stagedCandidate) Apply(ctx context.Context, tx *sql.Tx, item PendingItem) (ItemResult, error) {
	if item != c.item || tx == nil {
		return ItemResult{}, ErrUnavailable
	}
	objects := make([]storage.Object, 0)
	for _, stage := range c.allStages() {
		objects = append(objects, stage.Object)
	}
	if err := c.pipeline.options.Registry.LockObjects(ctx, tx, objects); err != nil {
		return ItemResult{}, err
	}
	if err := c.persistLicense(ctx, tx); err != nil {
		return ItemResult{}, err
	}
	if c.rejection != nil {
		ownerType := "REJECTED"
		if c.attemptIncomplete {
			ownerType = "IMPORT_ATTEMPT"
		}
		if c.licenseID != "" {
			id := c.licenseID
			c.rejection.LicenseEvidenceID = &id
		}
		for role, stage := range map[string]*storage.StagedObject{"SOURCE": c.source, "NORMALIZED": c.normalized, "LOG": c.log} {
			if stage != nil {
				if err := c.pipeline.options.Registry.AttachImmutable(ctx, tx, *stage, ownerType, c.rejection.ID, role); err != nil {
					return ItemResult{}, err
				}
			}
		}
		if c.journal != nil {
			for _, stage := range c.journal.Stages() {
				if err := c.pipeline.options.Registry.AttachImmutable(ctx, tx, stage, ownerType, c.rejection.ID, "EVIDENCE_LOG"); err != nil {
					return ItemResult{}, err
				}
			}
		}
		validationStatus := "PENDING"
		if c.rejection.FailureStage == "VALIDATION_FAILED" || c.rejection.FailureStage == "INVALID_STRUCTURE" || c.rejection.FailureStage == "UNSUPPORTED" {
			validationStatus = "FAILED"
		}
		return ItemResult{Item: contract.ImportItem{PackagePath: item.PackagePath, Status: "REJECTED", LicenseStatus: c.licenseStatus, ValidationStatus: validationStatus, Errors: contract.Array[contract.TaskError]{c.diagnostic}}, Evidence: c.rejection}, nil
	}
	return c.applyValidated(ctx, tx)
}
