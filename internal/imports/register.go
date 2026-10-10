// SPDX-License-Identifier: Apache-2.0

package imports

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	problemstore "github.com/STAR-Ability/code-startrack-judge/internal/persistence/problems"
	"github.com/STAR-Ability/code-startrack-judge/internal/storage"
)

func (c *stagedCandidate) applyValidated(ctx context.Context, sqlTx *sql.Tx) (ItemResult, error) {
	if c.report == nil || c.report.Status != "PASSED" || c.candidate == nil || c.candidate.Manifest == nil || c.source == nil || c.normalized == nil || c.licenseID == "" {
		return ItemResult{}, ErrUnavailable
	}
	m := c.candidate.Manifest
	tx := c.pipeline.options.Problems.InTx(ctx, sqlTx)
	problem, err := tx.EnsureProblem(problemstore.Identity{Source: m.Source.Source, RepositoryURL: m.Source.RepositoryURL, PackagePath: m.Source.PackagePath})
	if err != nil {
		return ItemResult{}, err
	}
	metadata, _ := json.Marshal(m.SourceMetadata)
	contextBytes, _ := json.Marshal(c.report.Context)
	var validationContext problemstore.ValidationContext
	if json.Unmarshal(contextBytes, &validationContext) != nil {
		return ItemResult{}, ErrUnavailable
	}
	artifact, replay, err := tx.RegisterArtifact(problemstore.ArtifactSpec{ProblemID: problem.ID, Identity: problem.Identity, SourceRevision: c.lease.Revision, AdapterVersion: m.AdapterVersion, SourceArchive: c.source.Object, NormalizedArchive: c.normalized.Object, Manifest: c.candidate.ManifestJSON, SourceMetadata: metadata, LicenseEvidenceID: c.licenseID, ValidationContext: validationContext})
	if err != nil {
		return ItemResult{}, err
	}
	for role, stage := range map[string]storage.StagedObject{"SOURCE": *c.source, "NORMALIZED": *c.normalized} {
		if err := c.pipeline.options.Registry.AttachImmutable(ctx, sqlTx, stage, "ARTIFACT", artifact.ID, role); err != nil {
			return ItemResult{}, err
		}
	}
	for _, file := range c.candidate.NormalizedFiles {
		stage, ok := c.stages[file.Path]
		if !ok {
			return ItemResult{}, ErrUnavailable
		}
		if err := c.pipeline.options.Registry.AttachImmutable(ctx, sqlTx, stage, "ARTIFACT", artifact.ID, "FILE"); err != nil {
			return ItemResult{}, err
		}
	}
	if !replay {
		tests := make([]problemstore.TestCase, 0, len(m.Tests))
		for _, test := range m.Tests {
			id, err := contract.NewUUID()
			if err != nil {
				return ItemResult{}, ErrUnavailable
			}
			input, inputOK := c.stages[test.Input.Path]
			answer, answerOK := c.stages[test.Answer.Path]
			if !inputOK || !answerOK {
				return ItemResult{}, ErrUnavailable
			}
			tests = append(tests, problemstore.TestCase{ID: id, PackageArtifactID: artifact.ID, Ordinal: int64(test.Ordinal), Visibility: test.Visibility, Input: input.Object, Answer: answer.Object, ValidationGroup: test.ValidationGroup})
		}
		if err := tx.AppendTests(tests); err != nil {
			return ItemResult{}, err
		}
		references := make([]problemstore.ReferenceSolution, 0, len(m.ReferenceSolutions))
		for _, ref := range m.ReferenceSolutions {
			id, err := contract.NewUUID()
			if err != nil {
				return ItemResult{}, ErrUnavailable
			}
			stage, ok := c.stages[ref.File.Path]
			if !ok {
				return ItemResult{}, ErrUnavailable
			}
			references = append(references, problemstore.ReferenceSolution{ID: id, PackageArtifactID: artifact.ID, Role: ref.Role, LanguageID: ref.LanguageID, Source: stage.Object, UpstreamPath: ref.File.Path})
		}
		if err := tx.AppendReferences(references); err != nil {
			return ItemResult{}, err
		}
	}
	runID, err := contract.NewUUID()
	if err != nil {
		return ItemResult{}, ErrUnavailable
	}
	results, _ := json.Marshal(c.report.Results)
	adaptations, _ := json.Marshal(c.report.Adaptations)
	var log *storage.Object
	if c.log != nil {
		object := c.log.Object
		log = &object
	}
	var evidenceLogs []storage.Object
	if c.journal != nil {
		for _, stage := range c.journal.Stages() {
			evidenceLogs = append(evidenceLogs, stage.Object)
		}
	}
	if err := tx.AppendValidation(problemstore.ValidationRun{ID: runID, PackageArtifactID: artifact.ID, Status: "PASSED", Context: validationContext, Results: results, Errors: c.report.Errors, Adaptations: adaptations, Log: log, EvidenceLogs: evidenceLogs, StartedAt: c.report.StartedAt, FinishedAt: c.report.FinishedAt}); err != nil {
		return ItemResult{}, err
	}
	if c.log != nil {
		if err := c.pipeline.options.Registry.AttachImmutable(ctx, sqlTx, *c.log, "VALIDATION", runID, "LOG"); err != nil {
			return ItemResult{}, err
		}
	}
	if c.journal != nil {
		for _, stage := range c.journal.Stages() {
			if err := c.pipeline.options.Registry.AttachImmutable(ctx, sqlTx, stage, "VALIDATION", runID, "EVIDENCE_LOG"); err != nil {
				return ItemResult{}, err
			}
		}
	}
	if artifact.ValidationRunID == nil {
		if err := tx.SelectValidation(artifact.ID, runID); err != nil {
			return ItemResult{}, err
		}
	}
	var versionID contract.UUID
	err = sqlTx.QueryRowContext(ctx, `SELECT id::text FROM judge.problem_versions WHERE problem_id=$1 AND package_artifact_id=$2 ORDER BY version_number DESC LIMIT 1`, problem.ID, artifact.ID).Scan(&versionID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ItemResult{}, ErrUnavailable
	}
	if errors.Is(err, sql.ErrNoRows) {
		spec := c.versionSpec()
		spec.ProblemID, spec.PackageArtifactID = problem.ID, artifact.ID
		version, err := tx.CreateVersion(spec)
		if err != nil {
			return ItemResult{}, err
		}
		versionID = version.ID
	}
	return ItemResult{Item: contract.ImportItem{PackagePath: c.item.PackagePath, Status: "VALIDATED", ProblemID: &problem.ID, ProblemVersionID: &versionID, LicenseStatus: "VERIFIED", ValidationStatus: "PASSED", Errors: contract.Array[contract.TaskError]{}}}, nil
}

func (c *stagedCandidate) versionSpec() problemstore.VersionSpec {
	m := c.candidate.Manifest
	checker, _ := json.Marshal(m.Checker)
	samples := make([]contract.Sample, 0, len(c.candidate.Samples))
	for _, sample := range c.candidate.Samples {
		samples = append(samples, contract.Sample{Input: sample.Input, Output: sample.Output})
	}
	return problemstore.VersionSpec{Title: m.Title, StatementFormat: "MARKDOWN", StatementContent: c.candidate.StatementContent, StatementInput: c.candidate.StatementInput, StatementOutput: c.candidate.StatementOutput, Samples: samples, Tags: []string{}, DifficultyScale: contract.DifficultyUnrated, TimeLimitMs: m.Limits.TimeLimitMS, WallLimitMs: m.Limits.WallLimitMS, MemoryLimitBytes: m.Limits.MemoryLimitBytes, OutputLimitBytes: m.Limits.OutputLimitBytes, LanguageIDs: m.LanguageIDs, JudgeMode: m.JudgeMode, CheckerConfig: checker}
}
