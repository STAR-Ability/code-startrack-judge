package problems

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/storage"
)

// validateRun verifies the exact five checkpoints before SQL. Database checks
// independently enforce terminal shape and the source identity relationship.
func validateRun(run ValidationRun) (json.RawMessage, json.RawMessage, error) {
	if run.ID.Validate() != nil || run.PackageArtifactID.Validate() != nil || (run.Status != "PASSED" && run.Status != "FAILED") || run.StartedAt.IsZero() || run.FinishedAt.Before(run.StartedAt) || !validContext(run.Context) {
		return nil, nil, ErrInvalid
	}
	results, err := jsonObject(run.Results)
	if err != nil {
		return nil, nil, err
	}
	var sections map[string]json.RawMessage
	if json.Unmarshal(results, &sections) != nil || len(sections) != 5 {
		return nil, nil, ErrInvalid
	}
	allPassed := true
	for _, name := range []string{"structure", "statement", "testData", "validators", "referenceSolutions"} {
		var section map[string]json.RawMessage
		if json.Unmarshal(sections[name], &section) != nil || len(section) != 2 {
			return nil, nil, ErrInvalid
		}
		var passed bool
		if string(section["passed"]) != "true" && string(section["passed"]) != "false" {
			return nil, nil, ErrInvalid
		}
		if json.Unmarshal(section["passed"], &passed) != nil {
			return nil, nil, ErrInvalid
		}
		allPassed = allPassed && passed
		var evidence []map[string]json.RawMessage
		if json.Unmarshal(section["evidence"], &evidence) != nil || len(evidence) < 1 || len(evidence) > 65536 {
			return nil, nil, ErrInvalid
		}
		for _, entry := range evidence {
			if len(entry) != 4 {
				return nil, nil, ErrInvalid
			}
			var check, summary string
			var subject, key *string
			if json.Unmarshal(entry["check"], &check) != nil || !diagnosticPattern.MatchString(check) || json.Unmarshal(entry["summary"], &summary) != nil || !validText(summary, 500) || json.Unmarshal(entry["subjectSha256"], &subject) != nil || json.Unmarshal(entry["logObjectKey"], &key) != nil {
				return nil, nil, ErrInvalid
			}
			if subject != nil && !shaPattern.MatchString(*subject) {
				return nil, nil, ErrInvalid
			}
			if key != nil {
				found := run.Log != nil && run.Log.Key == *key
				for _, object := range run.EvidenceLogs {
					found = found || object.Key == *key
				}
				if !found {
					return nil, nil, ErrInvalid
				}
			}
		}
	}
	if run.Status == "PASSED" && (!allPassed || len(run.Errors) != 0) || run.Status == "FAILED" && (allPassed || len(run.Errors) == 0) {
		return nil, nil, ErrInvalid
	}
	for _, taskError := range run.Errors {
		if !diagnosticPattern.MatchString(taskError.Code) || !validText(taskError.Message, 500) {
			return nil, nil, ErrInvalid
		}
	}
	adaptations, err := canonical.Canonicalize(run.Adaptations)
	if err != nil || len(adaptations) == 0 || adaptations[0] != '[' {
		return nil, nil, ErrInvalid
	}
	var adaptationEntries []map[string]json.RawMessage
	if json.Unmarshal(adaptations, &adaptationEntries) != nil {
		return nil, nil, ErrInvalid
	}
	for _, entry := range adaptationEntries {
		var code, sourceField, reason string
		if len(entry) != 5 || json.Unmarshal(entry["code"], &code) != nil || !diagnosticPattern.MatchString(code) || json.Unmarshal(entry["sourceField"], &sourceField) != nil || !validText(sourceField, 1024) || json.Unmarshal(entry["reason"], &reason) != nil || !validText(reason, 500) || entry["originalValue"] == nil || entry["normalizedValue"] == nil {
			return nil, nil, ErrInvalid
		}
	}
	return results, adaptations, nil
}

func validText(value string, limit int) bool {
	return utf8.ValidString(value) && strings.TrimSpace(value) != "" && utf8.RuneCountInString(value) <= limit
}
func validContext(value ValidationContext) bool {
	return validText(value.ProblemtoolsVersion, 1024) && validText(value.AdapterVersion, 64) && validText(value.ToolchainVersion, 1024) && imagePattern.MatchString(value.ImageDigest) && shaPattern.MatchString(value.ConfigSHA256) && shaPattern.MatchString(value.SourceSHA256) && shaPattern.MatchString(value.NormalizedSHA256)
}

func (tx *Tx) AppendValidation(run ValidationRun) error {
	if tx.objects == nil {
		return ErrUnavailable
	}
	results, adaptations, err := validateRun(run)
	if err != nil {
		return err
	}
	objects := append([]storage.Object(nil), run.EvidenceLogs...)
	if run.Log != nil {
		objects = append(objects, *run.Log)
	}
	if err := tx.LockObjects(objects); err != nil {
		return err
	}
	var matches bool
	// Audit runs may use a different validation profile. Only source, adapter
	// and normalized content are fixed here; selection below matches all seven.
	if err := tx.db.QueryRowContext(tx.ctx, `SELECT EXISTS(SELECT 1 FROM judge.package_artifacts WHERE id=$1 AND adapter_version=$2 AND source_sha256=$3 AND normalized_sha256=$4)`, string(run.PackageArtifactID), run.Context.AdapterVersion, run.Context.SourceSHA256, run.Context.NormalizedSHA256).Scan(&matches); err != nil {
		return dbError(err)
	}
	if !matches {
		return ErrIntegrity
	}
	errorsJSON, err := json.Marshal(run.Errors)
	if err != nil {
		return ErrInvalid
	}
	if run.Errors == nil {
		errorsJSON = []byte("[]")
	}
	var logKey *string
	if run.Log != nil {
		logKey = &run.Log.Key
	}
	_, err = tx.db.ExecContext(tx.ctx, `INSERT INTO judge.package_validation_runs(id,package_artifact_id,status,problemtools_version,adapter_version,toolchain_version,image_digest,config_sha256,source_sha256,normalized_sha256,results,errors,adaptations,log_object_key,started_at,finished_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12::jsonb,$13::jsonb,$14,$15,$16)`, string(run.ID), string(run.PackageArtifactID), run.Status, run.Context.ProblemtoolsVersion, run.Context.AdapterVersion, run.Context.ToolchainVersion, run.Context.ImageDigest, run.Context.ConfigSHA256, run.Context.SourceSHA256, run.Context.NormalizedSHA256, string(results), string(errorsJSON), string(adaptations), logKey, run.StartedAt.UTC(), run.FinishedAt.UTC())
	if err != nil {
		return dbError(err)
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].Key < objects[j].Key })
	for _, object := range objects {
		role := "EVIDENCE_LOG"
		if run.Log != nil && object.Key == run.Log.Key {
			role = "LOG"
		}
		if err := tx.objects.Retain(tx.ctx, tx.db, object, "VALIDATION", run.ID, role); err != nil {
			return err
		}
	}
	return nil
}

// SelectValidation binds qualification once; replay of the same selection is
// harmless. Context mismatches and failed runs never qualify an artifact.
func (tx *Tx) SelectValidation(artifactID, runID contract.UUID) error {
	if artifactID.Validate() != nil || runID.Validate() != nil {
		return ErrInvalid
	}
	var current *contract.UUID
	var contextJSON json.RawMessage
	err := tx.db.QueryRowContext(tx.ctx, `SELECT validation_run_id::text,validation_context FROM judge.package_artifacts WHERE id=$1 FOR NO KEY UPDATE`, string(artifactID)).Scan(&current, &contextJSON)
	if err != nil {
		return dbError(err)
	}
	if current != nil {
		if *current == runID {
			return nil
		}
		return ErrIntegrity
	}
	run, err := tx.LoadValidation(runID)
	if err != nil {
		return err
	}
	expected, _ := json.Marshal(run.Context)
	stored, err := jsonObject(contextJSON)
	canonicalContext, _ := jsonObject(expected)
	if err != nil || run.PackageArtifactID != artifactID || run.Status != "PASSED" || !bytes.Equal(stored, canonicalContext) {
		return ErrIntegrity
	}
	_, err = tx.db.ExecContext(tx.ctx, `UPDATE judge.package_artifacts SET validation_run_id=$2 WHERE id=$1`, string(artifactID), string(runID))
	return dbError(err)
}

func (tx *Tx) LoadValidation(id contract.UUID) (ValidationRun, error) {
	if id.Validate() != nil {
		return ValidationRun{}, ErrInvalid
	}
	var run ValidationRun
	var errorsJSON json.RawMessage
	var logKey, sha *string
	var size sql.NullInt64
	err := tx.db.QueryRowContext(tx.ctx, `SELECT r.id::text,r.package_artifact_id::text,r.status,r.problemtools_version,r.adapter_version,r.toolchain_version,r.image_digest,r.config_sha256::text,r.source_sha256::text,r.normalized_sha256::text,r.results,r.errors,r.adaptations,r.log_object_key,o.sha256::text,o.size_bytes,r.started_at,r.finished_at,r.created_at FROM judge.package_validation_runs r LEFT JOIN judge.private_objects o ON o.object_key=r.log_object_key WHERE r.id=$1 AND r.status IN ('PASSED','FAILED')`, string(id)).Scan(&run.ID, &run.PackageArtifactID, &run.Status, &run.Context.ProblemtoolsVersion, &run.Context.AdapterVersion, &run.Context.ToolchainVersion, &run.Context.ImageDigest, &run.Context.ConfigSHA256, &run.Context.SourceSHA256, &run.Context.NormalizedSHA256, &run.Results, &errorsJSON, &run.Adaptations, &logKey, &sha, &size, &run.StartedAt, &run.FinishedAt, &run.CreatedAt)
	if err != nil {
		return ValidationRun{}, dbError(err)
	}
	if json.Unmarshal(errorsJSON, &run.Errors) != nil {
		return ValidationRun{}, ErrIntegrity
	}
	if logKey != nil {
		if sha == nil || !size.Valid {
			return ValidationRun{}, ErrIntegrity
		}
		run.Log = &storage.Object{Key: *logKey, SHA256: *sha, SizeBytes: size.Int64}
		if run.Log.Validate() != nil {
			return ValidationRun{}, ErrIntegrity
		}
	}
	return run, nil
}

func (r *Repository) LoadValidation(ctx context.Context, id contract.UUID) (ValidationRun, error) {
	var out ValidationRun
	err := r.WithTx(ctx, &sql.TxOptions{ReadOnly: true}, func(tx *Tx) error { var err error; out, err = tx.LoadValidation(id); return err })
	return out, err
}
