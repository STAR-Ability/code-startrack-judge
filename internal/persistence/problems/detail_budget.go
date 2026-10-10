// SPDX-License-Identifier: Apache-2.0

package problems

import (
	"database/sql"
	"errors"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/responsebudget"
)

var ErrDetailTooLarge = errors.New("problem detail exceeds implementation response budget")

// VersionDetailFits uses the same complete projection for import preparation
// and the persistence boundary. License facts come from the selected immutable
// approval, rather than untrusted package claims.
func VersionDetailFits(spec VersionSpec, license contract.License) bool {
	detail := contract.PlatformProblemDetail{
		PlatformProblemSummary: contract.PlatformProblemSummary{
			ProblemRef: contract.PlatformProblemRef{Source: contract.SourcePlatform, Platform: contract.PlatformStartrack},
			Title:      &spec.Title, DifficultyScale: spec.DifficultyScale, Tags: spec.Tags,
			TimeLimitMs: contract.SafeInt(spec.TimeLimitMs), MemoryLimitBytes: contract.SafeInt(spec.MemoryLimitBytes), LanguageIDs: spec.LanguageIDs,
		},
		Statement: contract.Statement{Format: spec.StatementFormat, Content: spec.StatementContent, Input: spec.StatementInput, Output: spec.StatementOutput},
		Samples:   spec.Samples, License: license,
	}
	if spec.Difficulty != nil {
		value := contract.SafeInt(*spec.Difficulty)
		detail.Difficulty = &value
	}
	return responsebudget.ProblemDetailFits(detail)
}

func (tx *Tx) checkVersionDetail(spec VersionSpec) error {
	var license contract.License
	var spdx sql.NullString
	err := tx.DB().QueryRowContext(tx.ctx, `SELECT l.spdx_id,l.notice,l.source_url
 FROM judge.package_artifacts a JOIN judge.license_evidence l ON l.id=a.license_evidence_id
 WHERE a.id=$1 AND a.problem_id=$2`, string(spec.PackageArtifactID), string(spec.ProblemID)).Scan(&spdx, &license.Notice, &license.SourceURL)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrIntegrity
	}
	if err != nil {
		return dbError(err)
	}
	if spdx.Valid {
		license.SPDXID = &spdx.String
	}
	if !VersionDetailFits(spec, license) {
		return ErrDetailTooLarge
	}
	return nil
}
