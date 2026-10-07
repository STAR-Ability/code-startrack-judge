package problems

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
)

// PublicQuery contains only validated public filters. It cannot name private
// columns or SQL fragments. Count and rows are read from one MVCC snapshot.
type PublicQuery struct {
	Page, PageSize               contract.SafeInt
	Q, Tag                       *string
	MinDifficulty, MaxDifficulty *contract.SafeInt
	Status                       contract.PlatformProblemStatus
}

var ErrPublicNotFound = errors.New("public problem view not found")

const summaryColumns = `p.id::text,v.id::text,v.title,v.difficulty,v.difficulty_scale,to_json(v.tags),
 CASE WHEN v.first_published_at IS NULL THEN 'DRAFT' ELSE p.status END,c.catalog_version::text,
 v.time_limit_ms,v.memory_limit_bytes,
 COALESCE((SELECT json_agg(x.language_id ORDER BY x.ordinality) FROM unnest(v.language_ids) WITH ORDINALITY x(language_id,ordinality)
 WHERE EXISTS(SELECT 1 FROM judge.judge_language_configs lc WHERE lc.language_id=x.language_id AND lc.is_active)),'[]'::json),
 CASE WHEN v.first_published_at IS NULL THEN v.created_at ELSE p.public_updated_at END`

type rowScanner interface{ Scan(...any) error }

func scanSummary(row rowScanner, extra ...any) (contract.PlatformProblemSummary, error) {
	var out contract.PlatformProblemSummary
	var title string
	var difficulty sql.NullInt64
	var tags, languages []byte
	var updated time.Time
	args := []any{&out.ProblemRef.ProblemID, &out.ProblemRef.ProblemVersionID, &title, &difficulty, &out.DifficultyScale, &tags,
		&out.Status, &out.CatalogVersion, &out.TimeLimitMs, &out.MemoryLimitBytes, &languages, &updated}
	args = append(args, extra...)
	if err := row.Scan(args...); err != nil {
		return out, err
	}
	out.ProblemRef.Source = contract.SourcePlatform
	out.ProblemRef.Platform = contract.PlatformStartrack
	out.Title = &title
	if difficulty.Valid {
		value := contract.SafeInt(difficulty.Int64)
		out.Difficulty = &value
	}
	if err := json.Unmarshal(tags, &out.Tags); err != nil {
		return out, err
	}
	if err := json.Unmarshal(languages, &out.LanguageIDs); err != nil {
		return out, err
	}
	out.UpdatedAt = contract.UTC(updated)
	return out, out.Validate()
}

func (tx *Tx) PublicDetail(problemID contract.ID, versionID *contract.UUID, currentOnly bool) (contract.PlatformProblemDetail, error) {
	var out contract.PlatformProblemDetail
	var samples []byte
	var input, output, spdx sql.NullString
	where := `p.id=$1 AND v.id=p.current_version_id AND p.status='PUBLISHED'`
	args := []any{string(problemID)}
	if !currentOnly {
		where = `p.id=$1 AND v.id=$2`
		args = append(args, string(*versionID))
	}
	row := tx.DB().QueryRowContext(tx.ctx, `SELECT `+summaryColumns+`,v.statement_format,v.statement_content,v.statement_input,v.statement_output,
 v.samples,l.spdx_id,l.notice,l.source_url FROM judge.platform_problems p JOIN judge.problem_versions v ON v.problem_id=p.id
 JOIN judge.package_artifacts a ON a.id=v.package_artifact_id JOIN judge.license_evidence l ON l.id=a.license_evidence_id
 CROSS JOIN judge.catalog_state c WHERE `+where, args...)
	summary, err := scanSummary(row, &out.Statement.Format, &out.Statement.Content, &input, &output, &samples, &spdx, &out.License.Notice, &out.License.SourceURL)
	if errors.Is(err, sql.ErrNoRows) {
		return out, ErrPublicNotFound
	}
	if err != nil {
		return out, err
	}
	out.PlatformProblemSummary = summary
	if input.Valid {
		out.Statement.Input = &input.String
	}
	if output.Valid {
		out.Statement.Output = &output.String
	}
	if spdx.Valid {
		out.License.SPDXID = &spdx.String
	}
	if err := json.Unmarshal(samples, &out.Samples); err != nil {
		return out, err
	}
	return out, nil
}

func (r *Repository) PublicDetail(ctx context.Context, problemID contract.ID, versionID *contract.UUID, currentOnly bool) (contract.PlatformProblemDetail, error) {
	var out contract.PlatformProblemDetail
	err := r.WithTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true}, func(tx *Tx) error {
		var err error
		out, err = tx.PublicDetail(problemID, versionID, currentOnly)
		return err
	})
	return out, err
}

func (r *Repository) PublicList(ctx context.Context, q PublicQuery) (contract.Array[contract.PlatformProblemSummary], contract.PageMeta, error) {
	items := make(contract.Array[contract.PlatformProblemSummary], 0)
	meta := contract.PageMeta{Page: q.Page, PageSize: q.PageSize}
	err := r.WithTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true}, func(tx *Tx) error {
		args := []any{string(q.Status), q.Q, q.Tag, q.MinDifficulty, q.MaxDifficulty}
		from := ` FROM judge.platform_problems p JOIN judge.problem_versions v ON v.problem_id=p.id AND v.id=CASE WHEN p.status='DRAFT' THEN p.latest_version_id ELSE p.current_version_id END CROSS JOIN judge.catalog_state c
 WHERE p.status=$1 AND ($2::text IS NULL OR strpos(lower(v.title),lower($2))>0 OR strpos(p.id::text,$2)>0)
 AND ($3::text IS NULL OR $3=ANY(v.tags))
 AND ($4::bigint IS NULL OR (v.difficulty_scale='PLATFORM_RATING' AND v.difficulty >= $4))
 AND ($5::bigint IS NULL OR (v.difficulty_scale='PLATFORM_RATING' AND v.difficulty <= $5))`
		if err := tx.DB().QueryRowContext(ctx, `SELECT count(*)`+from, args...).Scan(&meta.Total); err != nil {
			return err
		}
		args = append(args, int64(q.PageSize), int64(q.Page-1)*int64(q.PageSize))
		rows, err := tx.DB().QueryContext(ctx, `SELECT `+summaryColumns+from+` ORDER BY CASE WHEN v.first_published_at IS NULL THEN v.created_at ELSE p.public_updated_at END DESC,p.id DESC LIMIT $6 OFFSET $7`, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			item, err := scanSummary(rows)
			if err != nil {
				return err
			}
			items = append(items, item)
		}
		return rows.Err()
	})
	meta.HasNext = q.Page*q.PageSize < meta.Total
	return items, meta, err
}

func (r *Repository) PublicHistory(ctx context.Context, id contract.ID, page, pageSize contract.SafeInt) (contract.Array[contract.PlatformProblemSummary], contract.PageMeta, error) {
	items := make(contract.Array[contract.PlatformProblemSummary], 0)
	meta := contract.PageMeta{Page: page, PageSize: pageSize}
	err := r.WithTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true}, func(tx *Tx) error {
		var exists bool
		if err := tx.DB().QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM judge.platform_problems WHERE id=$1)`, string(id)).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrPublicNotFound
		}
		if err := tx.DB().QueryRowContext(ctx, `SELECT count(*) FROM judge.problem_versions WHERE problem_id=$1`, string(id)).Scan(&meta.Total); err != nil {
			return err
		}
		rows, err := tx.DB().QueryContext(ctx, `SELECT `+summaryColumns+` FROM judge.platform_problems p JOIN judge.problem_versions v ON v.problem_id=p.id CROSS JOIN judge.catalog_state c WHERE p.id=$1 ORDER BY v.version_number DESC LIMIT $2 OFFSET $3`, string(id), int64(pageSize), int64(page-1)*int64(pageSize))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			item, err := scanSummary(rows)
			if err != nil {
				return err
			}
			items = append(items, item)
		}
		return rows.Err()
	})
	meta.HasNext = page*pageSize < meta.Total
	return items, meta, err
}
