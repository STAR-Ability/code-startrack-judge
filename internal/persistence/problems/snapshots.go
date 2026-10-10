package problems

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
)

type SnapshotPage struct {
	ID             contract.UUID
	CatalogVersion contract.ID
	Count, Limit   int64
	ExpiresAt      time.Time
	Items          contract.Array[contract.CatalogEntry]
}

// CreateSnapshot freezes safe projections with one INSERT SELECT under the
// same REPEATABLE READ snapshot as the catalog version. No DRAFT is included.
func (r *Repository) CreateSnapshot(ctx context.Context, limit int64) (SnapshotPage, error) {
	id, err := contract.NewUUID()
	if err != nil {
		return SnapshotPage{}, err
	}
	var out SnapshotPage
	err = r.WithTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead}, func(tx *Tx) error {
		_, err := tx.DB().ExecContext(ctx, `INSERT INTO judge.catalog_snapshots(id,catalog_version,item_count,page_limit,created_at,expires_at)
 SELECT $1,catalog_version,(SELECT count(*) FROM judge.platform_problems WHERE status IN ('PUBLISHED','WITHDRAWN')),$2,clock_timestamp(),clock_timestamp()+interval '30 minutes' FROM judge.catalog_state WHERE singleton_id=1`, string(id), limit)
		if err != nil {
			return err
		}
		_, err = tx.DB().ExecContext(ctx, `INSERT INTO judge.catalog_snapshot_items(snapshot_id,ordinal,problem_id,problem_version_id,status,problem_summary)
 SELECT $1,row_number() OVER(ORDER BY p.id)-1,p.id,v.id,p.status,
 jsonb_build_object('problemRef',jsonb_build_object('source','PLATFORM','platform','startrack','problemId',p.id::text,'problemVersionId',v.id::text),
 'title',v.title,'difficulty',v.difficulty,'difficultyScale',v.difficulty_scale,'tags',to_jsonb(v.tags),'url',NULL)
 FROM judge.platform_problems p JOIN judge.problem_versions v ON v.problem_id=p.id AND v.id=p.current_version_id
 WHERE p.status IN ('PUBLISHED','WITHDRAWN') ORDER BY p.id`, string(id))
		if err != nil {
			return err
		}
		out, err = tx.snapshotPage(id, 0, limit)
		return err
	})
	return out, err
}

func (r *Repository) SnapshotPage(ctx context.Context, id contract.UUID, offset, limit int64) (SnapshotPage, error) {
	var out SnapshotPage
	err := r.WithTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true}, func(tx *Tx) error { var err error; out, err = tx.snapshotPage(id, offset, limit); return err })
	return out, err
}
func (tx *Tx) snapshotPage(id contract.UUID, offset, limit int64) (SnapshotPage, error) {
	out := SnapshotPage{ID: id, Items: make(contract.Array[contract.CatalogEntry], 0)}
	var expired bool
	err := tx.DB().QueryRowContext(tx.ctx, `SELECT catalog_version::text,item_count,page_limit,expires_at,expires_at<=clock_timestamp() FROM judge.catalog_snapshots WHERE id=$1`, string(id)).Scan(&out.CatalogVersion, &out.Count, &out.Limit, &out.ExpiresAt, &expired)
	if errors.Is(err, sql.ErrNoRows) || expired {
		return out, workflowError("SNAPSHOT_EXPIRED")
	}
	if err != nil {
		return out, err
	}
	if out.Limit != limit || offset < 0 || (offset > 0 && (offset >= out.Count || offset%limit != 0)) {
		return out, workflowError("INVALID_ARGUMENT")
	}
	rows, err := tx.DB().QueryContext(tx.ctx, `SELECT status,problem_summary FROM judge.catalog_snapshot_items WHERE snapshot_id=$1 AND ordinal>=$2 ORDER BY ordinal LIMIT $3`, string(id), offset, limit)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var item contract.CatalogEntry
		var raw []byte
		if err := rows.Scan(&item.Status, &raw); err != nil {
			return out, err
		}
		if err := json.Unmarshal(raw, &item.Problem); err != nil {
			return out, err
		}
		if err := item.Validate(); err != nil {
			return out, err
		}
		out.Items = append(out.Items, item)
	}
	return out, rows.Err()
}

// CleanupSnapshots deletes only bounded batches of expired complete snapshots.
// Cascading page-row deletion cannot affect problem/version business history.
func (r *Repository) CleanupSnapshots(ctx context.Context, limit int) (int64, error) {
	if limit < 1 || limit > 1000 {
		return 0, workflowError("INVALID_ARGUMENT")
	}
	var count int64
	err := r.WithTx(ctx, nil, func(tx *Tx) error {
		result, err := tx.DB().ExecContext(ctx, `DELETE FROM judge.catalog_snapshots WHERE id IN(SELECT id FROM judge.catalog_snapshots WHERE expires_at<=clock_timestamp() ORDER BY expires_at,id LIMIT $1 FOR UPDATE SKIP LOCKED)`, limit)
		if err != nil {
			return err
		}
		count, err = result.RowsAffected()
		return err
	})
	return count, err
}
