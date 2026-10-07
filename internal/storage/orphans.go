package storage

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
)

var stopWalk = errors.New("private object scan batch complete")

// walkPublished never follows symlinks. The callback controls the batch, so a
// prefix of registered objects cannot starve later unregistered crash debris.
func (store *Store) walkPublished(ctx context.Context, before time.Time, visit func(Object) error) error {
	for _, directory := range []string{"sha256", "sources"} {
		err := fs.WalkDir(store.root.FS(), directory, func(name string, entry fs.DirEntry, walkErr error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if walkErr != nil {
				return ErrUnavailable
			}
			if entry.Type()&fs.ModeSymlink != 0 {
				return ErrUnsafePath
			}
			info, err := entry.Info()
			if err != nil {
				return ErrUnavailable
			}
			if entry.IsDir() {
				if info.Mode().Perm()&0077 != 0 {
					return ErrUnsafePath
				}
				return nil
			}
			if !info.Mode().IsRegular() {
				return ErrUnsafePath
			}
			if !info.ModTime().Before(before) {
				return nil
			}
			parts := strings.Split(name, "/")
			if len(parts) != 3 {
				return ErrUnsafePath
			}
			object := Object{Key: name, SHA256: parts[2], SizeBytes: info.Size()}
			if object.Validate() != nil {
				return ErrUnsafePath
			}
			return visit(object)
		})
		if errors.Is(err, stopWalk) {
			return nil
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// CollectUnregistered covers publication without a ledger row. Each candidate
// is rechecked against both registry and historical owners under the same
// cross-process lock as newStage before unlinking. The limit counts removals.
func (registry *Registry) CollectUnregistered(ctx context.Context, before time.Time, limit int) (int, error) {
	if limit < 1 || limit > 1000 {
		return 0, ErrInvalidObject
	}
	removed := 0
	err := registry.store.walkPublished(ctx, before, func(object Object) error {
		count, err := registry.collectUnregisteredOne(ctx, object)
		if err != nil {
			return err
		}
		removed += count
		if removed >= limit {
			return stopWalk
		}
		return nil
	})
	return removed, err
}

func (registry *Registry) collectUnregisteredOne(ctx context.Context, object Object) (int, error) {
	tx, err := registry.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, databaseError(err)
	}
	defer tx.Rollback()
	if err := lockObject(ctx, tx, object.Key); err != nil {
		return 0, err
	}
	var exists bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM judge.private_objects WHERE object_key=$1) OR judge.private_object_has_business_owner($1)`, object.Key).Scan(&exists)
	if err != nil {
		return 0, databaseError(err)
	}
	if exists {
		return 0, nil
	}
	if err := registry.store.remove(object); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, databaseError(err)
	}
	return 1, nil
}

// PruneStaging clears abandoned temporary writes. These filenames are never
// accepted object keys. Current writes have fresh mtimes; deleting an old open
// temporary file can only fail that write, never invalidate registered bytes.
func (store *Store) PruneStaging(ctx context.Context, before time.Time, limit int) (int, error) {
	if limit < 1 || limit > 1000 {
		return 0, ErrInvalidObject
	}
	directory, err := store.root.Open("staging")
	if err != nil {
		return 0, ErrUnavailable
	}
	defer directory.Close()
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return 0, ErrUnavailable
	}
	removed := 0
	for _, entry := range entries {
		if ctx.Err() != nil {
			return removed, ctx.Err()
		}
		if removed >= limit {
			break
		}
		if contract.UUID(entry.Name()).Validate() != nil || entry.Type()&fs.ModeSymlink != 0 || entry.IsDir() {
			return removed, ErrUnsafePath
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return removed, ErrUnsafePath
		}
		if !info.ModTime().Before(before) {
			continue
		}
		if err := store.root.Remove("staging/" + entry.Name()); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return removed, ErrUnavailable
		}
		removed++
	}
	return removed, nil
}
