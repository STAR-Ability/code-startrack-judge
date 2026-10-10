package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
)

var ErrStageLost = errors.New("private object stage is missing or expired")

type Registry struct {
	db    *sql.DB
	store *Store
}

func NewRegistry(db *sql.DB, store *Store) (*Registry, error) {
	if db == nil || store == nil {
		return nil, ErrUnavailable
	}
	return &Registry{db, store}, nil
}
func (registry *Registry) Verify(ctx context.Context, object Object) error {
	return registry.store.Verify(ctx, object)
}

func databaseError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return ErrUnavailable
}
func lockObject(ctx context.Context, tx *sql.Tx, key string) error {
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('judge-private-object:' || $1,0))`, key)
	return databaseError(err)
}

// LockObjects reserves a complete workflow inventory in stable key order.
// Multi-object owner transactions call this before any individual retention
// to avoid cross-process lock inversions when packages share private bytes.
func (registry *Registry) LockObjects(ctx context.Context, tx *sql.Tx, objects []Object) error {
	if tx == nil {
		return ErrInvalidObject
	}
	keys := make([]string, 0, len(objects))
	for _, object := range objects {
		if err := object.Validate(); err != nil {
			return err
		}
		keys = append(keys, object.Key)
	}
	sort.Strings(keys)
	previous := ""
	for _, key := range keys {
		if key != previous {
			if err := lockObject(ctx, tx, key); err != nil {
				return err
			}
			previous = key
		}
	}
	return nil
}

func ensureObject(ctx context.Context, tx *sql.Tx, object Object) error {
	if err := object.Validate(); err != nil {
		return err
	}
	if err := lockObject(ctx, tx, object.Key); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO judge.private_objects(object_key,sha256,size_bytes) VALUES($1,$2,$3) ON CONFLICT(object_key) DO NOTHING`, object.Key, object.SHA256, object.SizeBytes)
	if err != nil {
		return databaseError(err)
	}
	var sha string
	var size int64
	err = tx.QueryRowContext(ctx, `SELECT sha256::text,size_bytes FROM judge.private_objects WHERE object_key=$1 FOR UPDATE`, object.Key).Scan(&sha, &size)
	if err != nil {
		return databaseError(err)
	}
	if sha != object.SHA256 || size != object.SizeBytes {
		return ErrIntegrity
	}
	return nil
}

func (registry *Registry) newStage(ctx context.Context, object Object, taskID *contract.UUID) (StagedObject, error) {
	if registry.db == nil || registry.store == nil {
		return StagedObject{}, ErrUnavailable
	}
	tx, err := registry.db.BeginTx(ctx, nil)
	if err != nil {
		return StagedObject{}, databaseError(err)
	}
	defer tx.Rollback()
	if err := ensureObject(ctx, tx, object); err != nil {
		return StagedObject{}, err
	}
	id, err := contract.NewUUID()
	if err != nil {
		return StagedObject{}, ErrUnavailable
	}
	stage := StagedObject{RegistrationID: id, Object: object}
	err = tx.QueryRowContext(ctx, `INSERT INTO judge.private_object_stages(id,object_key,task_id,expires_at) VALUES($1,$2,$3,clock_timestamp()+interval '1 hour') RETURNING expires_at`, string(id), object.Key, taskID).Scan(&stage.ExpiresAt)
	if err != nil {
		return StagedObject{}, databaseError(err)
	}
	if err := tx.Commit(); err != nil {
		return StagedObject{}, databaseError(err)
	}
	return stage, nil
}

func (registry *Registry) Stage(ctx context.Context, taskID contract.UUID, source []byte, expectedSHA256 string) (SourceRegistration, error) {
	if taskID.Validate() != nil || !utf8.Valid(source) || len(source) == 0 || strings.TrimSpace(string(source)) == "" {
		return SourceRegistration{}, ErrInvalidObject
	}
	if len(source) > contract.MaxSourceBytes {
		return SourceRegistration{}, ErrSizeLimit
	}
	taskID = contract.UUID(strings.ToLower(string(taskID)))
	digest := sha256.Sum256(source)
	sha := hex.EncodeToString(digest[:])
	if sha != expectedSHA256 {
		return SourceRegistration{}, ErrIntegrity
	}
	object := Object{Key: "sources/" + string(taskID) + "/" + sha, SHA256: sha, SizeBytes: int64(len(source))}
	stage, err := registry.newStage(ctx, object, &taskID)
	if err != nil {
		return SourceRegistration{}, err
	}
	registration := SourceRegistration{stage.RegistrationID, taskID, object.Key, object.SHA256, object.SizeBytes}
	written, err := registry.store.PutSource(ctx, taskID, source)
	if err != nil {
		registry.cleanup(ctx, func(cleanupCtx context.Context) { _ = registry.Abandon(cleanupCtx, registration) })
		return SourceRegistration{}, err
	}
	if written != object {
		registry.cleanup(ctx, func(cleanupCtx context.Context) { _ = registry.Abandon(cleanupCtx, registration) })
		return SourceRegistration{}, ErrIntegrity
	}
	return registration, nil
}

func (registry *Registry) StageImmutable(ctx context.Context, reader io.Reader, expected Object) (StagedObject, error) {
	if expected.Validate() != nil || !strings.HasPrefix(expected.Key, "sha256/") {
		return StagedObject{}, ErrInvalidObject
	}
	stage, err := registry.newStage(ctx, expected, nil)
	if err != nil {
		return StagedObject{}, err
	}
	written, err := registry.store.Put(ctx, reader, expected.SizeBytes)
	if err != nil {
		registry.cleanup(ctx, func(cleanupCtx context.Context) { _ = registry.Release(cleanupCtx, stage) })
		return StagedObject{}, err
	}
	if written != expected {
		registry.cleanup(ctx, func(cleanupCtx context.Context) { _ = registry.Release(cleanupCtx, stage) })
		return StagedObject{}, ErrIntegrity
	}
	return stage, nil
}

func (registry *Registry) cleanup(ctx context.Context, release func(context.Context)) {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	release(cleanupCtx)
}

// Abandon releases only this unconsumed candidate pin. If acceptance committed,
// the stage is already gone and its durable task reference remains untouched.
func (registry *Registry) Abandon(ctx context.Context, registration SourceRegistration) error {
	if registration.RegistrationID.Validate() != nil || registration.TaskID.Validate() != nil {
		return ErrInvalidObject
	}
	object := Object{registration.Key, registration.SHA256, registration.SizeBytes}
	if object.Validate() != nil {
		return ErrInvalidObject
	}
	tx, err := registry.db.BeginTx(ctx, nil)
	if err != nil {
		return databaseError(err)
	}
	defer tx.Rollback()
	if err := lockObject(ctx, tx, registration.Key); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM judge.private_object_stages WHERE id=$1 AND task_id=$2 AND object_key=$3`, string(registration.RegistrationID), string(registration.TaskID), registration.Key)
	if err != nil {
		return databaseError(err)
	}
	return databaseError(tx.Commit())
}

func (registry *Registry) Release(ctx context.Context, stage StagedObject) error {
	if stage.RegistrationID.Validate() != nil || stage.Object.Validate() != nil {
		return ErrInvalidObject
	}
	tx, err := registry.db.BeginTx(ctx, nil)
	if err != nil {
		return databaseError(err)
	}
	defer tx.Rollback()
	if err := lockObject(ctx, tx, stage.Object.Key); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM judge.private_object_stages WHERE id=$1 AND object_key=$2 AND task_id IS NULL`, string(stage.RegistrationID), stage.Object.Key)
	if err != nil {
		return databaseError(err)
	}
	return databaseError(tx.Commit())
}

func (registry *Registry) activeStage(ctx context.Context, tx *sql.Tx, id contract.UUID, object Object, taskID *contract.UUID) error {
	if id.Validate() != nil || object.Validate() != nil {
		return ErrInvalidObject
	}
	if err := ensureObject(ctx, tx, object); err != nil {
		return err
	}
	var expiry time.Time
	err := tx.QueryRowContext(ctx, `SELECT expires_at FROM judge.private_object_stages WHERE id=$1 AND object_key=$2 AND task_id IS NOT DISTINCT FROM $3::uuid FOR UPDATE`, string(id), object.Key, taskID).Scan(&expiry)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrStageLost
	}
	if err != nil {
		return databaseError(err)
	}
	var valid bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM judge.private_object_stages WHERE id=$1 AND object_key=$2 AND task_id IS NOT DISTINCT FROM $3::uuid AND expires_at>clock_timestamp())`, string(id), object.Key, taskID).Scan(&valid)
	if err != nil {
		return databaseError(err)
	}
	if !valid {
		return ErrStageLost
	}
	if err := registry.store.Verify(ctx, object); err != nil {
		return err
	}
	return nil
}

func (registry *Registry) AttachSource(ctx context.Context, tx *sql.Tx, registration SourceRegistration) error {
	if tx == nil || registration.TaskID.Validate() != nil {
		return ErrInvalidObject
	}
	object := Object{registration.Key, registration.SHA256, registration.SizeBytes}
	if err := registry.activeStage(ctx, tx, registration.RegistrationID, object, &registration.TaskID); err != nil {
		return err
	}
	var matches bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM judge.judge_tasks WHERE id=$1 AND transient_source_key=$2 AND source_sha256=$3 AND status='QUEUED')`, string(registration.TaskID), registration.Key, registration.SHA256).Scan(&matches)
	if err != nil {
		return databaseError(err)
	}
	if !matches {
		return ErrIntegrity
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO judge.private_object_references(object_key,owner_type,owner_id,role) VALUES($1,'TASK',$2,'SOURCE') ON CONFLICT DO NOTHING`, registration.Key, string(registration.TaskID))
	if err != nil {
		return databaseError(err)
	}
	return consumeStage(ctx, tx, registration.RegistrationID)
}

func (registry *Registry) AttachImmutable(ctx context.Context, tx *sql.Tx, stage StagedObject, ownerType string, ownerID contract.UUID, role string) error {
	if ownerType == "TASK" || !strings.HasPrefix(stage.Object.Key, "sha256/") {
		return ErrInvalidObject
	}
	if err := registry.activeStage(ctx, tx, stage.RegistrationID, stage.Object, nil); err != nil {
		return err
	}
	if err := registry.Retain(ctx, tx, stage.Object, ownerType, ownerID, role); err != nil {
		return err
	}
	return consumeStage(ctx, tx, stage.RegistrationID)
}

func consumeStage(ctx context.Context, tx *sql.Tx, id contract.UUID) error {
	// activeStage already holds this row lock, so the deadline is evaluated
	// after any waiting and after physical verification, without a new wait.
	result, err := tx.ExecContext(ctx, `DELETE FROM judge.private_object_stages WHERE id=$1 AND expires_at>clock_timestamp()`, string(id))
	if err != nil {
		return databaseError(err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return databaseError(err)
	}
	if count != 1 {
		return ErrStageLost
	}
	return nil
}

// Retain is for immutable owners. The deferrable database constraint confirms
// the real owner and matching key in this transaction before commit.
func (registry *Registry) Retain(ctx context.Context, tx *sql.Tx, object Object, ownerType string, ownerID contract.UUID, role string) error {
	if tx == nil || ownerType == "TASK" || ownerID.Validate() != nil || !strings.HasPrefix(object.Key, "sha256/") {
		return ErrInvalidObject
	}
	if err := ensureObject(ctx, tx, object); err != nil {
		return err
	}
	if err := registry.store.Verify(ctx, object); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO judge.private_object_references(object_key,owner_type,owner_id,role) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, object.Key, ownerType, string(ownerID), role)
	return databaseError(err)
}

// Renew keeps a staged immutable upload alive during a still-authorized long
// validation operation. Renewing an expired pin cannot resurrect it.
func (registry *Registry) Renew(ctx context.Context, stage StagedObject) error {
	if stage.RegistrationID.Validate() != nil || stage.Object.Validate() != nil {
		return ErrInvalidObject
	}
	tx, err := registry.db.BeginTx(ctx, nil)
	if err != nil {
		return databaseError(err)
	}
	defer tx.Rollback()
	if err := lockObject(ctx, tx, stage.Object.Key); err != nil {
		return err
	}
	// Acquire the tuple lock before evaluating the deadline. PostgreSQL may
	// evaluate UPDATE predicates before waiting on an unchanged locked tuple.
	// A second statement after lock acquisition prevents expired-pin revival.
	var expiry time.Time
	err = tx.QueryRowContext(ctx, `SELECT expires_at FROM judge.private_object_stages WHERE id=$1 AND object_key=$2 FOR UPDATE`, string(stage.RegistrationID), stage.Object.Key).Scan(&expiry)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrStageLost
	}
	if err != nil {
		return databaseError(err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE judge.private_object_stages SET expires_at=clock_timestamp()+interval '1 hour' WHERE id=$1 AND object_key=$2 AND expires_at>clock_timestamp()`, string(stage.RegistrationID), stage.Object.Key)
	if err != nil {
		return databaseError(err)
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return ErrStageLost
	}
	return databaseError(tx.Commit())
}

// Collect removes only old unreferenced objects with no live staged pin. The
// same per-key lock is used by allocation and registration across processes.
func (registry *Registry) Collect(ctx context.Context, before time.Time, limit int) (int, error) {
	if limit < 1 || limit > 1000 {
		return 0, ErrInvalidObject
	}
	rows, err := registry.db.QueryContext(ctx, `SELECT object_key,sha256::text,size_bytes FROM judge.private_objects o WHERE created_at<$1 AND NOT EXISTS(SELECT 1 FROM judge.private_object_references WHERE object_key=o.object_key) AND NOT EXISTS(SELECT 1 FROM judge.private_object_stages WHERE object_key=o.object_key AND expires_at>clock_timestamp()) AND NOT judge.private_object_has_business_owner(o.object_key) ORDER BY created_at,object_key LIMIT $2`, before, limit)
	if err != nil {
		return 0, databaseError(err)
	}
	var objects []Object
	for rows.Next() {
		var object Object
		if err := rows.Scan(&object.Key, &object.SHA256, &object.SizeBytes); err != nil {
			rows.Close()
			return 0, databaseError(err)
		}
		objects = append(objects, object)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, databaseError(err)
	}
	removed := 0
	for _, object := range objects {
		count, err := registry.collectOne(ctx, object)
		if err != nil {
			return removed, err
		}
		removed += count
	}
	return removed, nil
}

func (registry *Registry) collectOne(ctx context.Context, object Object) (int, error) {
	tx, err := registry.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, databaseError(err)
	}
	defer tx.Rollback()
	if err := lockObject(ctx, tx, object.Key); err != nil {
		return 0, err
	}
	// A tuple lock additionally fences direct reference INSERTs through their
	// FK KEY SHARE locks before unlink. Repository writers also share the key
	// advisory lock; both defenses precede the filesystem mutation.
	var sha string
	var size int64
	err = tx.QueryRowContext(ctx, `SELECT sha256::text,size_bytes FROM judge.private_objects WHERE object_key=$1 FOR UPDATE`, object.Key).Scan(&sha, &size)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, databaseError(err)
	}
	if sha != object.SHA256 || size != object.SizeBytes {
		return 0, ErrIntegrity
	}
	var live bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM judge.private_object_references WHERE object_key=$1) OR EXISTS(SELECT 1 FROM judge.private_object_stages WHERE object_key=$1 AND expires_at>clock_timestamp()) OR judge.private_object_has_business_owner($1)`, object.Key).Scan(&live)
	if err != nil {
		return 0, databaseError(err)
	}
	if live {
		return 0, nil
	}
	if err := registry.store.remove(object); err != nil {
		return 0, err
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM judge.private_object_stages WHERE object_key=$1`, object.Key)
	if err != nil {
		return 0, databaseError(err)
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM judge.private_objects WHERE object_key=$1`, object.Key)
	if err != nil {
		return 0, databaseError(err)
	}
	if err := tx.Commit(); err != nil {
		return 0, databaseError(err)
	}
	return 1, nil
}

// CleanSources clears only terminal task copies whose original 24-hour
// retention period has elapsed. It neither revises public state nor accesses
// backend storage, immutable package objects, or historical results.
func (registry *Registry) CleanSources(ctx context.Context, limit int) (int, error) {
	if limit < 1 || limit > 1000 {
		return 0, ErrInvalidObject
	}
	tx, err := registry.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, databaseError(err)
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT t.id::text,t.transient_source_key FROM judge.judge_tasks t WHERE status IN ('COMPLETED','FAILED','CANCELLED') AND transient_source_key IS NOT NULL AND source_expires_at<=clock_timestamp() AND finished_at<=clock_timestamp()-interval '24 hours' ORDER BY finished_at,id LIMIT $1 FOR UPDATE SKIP LOCKED`, limit)
	if err != nil {
		return 0, databaseError(err)
	}
	type candidate struct {
		id  contract.UUID
		key string
	}
	var candidates []candidate
	for rows.Next() {
		var value candidate
		if err := rows.Scan(&value.id, &value.key); err != nil {
			rows.Close()
			return 0, databaseError(err)
		}
		candidates = append(candidates, value)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, databaseError(err)
	}
	for _, value := range candidates {
		if err := lockObject(ctx, tx, value.key); err != nil {
			return 0, err
		}
		if err := registry.store.removeTaskWork(value.id); err != nil {
			return 0, err
		}
		_, err = tx.ExecContext(ctx, `UPDATE judge.judge_tasks SET transient_source_key=NULL WHERE id=$1`, string(value.id))
		if err != nil {
			return 0, databaseError(err)
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM judge.private_object_references WHERE object_key=$1 AND owner_type='TASK' AND owner_id=$2 AND role='SOURCE'`, value.key, string(value.id))
		if err != nil {
			return 0, databaseError(err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, databaseError(err)
	}
	// Actual unlink is separately retryable. A crash after pointer cleanup does
	// not keep submitted source indefinitely; orphan collection completes it.
	return len(candidates), nil
}
