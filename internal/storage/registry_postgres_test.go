package storage_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/storage"
	"github.com/STAR-Ability/code-startrack-judge/internal/testutil/judgetask"
	"github.com/STAR-Ability/code-startrack-judge/internal/testutil/postgres"
	"github.com/jackc/pgx/v5/pgconn"
)

type lifecycleFixture struct {
	db       postgres.Database
	store    *storage.Store
	registry *storage.Registry
}

func lifecycle(t *testing.T) lifecycleFixture {
	t.Helper()
	db := postgres.New(t)
	directory := t.TempDir()
	if os.Chmod(directory, 0700) != nil {
		t.Fatal("private fixture directory unavailable")
	}
	store, err := storage.New(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	registry, err := storage.NewRegistry(db.Runtime, store)
	if err != nil {
		t.Fatal(err)
	}
	return lifecycleFixture{db, store, registry}
}
func execFixture(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatal("synthetic lifecycle fixture failed")
	}
}
func blob(t *testing.T, data string) storage.Object {
	t.Helper()
	object, err := storage.Blob(canonical.HashBytes([]byte(data)), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	return object
}

func TestPostgresStagePinExpiryAndConcurrentGC(t *testing.T) {
	f := lifecycle(t)
	ctx := context.Background()
	object := blob(t, "durable staged bytes")
	stage, err := f.registry.StageImmutable(ctx, strings.NewReader("durable staged bytes"), object)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := f.registry.Collect(ctx, time.Now().Add(time.Hour), 100); err != nil || n != 0 {
		t.Fatalf("live stage collected: %d %v", n, err)
	}
	if n, err := f.registry.CollectUnregistered(ctx, time.Now().Add(time.Hour), 100); err != nil || n != 0 {
		t.Fatalf("registered stage removed: %d %v", n, err)
	}
	execFixture(t, f.db.Admin, `UPDATE judge.private_object_stages SET expires_at=created_at+interval '1 microsecond' WHERE id=$1`, string(stage.RegistrationID))
	if err := f.registry.Renew(ctx, stage); !errors.Is(err, storage.ErrStageLost) {
		t.Fatal("expired stage resurrected")
	}
	var group sync.WaitGroup
	counts := make(chan int, 8)
	failures := make(chan error, 8)
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			n, err := f.registry.Collect(ctx, time.Now().Add(time.Hour), 100)
			counts <- n
			failures <- err
		}()
	}
	group.Wait()
	close(counts)
	close(failures)
	sum := 0
	for n := range counts {
		sum += n
	}
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	if sum != 1 {
		t.Fatalf("concurrent GC deletions=%d", sum)
	}
	if err := f.store.Verify(ctx, object); !errors.Is(err, storage.ErrNotFound) {
		t.Fatal("expired abandoned object survived")
	}
}

func TestPostgresUnregisteredScanDoesNotStarve(t *testing.T) {
	f := lifecycle(t)
	ctx := context.Background()
	// Fill a prefix with ledger objects, leaving later raw publications outside
	// the ledger. A limit of one must still eventually reach all crash debris.
	for i := 0; i < 12; i++ {
		data := strings.Repeat(string(rune('A'+i)), 20)
		object := blob(t, data)
		if _, err := f.registry.StageImmutable(ctx, strings.NewReader(data), object); err != nil {
			t.Fatal(err)
		}
	}
	orphan, err := f.store.Put(ctx, strings.NewReader("crashed raw publication"), 100)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := f.registry.CollectUnregistered(ctx, time.Now().Add(time.Hour), 1); err != nil || n != 1 {
		t.Fatalf("orphan starved: %d %v", n, err)
	}
	if err := f.store.Verify(ctx, orphan); !errors.Is(err, storage.ErrNotFound) {
		t.Fatal("raw orphan remains")
	}
}

func TestPostgresHistoricalOwnerWithoutRegistrationSurvivesGC(t *testing.T) {
	f := lifecycle(t)
	ctx := context.Background()
	data := "historical private archive"
	object := blob(t, data)
	if _, err := f.store.Put(ctx, strings.NewReader(data), 100); err != nil {
		t.Fatal(err)
	}
	// This fixture intentionally follows the baseline's existing owner rows,
	// before lifecycle pins were introduced. It never disables any constraint.
	raw, err := os.ReadFile(filepath.Join("..", "testutil", "judgetask", "testdata", "seed.sql"))
	if err != nil {
		t.Fatal("historical fixture missing")
	}
	fixture := strings.ReplaceAll(string(raw), "private/source", object.Key)
	fixture = strings.ReplaceAll(fixture, "repeat('a',64)", "'"+object.SHA256+"'")
	execFixture(t, f.db.Admin, fixture)
	if n, err := f.registry.CollectUnregistered(ctx, time.Now().Add(time.Hour), 100); err != nil || n != 0 {
		t.Fatalf("historical owner collected: %d %v", n, err)
	}
	// A ledger record without its reference is equally protected by the owner.
	stage, err := f.registry.StageImmutable(ctx, strings.NewReader(data), object)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.registry.Release(ctx, stage); err != nil {
		t.Fatal(err)
	}
	if n, err := f.registry.Collect(ctx, time.Now().Add(time.Hour), 100); err != nil || n != 0 {
		t.Fatalf("missing pin erased history: %d %v", n, err)
	}
	if err := f.store.Verify(ctx, object); err != nil {
		t.Fatal("historical bytes lost")
	}
}

func TestPostgresTerminalSourceRetentionAndCleanedException(t *testing.T) {
	f := lifecycle(t)
	ctx := context.Background()
	judgetask.Seed(t, f.db.Admin, 1)
	type taskCopy struct {
		id     contract.UUID
		object storage.Object
	}
	copies := make([]taskCopy, 0, 3)
	for index, status := range []string{"QUEUED", "CANCELLED", "CANCELLED"} {
		id, err := contract.NewUUID()
		if err != nil {
			t.Fatal(err)
		}
		source := []byte("int main(){}\r\n")
		stage, err := f.registry.Stage(ctx, id, source, canonical.HashBytes(source))
		if err != nil {
			t.Fatal(err)
		}
		object := storage.Object{Key: stage.Key, SHA256: stage.SHA256, SizeBytes: stage.SizeBytes}
		copies = append(copies, taskCopy{id, object})
		request, _ := contract.NewUUID()
		tx, err := f.db.Runtime.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal("task fixture unavailable")
		}
		terminal := index > 0
		age := "0 hours"
		if index == 2 {
			age = "25 hours"
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO judge.judge_tasks(id,request_id,request_hash,submission_id,problem_id,problem_version_id,source_owner,source_sha256,transient_source_key,source_expires_at,language_id,language_config_version,sandbox_version,worker_image_digest,execution_limits,status,error,finished_at)
   VALUES($1,$2,repeat('a',64),$3,1,'00000000-0000-0000-0000-000000000011','backend',$4,$5,
   CASE WHEN $6 THEN now()-$7::interval+interval '24 hours' ELSE NULL END,
   'cpp17',$8,'synthetic','sha256:'||repeat('b',64),'{}',$9,
   CASE WHEN $6 THEN '{"code":"TASK_CANCELLED","message":"Synthetic cancellation","retryable":false}'::jsonb ELSE NULL END,
   CASE WHEN $6 THEN now()-$7::interval ELSE NULL END)`, string(id), string(request), index+100, object.SHA256, object.Key, terminal, age, judgetask.Identity().LanguageConfigVersion, status)
		if err == nil {
			_, err = tx.ExecContext(ctx, `INSERT INTO judge.callback_outbox(event_id,judge_task_id,revision,event_type,request_id,payload,payload_hash,status,next_attempt_at) SELECT event_id,$1::uuid,1,'JUDGE_TASK_UPDATED',$2::uuid,jsonb_build_object('eventId',event_id::text,'requestId',$2::uuid,'aggregateId',$1::uuid,'eventType','JUDGE_TASK_UPDATED','revision',1,'payload',jsonb_build_object('revision',1,'requestId',$2::uuid,'judgeTaskId',$1::uuid,'submissionId',$3::text,'status',$4::text)),repeat('a',64),'PENDING',now() FROM (SELECT gen_random_uuid() event_id) generated`, string(id), string(request), strconv.Itoa(index+100), status)
		}
		if err == nil && !terminal {
			err = f.registry.AttachSource(ctx, tx, stage)
		}
		if err != nil {
			tx.Rollback()
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) {
				t.Fatalf("synthetic source task fixture SQLSTATE %s, constraint %s", pgErr.Code, pgErr.ConstraintName)
			}
			t.Fatal("synthetic source task fixture failed")
		}
		if err := tx.Commit(); err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) {
				t.Fatalf("source task index%d SQLSTATE %s: %s", index, pgErr.Code, pgErr.Message)
			}
			t.Fatal("synthetic source task consistency failed")
		}
		if terminal {
			if err := f.registry.Abandon(ctx, stage); err != nil {
				t.Fatal(err)
			}
		}
	}
	if n, err := f.registry.Collect(ctx, time.Now().Add(time.Hour), 100); err != nil || n != 0 {
		t.Fatalf("live/fresh/historical task copies collected: %d %v", n, err)
	}
	workspace, err := f.store.ExtractFiles(ctx, copies[2].id, []storage.File{{Path: "main.cpp", Data: []byte("private working bytes")}}, storage.PackageExtractionLimits)
	if err != nil {
		t.Fatal(err)
	}
	workspace.Close()
	if n, err := f.registry.CleanSources(ctx, 100); err != nil || n != 1 {
		t.Fatalf("terminal retention cleanup: %d %v", n, err)
	}
	if n, err := f.registry.Collect(ctx, time.Now().Add(time.Hour), 100); err != nil || n != 1 {
		t.Fatalf("cleaned exception not collected: %d %v", n, err)
	}
	for index, copy := range copies {
		err := f.store.Verify(ctx, copy.object)
		if index == 2 && !errors.Is(err, storage.ErrNotFound) {
			t.Fatal("expired source retained")
		}
		if index < 2 && err != nil {
			t.Fatal("in-flight/fresh source lost")
		}
	}
}
