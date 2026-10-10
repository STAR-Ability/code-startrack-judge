package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
)

func newTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := New(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, directory
}
func testTaskID() contract.UUID { return "a1000000-0000-0000-0000-000000000001" }

func TestPrivateExactSourceBytesAndAtomicReuse(t *testing.T) {
	store, directory := newTestStore(t)
	source := []byte("// é\r\nint main(){}\r\n")
	object, err := store.PutSource(context.Background(), testTaskID(), source)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.Read(context.Background(), object, int64(len(source)))
	if err != nil || !bytes.Equal(got, source) {
		t.Fatalf("exact source bytes: %v", err)
	}
	info, err := os.Stat(filepath.Join(directory, object.Key))
	if err != nil || info.Mode().Perm() != 0400 {
		t.Fatal("published bytes are not private read-only")
	}
	var group sync.WaitGroup
	failures := make(chan error, 16)
	for range 16 {
		group.Add(1)
		go func() {
			defer group.Done()
			reused, err := store.PutSource(context.Background(), testTaskID(), source)
			if err == nil && reused != object {
				err = ErrIntegrity
			}
			failures <- err
		}()
	}
	group.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	staged, err := os.ReadDir(filepath.Join(directory, "staging"))
	if err != nil || len(staged) != 0 {
		t.Fatal("publication left temporary writes")
	}
}

func TestPrivateLimitsCancellationAndMutation(t *testing.T) {
	store, directory := newTestStore(t)
	if _, err := store.Put(context.Background(), strings.NewReader("12345"), 4); !errors.Is(err, ErrSizeLimit) {
		t.Fatal("oversize write accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Put(ctx, strings.NewReader("x"), 1); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled write accepted")
	}
	if _, err := store.PutSource(context.Background(), testTaskID(), []byte{0xff}); !errors.Is(err, ErrInvalidObject) {
		t.Fatal("invalid UTF-8 accepted")
	}
	if _, err := store.PutSource(context.Background(), testTaskID(), []byte(" \n")); !errors.Is(err, ErrInvalidObject) {
		t.Fatal("blank source accepted")
	}
	object, err := store.Put(context.Background(), strings.NewReader("1234"), 4)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(context.Background(), object, 3); !errors.Is(err, ErrSizeLimit) {
		t.Fatal("oversize read accepted")
	}
	if err := os.Chmod(filepath.Join(directory, object.Key), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, object.Key), []byte("4321"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(directory, object.Key), 0400); err != nil {
		t.Fatal(err)
	}
	if err := store.Verify(context.Background(), object); !errors.Is(err, ErrIntegrity) {
		t.Fatal("mutated bytes accepted")
	}
	if _, err := store.Put(context.Background(), strings.NewReader("1234"), 4); !errors.Is(err, ErrIntegrity) {
		t.Fatal("immutable identity overwritten")
	}
}

func TestPrivateSymlinksAndPrivacy(t *testing.T) {
	store, directory := newTestStore(t)
	object, err := store.Put(context.Background(), strings.NewReader("secret-test-answer"), 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{object, SourceRegistration{Key: object.Key, SHA256: object.SHA256}, StagedObject{Object: object}} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			text := fmt.Sprintf(format, value)
			if strings.Contains(text, object.Key) || strings.Contains(text, object.SHA256) {
				t.Fatal("private formatter exposed object identity")
			}
		}
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("secret-test-answer"), 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(directory, object.Key)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(directory, object.Key)); err != nil {
		t.Fatal(err)
	}
	if err := store.Verify(context.Background(), object); !errors.Is(err, ErrUnsafePath) {
		t.Fatal("object symlink accepted")
	}
	if err := os.Remove(filepath.Join(directory, object.Key)); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Dir(filepath.Join(directory, object.Key))
	if err := os.Remove(parent); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), parent); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(context.Background(), strings.NewReader("secret-test-answer"), 100); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("ancestor symlink accepted: %v", err)
	}
	rootAlias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(directory, rootAlias); err != nil {
		t.Fatal(err)
	}
	if alias, err := New(rootAlias); !errors.Is(err, ErrUnsafePath) {
		if alias != nil {
			alias.Close()
		}
		t.Fatal("root symlink accepted")
	}
}

func TestPrivateReadiness(t *testing.T) {
	store, directory := newTestStore(t)
	if err := store.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(directory, "staging"))
	if err != nil || len(entries) != 0 {
		t.Fatal("readiness left private data")
	}
	if err := os.Chmod(filepath.Join(directory, "work"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := store.Check(context.Background()); !errors.Is(err, ErrUnsafePath) {
		t.Fatal("readiness ignored permissions")
	}
}

func TestPrivateDeletionRejectsNamespaceSymlink(t *testing.T) {
	store, directory := newTestStore(t)
	ctx := context.Background()
	stale, err := store.PutSource(ctx, testTaskID(), []byte("same exact source"))
	if err != nil {
		t.Fatal(err)
	}
	activeID := contract.UUID("a1000000-0000-0000-0000-000000000002")
	active, err := store.PutSource(ctx, activeID, []byte("same exact source"))
	if err != nil {
		t.Fatal(err)
	}
	staleDirectory := filepath.Join(directory, "sources", string(testTaskID()))
	if err := os.RemoveAll(staleDirectory); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(string(activeID), staleDirectory); err != nil {
		t.Fatal(err)
	}
	if err := store.remove(stale); !errors.Is(err, ErrUnsafePath) {
		t.Fatal("cleanup followed namespace alias")
	}
	if err := store.Verify(ctx, active); err != nil {
		t.Fatal("another task's source was deleted")
	}
}
