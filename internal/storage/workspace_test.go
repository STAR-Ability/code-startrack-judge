package storage

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestExtractionRejectsAmbiguousPathsAndCollisions(t *testing.T) {
	store, _ := newTestStore(t)
	for _, name := range []string{".", "../answer", "a/../answer", "/absolute", "a\\b", "a%2fb", "C:answer", "a//b", "a/./b", "a/\x00b", string([]byte{'a', 0xff})} {
		if ValidRelativePath(name) == nil {
			t.Fatalf("unsafe path accepted: %q", name)
		}
	}
	for _, names := range [][]string{{"a", "a"}, {"A", "a"}, {"K.cpp", "k.cpp"}, {"Σ", "ς"}, {"a", "a/b"}, {"A", "a/b"}} {
		files := []File{{Path: names[0], Data: []byte("x")}, {Path: names[1], Data: []byte("y")}}
		if workspace, err := store.ExtractFiles(context.Background(), testTaskID(), files, PackageExtractionLimits); !errors.Is(err, ErrUnsafePath) {
			if workspace != nil {
				workspace.Remove()
			}
			t.Fatalf("collision accepted: %q %v", names, err)
		}
	}
}

func TestExtractionPrivateRegularFilesCleanupAndBounds(t *testing.T) {
	store, directory := newTestStore(t)
	files := []File{{Path: "data/secret/1.in", Data: []byte("1\r\n")}, {Path: "é.txt", Data: []byte("combining")}}
	workspace, err := store.ExtractFiles(context.Background(), testTaskID(), files, PackageExtractionLimits)
	if err != nil {
		t.Fatal(err)
	}
	key := workspace.key
	for _, file := range files {
		got, err := workspace.Root().ReadFile(file.Path)
		if err != nil || string(got) != string(file.Data) {
			t.Fatal("workspace altered bytes")
		}
		info, err := workspace.Root().Lstat(file.Path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatal("workspace permissions incorrect")
		}
	}
	if err := workspace.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(directory, key)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("workspace retained after remove")
	}
	if workspace, err := store.ExtractFiles(context.Background(), testTaskID(), files, ExtractionLimits{MaxFiles: 1, MaxFileBytes: 100, MaxTotalBytes: 100}); !errors.Is(err, ErrSizeLimit) {
		if workspace != nil {
			workspace.Remove()
		}
		t.Fatal("file count bound ignored")
	}
	if workspace, err := store.ExtractFiles(context.Background(), testTaskID(), files, ExtractionLimits{MaxFiles: 5, MaxFileBytes: 5, MaxTotalBytes: 100}); !errors.Is(err, ErrSizeLimit) {
		if workspace != nil {
			workspace.Remove()
		}
		t.Fatal("file size bound ignored")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.ExtractFiles(ctx, testTaskID(), files, PackageExtractionLimits); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored")
	}
	entries, err := os.ReadDir(filepath.Join(directory, "work", string(testTaskID())))
	if err != nil || len(entries) != 0 {
		t.Fatal("failed extraction left work directory")
	}
}
