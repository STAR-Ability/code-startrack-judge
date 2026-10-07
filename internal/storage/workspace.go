package storage

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
)

type File struct {
	Path string
	Data []byte
}
type ExtractionLimits struct {
	MaxFiles                    int
	MaxFileBytes, MaxTotalBytes int64
}

var PackageExtractionLimits = ExtractionLimits{MaxFiles: 65536, MaxFileBytes: 64 << 20, MaxTotalBytes: 512 << 20}

// ValidRelativePath rejects ambiguous filesystem interpretations without
// repairing paths or normalizing Unicode. Archive parsers must also reject
// links, extension/sparse records, special entries and duplicate names.
func ValidRelativePath(name string) error {
	if !utf8.ValidString(name) || !fs.ValidPath(name) || name == "." || strings.ContainsAny(name, "\\%:") {
		return ErrUnsafePath
	}
	for _, character := range name {
		if unicode.IsControl(character) {
			return ErrUnsafePath
		}
	}
	for _, segment := range strings.Split(name, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return ErrUnsafePath
		}
	}
	return nil
}

type Workspace struct {
	ID    contract.UUID
	root  *os.Root
	store *Store
	key   string
}

func (*Workspace) String() string   { return "private workspace (redacted)" }
func (*Workspace) GoString() string { return "private workspace (redacted)" }

func (workspace *Workspace) Root() *os.Root { return workspace.root }
func (workspace *Workspace) Close() error   { return workspace.root.Close() }
func (workspace *Workspace) Remove() error {
	workspace.root.Close()
	if err := workspace.store.root.RemoveAll(workspace.key); err != nil {
		return ErrUnavailable
	}
	return nil
}

// ExtractFiles accepts a validated regular-file inventory, allocates a new
// private workspace and creates every file exclusively. Executable mode bits
// are not trusted. Portable case folding collisions fail before any write.
func (store *Store) ExtractFiles(ctx context.Context, taskID contract.UUID, files []File, limits ExtractionLimits) (*Workspace, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if taskID.Validate() != nil || limits.MaxFiles < 1 || limits.MaxFiles > PackageExtractionLimits.MaxFiles || limits.MaxFileBytes < 0 || limits.MaxFileBytes > PackageExtractionLimits.MaxFileBytes || limits.MaxTotalBytes < 0 || limits.MaxTotalBytes > PackageExtractionLimits.MaxTotalBytes || len(files) > limits.MaxFiles {
		return nil, ErrSizeLimit
	}
	seen := map[string]struct{}{}
	var total int64
	for _, file := range files {
		if err := ValidRelativePath(file.Path); err != nil {
			return nil, err
		}
		folded := portableFold(file.Path)
		if _, exists := seen[folded]; exists {
			return nil, ErrUnsafePath
		}
		seen[folded] = struct{}{}
		if int64(len(file.Data)) > limits.MaxFileBytes || int64(len(file.Data)) > limits.MaxTotalBytes-total {
			return nil, ErrSizeLimit
		}
		total += int64(len(file.Data))
	}
	// Prefix collisions (a regular file named a and another named a/b) are
	// rejected before writing, including portable case-folding interpretations.
	for name := range seen {
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			if _, exists := seen[parent]; exists {
				return nil, ErrUnsafePath
			}
		}
	}
	id, err := contract.NewUUID()
	if err != nil {
		return nil, ErrUnavailable
	}
	parent := "work/" + strings.ToLower(string(taskID))
	if err := store.directory(parent); err != nil {
		return nil, err
	}
	key := parent + "/" + string(id)
	if err := store.root.Mkdir(key, 0700); err != nil {
		return nil, ErrUnavailable
	}
	root, err := store.root.OpenRoot(key)
	if err != nil {
		store.root.RemoveAll(key)
		return nil, ErrUnavailable
	}
	workspace := &Workspace{ID: id, root: root, store: store, key: key}
	complete := false
	defer func() {
		if !complete {
			workspace.Remove()
		}
	}()
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if parent := path.Dir(file.Path); parent != "." {
			if err := root.MkdirAll(parent, 0700); err != nil {
				return nil, ErrUnavailable
			}
		}
		handle, err := root.OpenFile(file.Path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|noFollow, 0600)
		if err != nil {
			return nil, ErrUnsafePath
		}
		_, writeErr := handle.Write(file.Data)
		closeErr := handle.Close()
		if writeErr != nil || closeErr != nil {
			return nil, ErrUnavailable
		}
	}
	complete = true
	return workspace, nil
}

func portableFold(value string) string {
	var result strings.Builder
	for _, character := range value {
		minimum := character
		for other := unicode.SimpleFold(character); other != character; other = unicode.SimpleFold(other) {
			if other < minimum {
				minimum = other
			}
		}
		result.WriteRune(minimum)
	}
	return result.String()
}

func (store *Store) Check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, name := range []string{".", "sha256", "sources", "staging", "work"} {
		info, err := store.root.Lstat(name)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
			return ErrUnsafePath
		}
	}
	id, err := contract.NewUUID()
	if err != nil {
		return ErrUnavailable
	}
	key := "staging/" + string(id)
	file, err := store.root.OpenFile(key, os.O_RDWR|os.O_CREATE|os.O_EXCL|noFollow, 0600)
	if err != nil {
		return ErrUnavailable
	}
	defer store.root.Remove(key)
	defer file.Close()
	probe := []byte("judge-private-storage-probe")
	if _, err := file.Write(probe); err != nil {
		return ErrUnavailable
	}
	if err := file.Sync(); err != nil {
		return ErrUnavailable
	}
	actual := make([]byte, len(probe))
	if _, err := file.ReadAt(actual, 0); err != nil || string(actual) != string(probe) {
		return ErrIntegrity
	}
	if err := file.Close(); err != nil {
		return ErrUnavailable
	}
	if err := store.root.Remove(key); err != nil {
		return ErrUnavailable
	}
	directory, err := store.root.Open("staging")
	if err != nil {
		return ErrUnavailable
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return ErrUnavailable
	}
	return ctx.Err()
}

func (store *Store) removeTaskWork(taskID contract.UUID) error {
	if taskID.Validate() != nil {
		return ErrInvalidObject
	}
	if err := store.root.RemoveAll("work/" + strings.ToLower(string(taskID))); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return ErrUnavailable
	}
	return nil
}
