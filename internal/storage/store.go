// Package storage owns private judge filesystem objects. Keys are server-made
// content identities, never caller filesystem paths, and never public DTOs.
package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
)

const MaxObjectBytes int64 = 1 << 30

var (
	ErrUnsafePath    = errors.New("unsafe private storage path")
	ErrSizeLimit     = errors.New("private object size limit exceeded")
	ErrIntegrity     = errors.New("private object integrity conflict")
	ErrNotFound      = errors.New("private object not found")
	ErrUnavailable   = errors.New("private storage unavailable")
	ErrInvalidObject = errors.New("invalid private object identity")
	digestPattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type Object struct {
	Key       string
	SHA256    string
	SizeBytes int64
}

func (Object) String() string   { return "private object (redacted)" }
func (Object) GoString() string { return "private object (redacted)" }

func (object Object) Validate() error {
	if !digestPattern.MatchString(object.SHA256) || object.SizeBytes < 0 || object.SizeBytes > MaxObjectBytes {
		return ErrInvalidObject
	}
	parts := strings.Split(object.Key, "/")
	if len(parts) == 3 && parts[0] == "sha256" && parts[1] == object.SHA256[:2] && parts[2] == object.SHA256 {
		return nil
	}
	if len(parts) == 3 && parts[0] == "sources" && contract.UUID(parts[1]).Validate() == nil && strings.ToLower(parts[1]) == parts[1] && parts[2] == object.SHA256 {
		return nil
	}
	return ErrInvalidObject
}

func Blob(sha string, size int64) (Object, error) {
	if !digestPattern.MatchString(sha) {
		return Object{}, ErrInvalidObject
	}
	object := Object{Key: "sha256/" + sha[:2] + "/" + sha, SHA256: sha, SizeBytes: size}
	return object, object.Validate()
}

type Store struct{ root *os.Root }

// New requires a dedicated private directory. os.Root confines even raced
// path resolution; Unix final-component O_NOFOLLOW rejects symbolic objects.
// The sandbox never receives this root or its parent as a host mount.
func New(directory string) (*Store, error) {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, ErrUnavailable
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return nil, ErrUnsafePath
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, ErrUnavailable
	}
	store := &Store{root: root}
	for _, name := range []string{"sha256", "sources", "staging", "work"} {
		if err := store.directory(name); err != nil {
			root.Close()
			return nil, err
		}
	}
	return store, nil
}

func (store *Store) Close() error { return store.root.Close() }

func (store *Store) directory(name string) error {
	current := ""
	for _, part := range strings.Split(name, "/") {
		if current != "" {
			current += "/"
		}
		current += part
		err := store.root.Mkdir(current, 0700)
		created := err == nil
		if err != nil && !errors.Is(err, fs.ErrExist) {
			return ErrUnavailable
		}
		info, err := store.root.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
			return ErrUnsafePath
		}
		if created {
			parent := "."
			if index := strings.LastIndexByte(current, '/'); index >= 0 {
				parent = current[:index]
			}
			directory, err := store.root.Open(parent)
			if err != nil {
				return ErrUnavailable
			}
			err = directory.Sync()
			directory.Close()
			if err != nil {
				return ErrUnavailable
			}
		}
	}
	return nil
}

// Put writes a bounded immutable object. Hard-link publication is atomic and
// cannot replace an existing identity. Existing bytes must verify before reuse.
// Workflow code must use Registry staging/reference pins before acceptance;
// a raw Put alone is not a database registration or task acceptance.
func (store *Store) Put(ctx context.Context, reader io.Reader, maxBytes int64) (Object, error) {
	return store.put(ctx, reader, maxBytes, "")
}

func (store *Store) PutSource(ctx context.Context, taskID contract.UUID, source []byte) (Object, error) {
	if taskID.Validate() != nil || !utf8.Valid(source) || len(source) == 0 || strings.TrimSpace(string(source)) == "" {
		return Object{}, ErrInvalidObject
	}
	if len(source) > contract.MaxSourceBytes {
		return Object{}, ErrSizeLimit
	}
	return store.put(ctx, strings.NewReader(string(source)), contract.MaxSourceBytes, strings.ToLower(string(taskID)))
}

func (store *Store) put(ctx context.Context, reader io.Reader, maxBytes int64, taskID string) (Object, error) {
	if reader == nil || maxBytes < 0 || maxBytes > MaxObjectBytes {
		return Object{}, ErrInvalidObject
	}
	if err := ctx.Err(); err != nil {
		return Object{}, err
	}
	id, err := contract.NewUUID()
	if err != nil {
		return Object{}, ErrUnavailable
	}
	temporary := "staging/" + string(id)
	file, err := store.root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|noFollow, 0600)
	if err != nil {
		return Object{}, ErrUnavailable
	}
	defer store.root.Remove(temporary)
	digest := sha256.New()
	size, writeErr := io.Copy(io.MultiWriter(file, digest), io.LimitReader(contextReader{ctx, reader}, maxBytes+1))
	if writeErr != nil {
		file.Close()
		if ctx.Err() != nil {
			return Object{}, ctx.Err()
		}
		return Object{}, ErrUnavailable
	}
	if size > maxBytes {
		file.Close()
		return Object{}, ErrSizeLimit
	}
	if err := file.Chmod(0400); err != nil {
		file.Close()
		return Object{}, ErrUnavailable
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return Object{}, ErrUnavailable
	}
	if err := file.Close(); err != nil {
		return Object{}, ErrUnavailable
	}
	sha := hex.EncodeToString(digest.Sum(nil))
	object := Object{Key: "sha256/" + sha[:2] + "/" + sha, SHA256: sha, SizeBytes: size}
	parent := "sha256/" + sha[:2]
	if taskID != "" {
		object.Key = "sources/" + taskID + "/" + sha
		parent = "sources/" + taskID
	}
	if err := store.directory(parent); err != nil {
		return Object{}, err
	}
	if err := store.root.Link(temporary, object.Key); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return Object{}, ErrUnavailable
		}
		if err := store.Verify(ctx, object); err != nil {
			return Object{}, err
		}
	}
	// File data and containing directory entries both reach durable storage
	// before a task/version transaction is permitted to refer to this object.
	directory, err := store.root.Open(parent)
	if err != nil {
		return Object{}, ErrUnavailable
	}
	err = directory.Sync()
	directory.Close()
	if err != nil {
		return Object{}, ErrUnavailable
	}
	return object, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader contextReader) Read(data []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(data)
}

func (store *Store) open(object Object) (*os.File, error) {
	if err := object.Validate(); err != nil {
		return nil, err
	}
	parts := strings.Split(object.Key, "/")
	for index := 1; index < len(parts); index++ {
		info, err := store.root.Lstat(strings.Join(parts[:index], "/"))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, ErrNotFound
			}
			return nil, ErrUnavailable
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrUnsafePath
		}
	}
	info, err := store.root.Lstat(object.Key)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, ErrUnavailable
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0400 {
		return nil, ErrUnsafePath
	}
	file, err := store.root.OpenFile(object.Key, os.O_RDONLY|noFollow, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() != object.SizeBytes {
		file.Close()
		return nil, ErrIntegrity
	}
	return file, nil
}

func (store *Store) Verify(ctx context.Context, object Object) error {
	file, err := store.open(object)
	if err != nil {
		return err
	}
	defer file.Close()
	digest := sha256.New()
	size, err := io.Copy(digest, io.LimitReader(contextReader{ctx, file}, object.SizeBytes+1))
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrUnavailable
	}
	if size != object.SizeBytes || hex.EncodeToString(digest.Sum(nil)) != object.SHA256 {
		return ErrIntegrity
	}
	return nil
}

// Read verifies the bytes it returns, rather than verifying one file handle
// and reopening another. A changed object is never uploaded to the sandbox.
func (store *Store) Read(ctx context.Context, object Object, maxBytes int64) ([]byte, error) {
	if maxBytes < 0 || maxBytes > MaxObjectBytes || object.SizeBytes > maxBytes {
		return nil, ErrSizeLimit
	}
	file, err := store.open(object)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(contextReader{ctx, file}, object.SizeBytes+1))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrUnavailable
	}
	digest := sha256.Sum256(data)
	if int64(len(data)) != object.SizeBytes || hex.EncodeToString(digest[:]) != object.SHA256 {
		return nil, ErrIntegrity
	}
	return data, nil
}

func (store *Store) ReadBlob(ctx context.Context, sha string, size, maxBytes int64) ([]byte, error) {
	object, err := Blob(sha, size)
	if err != nil {
		return nil, err
	}
	return store.Read(ctx, object, maxBytes)
}

// remove is deliberately private. Only the lifecycle registry may delete an
// object after holding its database lock and proving it has no live reference.
func (store *Store) remove(object Object) error {
	if err := object.Validate(); err != nil {
		return err
	}
	parts := strings.Split(object.Key, "/")
	parent := strings.Join(parts[:len(parts)-1], "/")
	var info os.FileInfo
	for index := 1; index < len(parts); index++ {
		var err error
		info, err = store.root.Lstat(strings.Join(parts[:index], "/"))
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return ErrUnavailable
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
			return ErrUnsafePath
		}
	}
	// Bind deletion to the checked parent directory handle. Following a raced
	// source namespace alias must never unlink another accepted task's copy.
	bound, err := store.root.OpenRoot(parent)
	if err != nil {
		return ErrUnavailable
	}
	defer bound.Close()
	opened, err := bound.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		return ErrUnsafePath
	}
	if err := bound.Remove(parts[len(parts)-1]); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return ErrUnavailable
	}
	directory, err := bound.Open(".")
	if err != nil {
		return ErrUnavailable
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return ErrUnavailable
	}
	return nil
}
