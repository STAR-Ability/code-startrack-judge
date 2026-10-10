// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/packages"
)

// These tests only copy and inspect pinned bytes. They never import or execute
// upstream programs, validators, or statement converters.
func pinnedUpstreamCarrier(t *testing.T) string {
	t.Helper()
	source := os.Getenv("STARTRACK_PROBLEMTOOLS_SOURCE_DIR")
	if source == "" {
		t.Skip("pinned problemtools source directory is unset")
	}
	root := t.TempDir()
	for _, name := range []string{"different", "hello"} {
		originalRoot := filepath.Join(source, "examples", name)
		err := filepath.WalkDir(originalRoot, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() && !entry.Type().IsRegular() {
				return errors.New("pinned example contains a nonregular member")
			}
			relative, err := filepath.Rel(originalRoot, path)
			if err != nil {
				return err
			}
			destination := filepath.Join(root, name, relative)
			if entry.IsDir() {
				return os.MkdirAll(destination, 0700)
			}
			raw, err := readPinnedUpstreamBytes(path, 65536)
			if err != nil {
				return err
			}
			return os.WriteFile(destination, raw, 0600)
		})
		if err != nil {
			t.Fatalf("read explicitly configured pinned %s example: %v", name, err)
		}
	}
	return root
}

func readPinnedUpstreamBytes(path string, limit int64) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil || int64(len(raw)) > limit {
		return nil, errors.New("bounded pinned fixture read failed")
	}
	return raw, nil
}

func pinnedUpstreamCorpus(t *testing.T) upstreamExampleCorpus {
	t.Helper()
	corpus, err := loadUpstreamExamples(pinnedUpstreamCarrier(t), readPinnedUpstreamBytes)
	if err != nil {
		t.Fatalf("configured pinned corpus was rejected: %v", err)
	}
	return corpus
}

func copyPinnedUpstreamCorpus(t *testing.T, corpus upstreamExampleCorpus) string {
	t.Helper()
	root := t.TempDir()
	for name, files := range corpus.Files {
		for path, raw := range files {
			destination := filepath.Join(root, name, filepath.FromSlash(path))
			if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(destination, raw, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	return root
}

func TestPinnedUpstreamExamplesExactCorpus(t *testing.T) {
	corpus := pinnedUpstreamCorpus(t)
	if len(corpus.Files) != 2 || len(corpus.Inventory) != 49 || corpus.Bytes != 20927 || corpus.SHA256 != "e228ec6956f76001d3eb6635bf959b1683f36819679672866e10bdc9f65a3594" {
		t.Fatal("original two-example corpus identity differs from the reviewed pin")
	}
	var rebuilt []upstreamExampleRecord
	var total int64
	for name, files := range corpus.Files {
		for path, raw := range files {
			rebuilt = append(rebuilt, upstreamExampleRecord{Path: "examples/" + name + "/" + path, SHA256: canonical.HashBytes(raw), Size: int64(len(raw))})
			total += int64(len(raw))
		}
	}
	sort.Slice(rebuilt, func(i, j int) bool { return rebuilt[i].Path < rebuilt[j].Path })
	raw, err := json.Marshal(rebuilt)
	if err != nil || total != corpus.Bytes || canonical.HashBytes(raw) != corpus.SHA256 || !reflect.DeepEqual(rebuilt, corpus.Inventory) {
		t.Fatal("corpus inventory does not bind every preserved original byte")
	}
	for _, expected := range []struct {
		name, sha string
		count     int
		bytes     int64
	}{
		{"different", "8fb86789076f68fc34f98f7a82a07d6a00fad268502126f05dd537330aed67be", 35, 18675},
		{"hello", "bfb5764363aa1bc8b5f1941b8a0f40bf65fa55398d91fe1a0542085b7238ac38", 14, 2252},
	} {
		sha, count, size := originalPackageIdentity(corpus, expected.name)
		if sha != expected.sha || count != expected.count || size != expected.bytes || len(corpus.Files[expected.name]) != expected.count {
			t.Fatalf("original %s package identity differs from the reviewed pin", expected.name)
		}
		if _, exists := corpus.Files[expected.name][".timelimit"]; exists {
			t.Fatalf("original %s corpus includes a fabricated time limit", expected.name)
		}
	}
}

func TestPinnedUpstreamExamplesRejectChangedTree(t *testing.T) {
	corpus := pinnedUpstreamCorpus(t)
	for _, fixture := range []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"same-size retained source corruption", func(t *testing.T, root string) {
			path := filepath.Join(root, "hello", "input_validators", "validate.py")
			raw := bytes.Clone(corpus.Files["hello"]["input_validators/validate.py"])
			raw[0] ^= 1
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"same-size omitted source corruption", func(t *testing.T, root string) {
			path := filepath.Join(root, "hello", "submissions", "accepted", "hello_alarm.c")
			raw := bytes.Clone(corpus.Files["hello"]["submissions/accepted/hello_alarm.c"])
			raw[0] ^= 1
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"missing empty original input", func(t *testing.T, root string) {
			if err := os.Remove(filepath.Join(root, "hello", "data", "secret", "hello.in")); err != nil {
				t.Fatal(err)
			}
		}},
		{"extra empty member", func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, "hello", "unexpected.txt"), nil, 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"original file replaced by correct-byte symlink", func(t *testing.T, root string) {
			path := filepath.Join(root, "hello", "input_validators", "validate.py")
			target := filepath.Join(t.TempDir(), "validator.py")
			if err := os.WriteFile(target, corpus.Files["hello"]["input_validators/validate.py"], 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		}},
		{"original directory replaced by correct-byte symlink", func(t *testing.T, root string) {
			path := filepath.Join(root, "hello", "input_validators")
			target := filepath.Join(t.TempDir(), "input_validators")
			if err := os.Rename(path, target); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			root := copyPinnedUpstreamCorpus(t, corpus)
			fixture.mutate(t, root)
			if _, err := loadUpstreamExamples(root, readPinnedUpstreamBytes); err == nil {
				t.Fatal("changed original corpus was accepted")
			}
		})
	}
	t.Run("reader failure", func(t *testing.T) {
		root := copyPinnedUpstreamCorpus(t, corpus)
		if _, err := loadUpstreamExamples(root, func(path string, limit int64) ([]byte, error) {
			if strings.HasSuffix(filepath.ToSlash(path), "/hello/data/secret/hello.in") {
				return nil, errors.New("fixture read unavailable")
			}
			return readPinnedUpstreamBytes(path, limit)
		}); err == nil {
			t.Fatal("unavailable original bytes were accepted")
		}
	})
}

func TestPinnedHelloProjectionPreservesOriginalRolesAndDeclaredTransport(t *testing.T) {
	corpus := pinnedUpstreamCorpus(t)
	originals := corpus.Files["hello"]
	blobs := &matrixBlobs{files: map[string][]byte{}}
	m, projection, omitted, err := upstreamHelloManifest(blobs, originals)
	if err != nil || packages.ValidateManifest(m) != nil {
		t.Fatalf("original hello projection is not a sealed frozen-profile fixture: %v", err)
	}
	if m.Limits != (packages.ExecutionLimits{TimeLimitMS: 1000, WallLimitMS: 2000, MemoryLimitBytes: 512 << 20, OutputLimitBytes: 8 << 20, ProcessLimit: 32}) || m.ExecutionProfiles != packages.DefaultExecutionProfiles() || !reflect.DeepEqual(m.Checker, packages.DefaultChecker()) || !reflect.DeepEqual(m.LanguageIDs, []string{"cpp17"}) {
		t.Fatal("projection changed frozen execution or checker semantics")
	}
	if len(m.Files) != 13 || len(projection) != 13 || m.TestCount != 2 || len(m.Tests) != 2 || len(m.InputValidators) != 1 || len(m.ReferenceSolutions) != 4 {
		t.Fatal("projection does not have the declared finite role and file set")
	}
	view := map[string][]byte{}
	for _, file := range m.Files {
		raw, err := blobs.ReadBlob(context.Background(), file.NormalizedSHA256, file.NormalizedSizeBytes, packages.MaxFileBytes)
		if err != nil || canonical.HashBytes(raw) != file.NormalizedSHA256 {
			t.Fatalf("projected member %s is not bound to its bytes", file.NormalizedPath)
		}
		view[file.NormalizedPath] = raw
	}
	for _, path := range []string{
		"data/secret/hello.in", "data/secret/hello.ans", "input_validators/validate.py", "problem_statement/problem.en.tex",
		"submissions/accepted/hello.cc", "submissions/accepted/hello.py", "submissions/run_time_error/memory_limit.cc", "submissions/wrong_answer/hello.cc",
	} {
		raw, exists := view[path]
		if !exists || !bytes.Equal(raw, originals[path]) {
			t.Fatalf("projection changed original executable, statement, or data bytes: %s", path)
		}
	}
	if m.Statement.ValidationView.Path != "problem_statement/problem.en.tex" || m.Statement.ValidationView.SHA256 != canonical.HashBytes(originals["problem_statement/problem.en.tex"]) || m.InputValidators[0].File.Path != "input_validators/validate.py" || m.InputValidators[0].LanguageID != "python3" {
		t.Fatal("original English statement or Python3 validator role changed")
	}
	expectedReferences := map[string]string{
		"submissions/accepted/hello.cc": "cpp17/ACCEPTED", "submissions/accepted/hello.py": "python3/ACCEPTED",
		"submissions/run_time_error/memory_limit.cc": "cpp17/RUNTIME_ERROR", "submissions/wrong_answer/hello.cc": "cpp17/WRONG_ANSWER",
	}
	for _, program := range m.ReferenceSolutions {
		if expectedReferences[program.File.Path] != program.LanguageID+"/"+program.Role {
			t.Fatal("original reference language or expected verdict role changed")
		}
		delete(expectedReferences, program.File.Path)
	}
	if len(expectedReferences) != 0 {
		t.Fatal("original supported reference was omitted")
	}
	for index, visibility := range []string{"SAMPLE", "SECRET"} {
		caseInput, caseAnswer := m.Tests[index].Input.Path, m.Tests[index].Answer.Path
		if m.Tests[index].Visibility != visibility || !bytes.Equal(view[caseInput], originals["data/secret/hello.in"]) || !bytes.Equal(view[caseAnswer], originals["data/secret/hello.ans"]) {
			t.Fatal("synthetic sample or original secret case changed original bytes")
		}
	}
	expectedOmitted := []string{
		"examples/hello/problem_statement/problem.sv.tex", "examples/hello/submissions/accepted/hello.java",
		"examples/hello/submissions/accepted/hello.kt", "examples/hello/submissions/accepted/hello.rs", "examples/hello/submissions/accepted/hello_alarm.c",
	}
	if !reflect.DeepEqual(omitted, expectedOmitted) {
		t.Fatal("projection did not declare every unsupported original omission")
	}
	for _, path := range omitted {
		if _, exists := view[strings.TrimPrefix(path, "examples/hello/")]; exists {
			t.Fatal("unsupported original member entered the execution projection")
		}
	}
	seen := map[string]bool{}
	for _, record := range projection {
		raw, exists := view[record.ViewPath]
		if !exists || seen[record.ViewPath] || record.SHA256 != canonical.HashBytes(raw) || record.Size != int64(len(raw)) {
			t.Fatal("projection record does not bind its exact transport view")
		}
		seen[record.ViewPath] = true
		switch record.ViewPath {
		case ".timelimit", "problem_statement/problem.en.md":
			if record.Purpose != "AUTHORED_TRANSPORT_METADATA" || record.OriginalPath != "" {
				t.Fatal("authored transport metadata was attributed to the original corpus")
			}
		case "data/sample/hello.in", "data/sample/hello.ans":
			original := "examples/hello/" + strings.Replace(record.ViewPath, "data/sample/", "data/secret/", 1)
			if record.Purpose != "BYTE_IDENTICAL_SAMPLE_DUPLICATE" || record.OriginalPath != original {
				t.Fatal("synthetic sample duplication is not explicitly declared")
			}
		case "problem.yaml":
			if record.Purpose != "NORMALIZED_TRANSPORT_CONFIG" || record.OriginalPath != "examples/hello/problem.yaml" {
				t.Fatal("normalized configuration was represented as unchanged original bytes")
			}
			encoded, err := json.Marshal(record)
			var fields map[string]any
			if err != nil || json.Unmarshal(encoded, &fields) != nil || fields["originalSha256"] != canonical.HashBytes(originals["problem.yaml"]) {
				t.Fatal("normalized configuration lost original source identity")
			}
		case "problem_statement/problem.en.tex":
			if record.Purpose != "ORIGINAL_TEX_BYTES" || record.OriginalPath != "examples/hello/"+record.ViewPath {
				t.Fatal("original English TeX copy is not explicitly declared")
			}
		default:
			if record.Purpose != "ORIGINAL_BYTES" || record.OriginalPath != "examples/hello/"+record.ViewPath {
				t.Fatal("preserved original role has an incorrect provenance record")
			}
		}
	}
	if !bytes.Equal(view[".timelimit"], []byte("1.000\n")) || bytes.Equal(view["problem.yaml"], originals["problem.yaml"]) {
		t.Fatal("declared authored timing or normalized configuration is missing")
	}
	if _, err := m.CanonicalJSON(); err != nil {
		t.Fatal("qualification transport cannot be sealed")
	}
}
