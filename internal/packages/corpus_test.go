// SPDX-License-Identifier: Apache-2.0

package packages

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Only trusted Git object reads run on the host. Imported source is never
// compiled or executed. The cache is owner-fetched and ignored by Git.
func pinnedCorpusFiles(t *testing.T, directory string) map[string][]File {
	t.Helper()
	git := func(args ...string) []byte {
		command := exec.Command("git", append([]string{"--git-dir=" + directory}, args...)...)
		command.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_NO_REPLACE_OBJECTS=1", "GIT_TERMINAL_PROMPT=0")
		raw, err := command.Output()
		if err != nil {
			t.Fatal("cannot read reviewed pinned Git object:", err)
		}
		return raw
	}
	if string(bytes.TrimSpace(git("rev-parse", "--verify", PinnedRevision+"^{commit}"))) != PinnedRevision {
		t.Fatal("cache does not contain exact reviewed commit")
	}
	files := map[string][]File{}
	for _, entry := range bytes.Split(git("ls-tree", "-r", "-z", PinnedRevision, "--", "problems"), []byte{0}) {
		if len(entry) == 0 {
			continue
		}
		parts := bytes.SplitN(entry, []byte{'\t'}, 2)
		if len(parts) != 2 {
			t.Fatal("invalid Git tree entry")
		}
		fields := strings.Fields(string(parts[0]))
		if len(fields) != 3 || fields[1] != "blob" {
			t.Fatal("unsupported Git object type")
		}
		path := strings.SplitN(string(parts[1]), "/", 3)
		if len(path) != 3 {
			continue
		}
		mode, err := strconv.ParseUint(fields[0], 8, 32)
		if err != nil {
			t.Fatal(err)
		}
		identity := path[0] + "/" + path[1]
		files[identity] = append(files[identity], File{Path: path[2], Data: git("cat-file", "blob", fields[2]), SourceMode: uint32(mode)})
	}
	return files
}

type corpusRecord struct {
	PackagePath      string `json:"packagePath"`
	SourceSHA256     string `json:"sourceSha256"`
	NormalizedSHA256 string `json:"normalizedSha256"`
	ManifestSHA256   string `json:"manifestSha256"`
	StatementPath    string `json:"statementPath"`
	TestCount        int    `json:"testCount"`
	ManifestReady    bool   `json:"manifestReady"`
	Rejection        string `json:"rejection"`
}
type corpusGolden struct {
	Repository string         `json:"repositoryUrl"`
	Revision   string         `json:"revision"`
	Adapter    string         `json:"adapterVersion"`
	Scope      string         `json:"scope"`
	Packages   []corpusRecord `json:"packages"`
}

func TestPinnedCorpusGolden(t *testing.T) {
	directory := os.Getenv("STARTRACK_PACKAGE_GIT_DIR")
	if directory == "" {
		t.Skip("set STARTRACK_PACKAGE_GIT_DIR to the owner-fetched pinned bare Git cache; no network fetch or source execution")
	}
	packages := pinnedCorpusFiles(t, directory)
	paths := make([]string, 0, len(packages))
	for path := range packages {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	if len(paths) != 14 {
		t.Fatal("pinned corpus has unexpected package count")
	}
	record := corpusGolden{Repository: RepositoryURL, Revision: PinnedRevision, Adapter: AdapterVersion, Scope: "Host-only byte adaptation of reviewed Git objects; structural readiness is not license approval, technical validation, or Linux qualification.", Packages: []corpusRecord{}}
	for _, path := range paths {
		a, err := Adapt(PinnedSource(path), packages[path])
		var rejection string
		if err != nil {
			var detail *AdaptError
			if !errors.As(err, &detail) || detail.Diagnostic != "INPUT_VALIDATOR_MISSING" {
				t.Fatal("unexpected corpus failure:", path, err)
			}
			rejection = detail.Diagnostic
		}
		if a.Manifest == nil || len(a.SourceArchive) == 0 || len(a.NormalizedArchive) == 0 || len(a.ManifestJSON) == 0 {
			t.Fatal("corpus original/derived evidence missing:", path)
		}
		if path == "problems/hello-world" {
			if !a.ManifestReady || err != nil {
				t.Fatal("hello-world not structurally ready")
			}
			if err := VerifyFiles(*a.Manifest, a.NormalizedFiles); err != nil {
				t.Fatal(err)
			}
		} else {
			if a.ManifestReady || err == nil {
				t.Fatal("missing validator falsely passed")
			}
		}
		record.Packages = append(record.Packages, corpusRecord{PackagePath: path, SourceSHA256: a.SourceSHA256, NormalizedSHA256: a.NormalizedSHA256, ManifestSHA256: a.ManifestSHA256, StatementPath: a.Manifest.Statement.Source.Path, TestCount: a.Manifest.TestCount, ManifestReady: a.ManifestReady, Rejection: rejection})
	}
	actual, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	actual = append(actual, '\n')
	if output := os.Getenv("STARTRACK_CORPUS_RECORD"); output != "" {
		if err := os.MkdirAll(filepath.Dir(output), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(output, actual, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Log("wrote requested private checksum-only record")
		return
	}
	expected, err := os.ReadFile("testdata/pinned-corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatal("pinned adaptation identity changed; independently review byte/provenance changes before updating goldens")
	}
}
