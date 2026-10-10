// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/packages"
	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
)

const upstreamExamplesRoot = "/opt/startrack/qualification/upstream_examples"
const upstreamExamplesRevision = "6010cbaa37a1612117f49566b2fff8646d53faa2"
const upstreamExamplesCorpusSHA256 = "e228ec6956f76001d3eb6635bf959b1683f36819679672866e10bdc9f65a3594"
const upstreamHelloSHA256 = "bfb5764363aa1bc8b5f1941b8a0f40bf65fa55398d91fe1a0542085b7238ac38"
const upstreamDifferentSHA256 = "8fb86789076f68fc34f98f7a82a07d6a00fad268502126f05dd537330aed67be"

type upstreamExampleRecord struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"sizeBytes"`
}
type upstreamExampleCorpus struct {
	Files     map[string]map[string][]byte
	Inventory []upstreamExampleRecord
	SHA256    string
	Bytes     int64
}
type upstreamProjectionRecord struct {
	OriginalPath   string `json:"originalPath,omitempty"`
	OriginalSHA256 string `json:"originalSha256,omitempty"`
	ViewPath       string `json:"viewPath"`
	SHA256         string `json:"sha256"`
	Size           int64  `json:"sizeBytes"`
	Purpose        string `json:"purpose"`
}
type upstreamExcludedExample struct {
	Path    string   `json:"path"`
	Reasons []string `json:"reasons"`
	Carried bool     `json:"carried"`
}
type upstreamPackageEvidence struct {
	Name                 string                          `json:"name"`
	OriginalCorpusSHA256 string                          `json:"originalCorpusSha256"`
	OriginalFiles        int                             `json:"originalFiles"`
	OriginalBytes        int64                           `json:"originalBytes"`
	Disposition          string                          `json:"disposition"`
	Passed               bool                            `json:"passed"`
	NativeExecuted       bool                            `json:"nativeExecuted"`
	UnsupportedFeatures  []string                        `json:"unsupportedFeatures,omitempty"`
	OmittedOriginalFiles []string                        `json:"omittedOriginalFiles,omitempty"`
	Projection           []upstreamProjectionRecord      `json:"projection,omitempty"`
	ProjectionSHA256     string                          `json:"projectionSha256,omitempty"`
	ManifestSHA256       string                          `json:"manifestSha256,omitempty"`
	ExecutionLimits      *packages.ExecutionLimits       `json:"executionLimits,omitempty"`
	Mature               *matureEvidence                 `json:"mature,omitempty"`
	ExactPrograms        *judgeruntime.ValidationOutcome `json:"exactPrograms,omitempty"`
	FailureCode          string                          `json:"failureCode,omitempty"`
}
type upstreamPackagesEvidence struct {
	SourceRepository        string                    `json:"sourceRepository"`
	SourceRevision          string                    `json:"sourceRevision"`
	SourceNamespace         string                    `json:"sourceNamespace"`
	Scope                   string                    `json:"scope"`
	ManifestNamespace       string                    `json:"manifestNamespace"`
	FullOriginalSuitePassed bool                      `json:"fullOriginalSuitePassed"`
	CorpusSHA256            string                    `json:"corpusSha256"`
	CorpusFiles             int                       `json:"corpusFiles"`
	CorpusBytes             int64                     `json:"corpusBytes"`
	Packages                []upstreamPackageEvidence `json:"packages"`
	UncarriedExamples       []upstreamExcludedExample `json:"uncarriedExamples"`
	Passed                  bool                      `json:"passed"`
}

// This reader is used only with the fixed, root-owned image carrier. Tests use
// a bounded inert reader; neither the command nor the service accepts a path.
func readUpstreamQualificationFile(path string, limit int64) ([]byte, error) {
	invalid := func() ([]byte, error) { return nil, errors.New("upstream qualification carrier invalid") }
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, e := os.Lstat(parent)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return invalid()
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 {
			return invalid()
		}
		if parent == string(filepath.Separator) {
			break
		}
	}
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return invalid()
	}
	f := os.NewFile(uintptr(fd), "fixed-upstream-qualification-file")
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > limit {
		return invalid()
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 {
		return invalid()
	}
	raw, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(raw)) != info.Size() || int64(len(raw)) > limit {
		return invalid()
	}
	return raw, nil
}

// Verify the entire original two-package corpus before selecting any native
// role. The corpus is data only until this fixed command dispatches via Adapter.
func loadUpstreamExamples(root string, read func(string, int64) ([]byte, error)) (out upstreamExampleCorpus, err error) {
	invalid := func() (upstreamExampleCorpus, error) {
		return upstreamExampleCorpus{}, errors.New("pinned upstream example corpus invalid")
	}
	entries, e := os.ReadDir(root)
	if e != nil || len(entries) != 2 || read == nil {
		return invalid()
	}
	out.Files = map[string]map[string][]byte{}
	for _, entry := range entries {
		name := entry.Name()
		if (name != "hello" && name != "different") || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return invalid()
		}
		out.Files[name] = map[string][]byte{}
		packageRoot := filepath.Join(root, name)
		e = filepath.WalkDir(packageRoot, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil || entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() && !entry.Type().IsRegular() {
				return errors.New("upstream example file type invalid")
			}
			if entry.IsDir() {
				return nil
			}
			relative, e := filepath.Rel(packageRoot, path)
			if e != nil {
				return e
			}
			relative = filepath.ToSlash(relative)
			if packages.ValidateSourcePath(relative) != nil {
				return errors.New("upstream example path invalid")
			}
			raw, e := read(path, 65536)
			if e != nil || len(raw) > 65536 || len(out.Inventory) >= 49 {
				return errors.New("upstream example bytes invalid")
			}
			out.Files[name][relative] = bytes.Clone(raw)
			out.Inventory = append(out.Inventory, upstreamExampleRecord{"examples/" + name + "/" + relative, canonical.HashBytes(raw), int64(len(raw))})
			out.Bytes += int64(len(raw))
			return nil
		})
		if e != nil {
			return invalid()
		}
	}
	sort.Slice(out.Inventory, func(i, j int) bool { return out.Inventory[i].Path < out.Inventory[j].Path })
	raw, e := json.Marshal(out.Inventory)
	if e != nil || len(out.Inventory) != 49 || out.Bytes != 20927 || canonical.HashBytes(raw) != upstreamExamplesCorpusSHA256 {
		return invalid()
	}
	out.SHA256 = canonical.HashBytes(raw)
	return out, nil
}

func originalPackageIdentity(corpus upstreamExampleCorpus, name string) (string, int, int64) {
	records := []upstreamExampleRecord{}
	var total int64
	for _, record := range corpus.Inventory {
		if strings.HasPrefix(record.Path, "examples/"+name+"/") {
			records = append(records, record)
			total += record.Size
		}
	}
	raw, _ := json.Marshal(records)
	return canonical.HashBytes(raw), len(records), total
}

func upstreamHelloManifest(blobs *matrixBlobs, originals map[string][]byte) (packages.Manifest, []upstreamProjectionRecord, []string, error) {
	// The manifest protocol has a fixed business namespace and requires Markdown,
	// a sample, and explicit timing. These declared transport additions never
	// become a problem/artifact/publication and are not Kattis package provenance.
	metadata := []packages.File{
		{Path: ".timelimit", Data: []byte("1.000\n")},
		{Path: "problem_statement/problem.en.md", Data: []byte("Qualification transport for the original pinned Hello World! example. The original English TeX is validated unchanged.\n")},
	}
	selected := []string{"problem.yaml", "data/secret/hello.in", "data/secret/hello.ans", "input_validators/validate.py",
		"submissions/accepted/hello.cc", "submissions/accepted/hello.py", "submissions/wrong_answer/hello.cc", "submissions/run_time_error/memory_limit.cc"}
	files := append([]packages.File(nil), metadata...)
	projection := []upstreamProjectionRecord{}
	used := map[string]bool{"problem_statement/problem.en.tex": true}
	addRecord := func(original, view string, raw []byte, purpose string) {
		projection = append(projection, upstreamProjectionRecord{OriginalPath: original, ViewPath: view, SHA256: canonical.HashBytes(raw), Size: int64(len(raw)), Purpose: purpose})
	}
	for _, file := range metadata {
		addRecord("", file.Path, file.Data, "AUTHORED_TRANSPORT_METADATA")
	}
	for _, path := range selected {
		raw, exists := originals[path]
		if !exists {
			return packages.Manifest{}, nil, nil, errors.New("original hello role missing")
		}
		used[path] = true
		files = append(files, packages.File{Path: path, Data: bytes.Clone(raw)})
		addRecord("examples/hello/"+path, path, raw, "ORIGINAL_BYTES")
	}
	for _, suffix := range []string{"in", "ans"} {
		original, view := "data/secret/hello."+suffix, "data/sample/hello."+suffix
		raw := originals[original]
		files = append(files, packages.File{Path: view, Data: bytes.Clone(raw)})
		addRecord("examples/hello/"+original, view, raw, "BYTE_IDENTICAL_SAMPLE_DUPLICATE")
	}
	artifact, e := packages.Adapt(packages.PinnedSource("problems/synthetic-upstream-hello-qualification"), files)
	if e != nil || artifact == nil || !artifact.ManifestReady || artifact.Manifest == nil {
		return packages.Manifest{}, nil, nil, errors.New("upstream hello transport projection invalid")
	}
	tex, exists := originals["problem_statement/problem.en.tex"]
	if !exists {
		return packages.Manifest{}, nil, nil, errors.New("original hello statement missing")
	}
	manifest := *artifact.Manifest
	ref := blobs.add(tex)
	manifest.Statement.ValidationView.SHA256, manifest.Statement.ValidationView.SizeBytes = ref.SHA256, ref.SizeBytes
	for i := range manifest.Files {
		if manifest.Files[i].NormalizedPath == manifest.Statement.ValidationView.Path {
			manifest.Files[i].NormalizedSHA256, manifest.Files[i].NormalizedSizeBytes = ref.SHA256, ref.SizeBytes
		}
	}
	for i := range artifact.NormalizedFiles {
		file := &artifact.NormalizedFiles[i]
		if file.Path == manifest.Statement.ValidationView.Path {
			file.Data = bytes.Clone(tex)
		}
		blobs.add(file.Data)
		if file.Path == "problem.yaml" {
			for j := range projection {
				if projection[j].ViewPath == file.Path {
					projection[j].OriginalSHA256 = canonical.HashBytes(originals[file.Path])
					projection[j].SHA256, projection[j].Size = canonical.HashBytes(file.Data), int64(len(file.Data))
					projection[j].Purpose = "NORMALIZED_TRANSPORT_CONFIG"
				}
			}
		}
	}
	if packages.VerifyFiles(manifest, artifact.NormalizedFiles) != nil {
		return packages.Manifest{}, nil, nil, errors.New("upstream hello projection seal invalid")
	}
	addRecord("examples/hello/problem_statement/problem.en.tex", manifest.Statement.ValidationView.Path, tex, "ORIGINAL_TEX_BYTES")
	omitted := []string{}
	for path := range originals {
		if !used[path] {
			omitted = append(omitted, "examples/hello/"+path)
		}
	}
	sort.Strings(omitted)
	sort.Slice(projection, func(i, j int) bool { return projection[i].ViewPath < projection[j].ViewPath })
	return manifest, projection, omitted, nil
}

func runUpstreamPackagesMatrix(ctx context.Context, adapter *judgeruntime.Adapter, blobs *matrixBlobs, report *matrixReport) error {
	result := &report.UpstreamPackages
	*result = upstreamPackagesEvidence{SourceRepository: "https://github.com/Kattis/problemtools", SourceRevision: upstreamExamplesRevision,
		SourceNamespace: "KATTIS_PROBLEMTOOLS_EXAMPLES", Scope: "ORIGINAL_BYTES_SUPPORTED_PROFILE_PROJECTION",
		ManifestNamespace: "SYNTHETIC_TRANSPORT_ONLY_NO_PROBLEM_OR_IMPORT_PROVENANCE", FullOriginalSuitePassed: false,
		Packages: []upstreamPackageEvidence{}, UncarriedExamples: []upstreamExcludedExample{
			{Path: "examples/guess", Reasons: []string{"INTERACTIVE_UNSUPPORTED"}, Carried: false},
			{Path: "examples/oddecho", Reasons: []string{"SCORING_UNSUPPORTED", "SYMLINK_TESTCASE_REUSE_UNSUPPORTED"}, Carried: false},
		}}
	corpus, e := loadUpstreamExamples(upstreamExamplesRoot, readUpstreamQualificationFile)
	if e != nil {
		return e
	}
	result.CorpusSHA256, result.CorpusFiles, result.CorpusBytes = corpus.SHA256, len(corpus.Inventory), corpus.Bytes
	digest, count, total := originalPackageIdentity(corpus, "different")
	// This is an expected qualification exclusion, not an observed ImportItem
	// response. The original package cannot be admitted to the DEFAULT profile.
	different := upstreamPackageEvidence{Name: "different", OriginalCorpusSHA256: digest, OriginalFiles: count, OriginalBytes: total,
		Disposition: "EXPECTED_PACKAGE_UNSUPPORTED", NativeExecuted: false,
		UnsupportedFeatures: []string{"CUSTOM_OUTPUT_VALIDATOR", "CHECKTESTDATA_ENGINE", "MULTIFILE_CHECKER", "UNSUPPORTED_REFERENCE_LANGUAGES"}}
	different.Passed = digest == upstreamDifferentSHA256 && count == 35 && total == 18675 &&
		bytes.Contains(corpus.Files["different"]["problem.yaml"], []byte("validation: custom\n")) &&
		len(corpus.Files["different"]["input_validators/different.ctd"]) > 0 &&
		len(corpus.Files["different"]["output_validators/different_validator/validate.cc"]) > 0 &&
		len(corpus.Files["different"]["output_validators/different_validator/validate.h"]) > 0
	result.Packages = append(result.Packages, different)
	if !different.Passed {
		return errors.New("original unsupported package exclusion mismatch")
	}
	digest, count, total = originalPackageIdentity(corpus, "hello")
	hello := upstreamPackageEvidence{Name: "hello", OriginalCorpusSHA256: digest, OriginalFiles: count, OriginalBytes: total,
		Disposition: "SUPPORTED_PROFILE_PROJECTION"}
	result.Packages = append(result.Packages, hello)
	helloResult := &result.Packages[1]
	if digest != upstreamHelloSHA256 || count != 14 || total != 2252 {
		return errors.New("original hello corpus mismatch")
	}
	manifest, projection, omitted, e := upstreamHelloManifest(blobs, corpus.Files["hello"])
	if e != nil {
		return e
	}
	helloResult.Projection, helloResult.OmittedOriginalFiles, helloResult.ExecutionLimits = projection, omitted, &manifest.Limits
	projectionJSON, _ := json.Marshal(projection)
	helloResult.ProjectionSHA256 = canonical.HashBytes(projectionJSON)
	manifestJSON, e := manifest.CanonicalJSON()
	if e != nil {
		return e
	}
	helloResult.ManifestSHA256 = canonical.HashBytes(manifestJSON)
	if adapter.Qualify(ctx) != nil {
		return errors.New("upstream package matrix refresh failed")
	}
	input := judgeruntime.MatureInput{JobID: matrixUUID(1100), ItemID: matrixUUID(1101), FencingToken: matrixUUID(1102), Identity: adapter.Identity(), Manifest: manifest}
	out, runErr := adapter.RunMature(ctx, input)
	log, logErr := retainMatrixLog("UPSTREAM_HELLO", out.RawLog)
	mature := &matureEvidence{Name: "UPSTREAM_HELLO", Completed: out.Completed, Parts: out.Parts, Errors: out.Errors, Warnings: out.Warnings, PrivateLog: log}
	helloResult.Mature = mature
	mature.Passed = runErr == nil && logErr == nil && out.Completed && len(out.Parts) == 5 && out.Errors == 0
	for _, part := range out.Parts {
		mature.Passed = mature.Passed && part.Passed && !part.NotRun && part.Errors == 0
	}
	if !mature.Passed {
		helloResult.FailureCode = "UPSTREAM_MATURE_PROFILE_FAILED"
		return errors.New("original hello mature profile mismatch")
	}
	helloResult.NativeExecuted = true
	exact, e := judgeruntime.ValidationFromManifest(matrixUUID(1103), matrixUUID(1104), matrixUUID(1105), adapter.Identity(), manifest)
	if e != nil {
		return e
	}
	programs, e := adapter.ValidatePrograms(ctx, exact)
	helloResult.ExactPrograms = &programs
	helloResult.Passed = e == nil && programs.ValidatorsPassed && programs.ReferencesPassed && programs.ValidatorCaseCount == 2 && programs.ReferenceCaseCount == 4 && len(programs.ValidatorCases) == 2 && len(programs.ReferenceCases) == 4
	for _, cases := range [][]judgeruntime.ProgramCaseEvidence{programs.ValidatorCases, programs.ReferenceCases} {
		for _, evidence := range cases {
			helloResult.Passed = helloResult.Passed && evidence.Passed
		}
	}
	if !helloResult.Passed {
		helloResult.FailureCode = "UPSTREAM_EXACT_PROGRAM_PROFILE_FAILED"
		return errors.New("original hello exact program profile mismatch")
	}
	result.Passed = true
	return nil
}
