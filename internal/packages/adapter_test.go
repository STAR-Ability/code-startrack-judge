// SPDX-License-Identifier: Apache-2.0

package packages

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func syntheticFiles() []File {
	return []File{
		{Path: "problem.yaml", Data: []byte("name: Synthetic title\ntags: [arrays, strings]\ndifficulty: 7\nlimits: {memory: 256, output: 8}\nunknown: {sourceFileModes: preserved, decimal: 0.125, date: 2026-10-08}\n"), SourceMode: 0o100644},
		{Path: ".timelimit", Data: []byte("1.25\n")},
		{Path: "problem_statement/problem.md", Data: []byte("# Markdown \\input{untrusted}\r\n\t$hi$ & 世界\n")},
		{Path: "data/sample/01.in", Data: []byte("public input\n")}, {Path: "data/sample/01.ans", Data: []byte("public answer\n")},
		{Path: "data/secret/group-z/02.in", Data: []byte("PRIVATE_INPUT\x00")}, {Path: "data/secret/group-z/02.ans", Data: []byte("PRIVATE_ANSWER\x00")},
		{Path: "submissions/accepted/main.cpp", Data: []byte("inert C++ fixture")},
		{Path: "input_validators/validate.py", Data: []byte("inert Python fixture"), SourceMode: 0o100755},
	}
}
func changeFile(files []File, name string, data string) []File {
	files = append([]File(nil), files...)
	for i := range files {
		if files[i].Path == name {
			files[i].Data = []byte(data)
			return files
		}
	}
	return append(files, File{Path: name, Data: []byte(data)})
}
func requireCandidate(t *testing.T) *Artifact {
	t.Helper()
	a, err := Adapt(PinnedSource("problems/synthetic"), syntheticFiles())
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAdapterPreservesSourceAndExactPolicies(t *testing.T) {
	files := syntheticFiles()
	a, err := Adapt(PinnedSource("problems/synthetic"), files)
	if err != nil {
		t.Fatal(err)
	}
	if !a.ManifestReady || a.StatementContent != string(files[2].Data) || a.StatementInput != nil || a.StatementOutput != nil {
		t.Fatal("source statement changed or invented section extraction")
	}
	if a.Manifest.Statement.Source.Path != files[2].Path || !reflect.DeepEqual(a.Samples, []Sample{{Input: "public input\n", Output: "public answer\n"}}) {
		t.Fatal("incorrect public statement/sample projection")
	}
	if a.Manifest.Limits != (ExecutionLimits{TimeLimitMS: 1250, WallLimitMS: 2500, MemoryLimitBytes: 256 << 20, OutputLimitBytes: 8 << 20, ProcessLimit: 32}) {
		t.Fatal("limits are not exact source units")
	}
	if len(a.Manifest.LanguageIDs) != 1 || a.Manifest.LanguageIDs[0] != "cpp17" || a.Manifest.TestCount != 2 || a.Manifest.Tests[0].Visibility != "SAMPLE" || a.Manifest.Tests[1].ValidationGroup == nil || *a.Manifest.Tests[1].ValidationGroup != "group-z" {
		t.Fatal("manifest languages, case order or group labels wrong")
	}
	metadata := a.Manifest.SourceMetadata["originalMetadata"].(map[string]any)
	if metadata["difficulty"] != int64(7) || !reflect.DeepEqual(metadata["tags"], []any{"arrays", "strings"}) || metadata["unknown"].(map[string]any)["sourceFileModes"] != "preserved" {
		t.Fatal("source metadata lost or replaced")
	}
	if err := VerifyFiles(*a.Manifest, a.NormalizedFiles); err != nil {
		t.Fatal(err)
	}
	canonical, err := a.Manifest.CanonicalJSON()
	if err != nil || !bytes.Equal(canonical, a.ManifestJSON) {
		t.Fatal("manifest serialization mismatch")
	}
	parsed, err := ReadArchive(bytes.NewReader(a.NormalizedArchive))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range parsed {
		if f.Path == ReservedManifestPath {
			found = true
			if !bytes.Equal(f.Data, a.ManifestJSON) {
				t.Fatal("reserved manifest bytes differ")
			}
		}
	}
	if !found {
		t.Fatal("normalized manifest missing")
	}
	for _, f := range a.NormalizedFiles {
		if f.Path == "problem_statement/problem.en.tex" && (!strings.HasPrefix(string(f.Data), "\\problemname{Synthetic title}\n") || strings.Contains(string(f.Data), "\\input{")) {
			t.Fatal("TeX source interpreted instead of literal escaped")
		}
	}
	files[2].Data[0] = '!'
	if a.StatementContent[0] != '#' || a.SourceFiles[2].Data[0] != '#' {
		t.Fatal("caller mutation changed source snapshot")
	}
	for _, value := range []any{a, *a.Manifest, a.SourceFiles[6]} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			printed := fmt.Sprintf(format, value)
			if strings.Contains(printed, "PRIVATE") || strings.Contains(printed, "group-z") {
				t.Fatal("private package material escaped formatted log")
			}
		}
	}
}

func TestAdapterDeterministicIndependentInputOrder(t *testing.T) {
	one := requireCandidate(t)
	files := syntheticFiles()
	for i, j := 0, len(files)-1; i < j; i, j = i+1, j-1 {
		files[i], files[j] = files[j], files[i]
	}
	two, err := Adapt(PinnedSource("problems/synthetic"), files)
	if err != nil {
		t.Fatal(err)
	}
	if one.SourceSHA256 != two.SourceSHA256 || one.NormalizedSHA256 != two.NormalizedSHA256 || one.ManifestSHA256 != two.ManifestSHA256 || !bytes.Equal(one.ManifestJSON, two.ManifestJSON) {
		t.Fatal("caller traversal order entered package identity")
	}
	for i := range files {
		if files[i].Path == "problem_statement/problem.md" {
			files[i].Path = "problem_statement/problem.en.md"
		}
	}
	if a, err := Adapt(PinnedSource("problems/synthetic"), files); err != nil || a.Manifest.Statement.Source.Path != "problem_statement/problem.en.md" {
		t.Fatal("English source variant rejected")
	}
}

func TestAdapterRejectsUnsupportedAndPreservesEvidence(t *testing.T) {
	for name, fixture := range map[string]struct {
		files      []File
		diagnostic string
	}{
		"missing-validator":      {syntheticFiles()[:8], "INPUT_VALIDATOR_MISSING"},
		"statement-ambiguous":    {changeFile(syntheticFiles(), "problem_statement/problem.en.md", "second statement"), "STATEMENT_AMBIGUOUS"},
		"statement-language":     {changeFile(syntheticFiles(), "problem_statement/problem.zh.md", "second statement"), "STATEMENT_LANGUAGE_UNSUPPORTED"},
		"unknown-test-directory": {changeFile(syntheticFiles(), "data/unrecognized/01.in", "inert"), "TEST_DIRECTORY_UNSUPPORTED"},
		"custom-checker":         {changeFile(syntheticFiles(), "output_validators/check.cpp", "inert"), "EXECUTION_FORMAT_UNSUPPORTED"},
		"group-semantics":        {changeFile(syntheticFiles(), "data/secret/testdata.yaml", "limits: {memory: 2}"), "GROUP_CONFIGURATION_UNSUPPORTED"},
		"validator-argv":         {changeFile(syntheticFiles(), "problem.yaml", "name: Valid\ninput_validator_flags: hidden\n"), "INPUT_VALIDATOR_ARGUMENTS_UNSUPPORTED"},
		"reserved":               {changeFile(syntheticFiles(), ReservedManifestPath, "inert manifest"), "RESERVED_MANIFEST_PATH"},
		"traversal":              {changeFile(syntheticFiles(), "../escape", "inert"), "SOURCE_FILES_UNSAFE"},
		"answer-missing":         {append(syntheticFiles()[:4], syntheticFiles()[5:]...), "ANSWER_MISSING"},
		"CPU-fraction":           {changeFile(syntheticFiles(), ".timelimit", "0.0001"), "CPU_LIMIT_OUT_OF_PROFILE"},
		"memory-cap":             {changeFile(syntheticFiles(), "problem.yaml", "name: Valid\nlimits: {memory: 2049}\n"), "RESOURCE_LIMIT_INVALID"},
	} {
		t.Run(name, func(t *testing.T) {
			a, err := Adapt(PinnedSource("problems/synthetic"), fixture.files)
			var detail *AdaptError
			if !errors.As(err, &detail) || detail.Diagnostic != fixture.diagnostic {
				t.Fatalf("wrong rejection: %v", err)
			}
			if a.ManifestReady || len(a.SourceFiles) != len(fixture.files) {
				t.Fatal("rejected evidence missing or candidate marked ready")
			}
			if name == "missing-validator" && (a.SourceSHA256 == "" || a.NormalizedSHA256 == "" || len(a.NormalizedArchive) == 0 || ValidateManifest(*a.Manifest) == nil) {
				t.Fatal("missing-validator candidate falsely valid or discarded normalized evidence")
			}
		})
	}
}

func TestMetadataParserRejectsAliasesDuplicatesAndDocuments(t *testing.T) {
	for _, value := range []string{"name: a\nname: b\n", "name: &title a\nother: *title\n", "name: a\n---\nname: b\n", "1: bad\n", "name: !custom bad\n", "[not, mapping]\n", "name: ["} {
		if _, err := decodeMetadata([]byte(value)); err == nil {
			t.Errorf("unsafe YAML accepted: %q", value)
		}
	}
	if _, err := decodeMetadata([]byte("name: " + strings.Repeat("x", maxMetadataBytes))); err == nil {
		t.Fatal("metadata cap ignored")
	}
}

func TestExactDecimalAndCheckerConfiguration(t *testing.T) {
	for value, expected := range map[string]int64{"1": 1000, "1.250": 1250, "1e-3": 1, "60": 60000, "60000e-3": 60000} {
		if ms, ok := exactMilliseconds(value); !ok || ms != expected {
			t.Fatalf("wrong exact milliseconds: %s", value)
		}
	}
	for _, value := range []string{"0", "0.0001", "60.001", "-1", "NaN", "1e9223372036854775804", "1e-9223372036854775811", "1e99999999999999999999999999999999", "1e-99999999999999999999999999999999", strings.Repeat("9", 65)} {
		if _, ok := exactMilliseconds(value); ok {
			t.Errorf("invalid decimal accepted: %s", value)
		}
	}
	for _, value := range []string{"0", "1", "0.0001", "1e-99999999999999999999999999999999", "0e99999999999999999999999999999"} {
		if !validTolerance(value) {
			t.Errorf("valid tolerance rejected: %s", value)
		}
	}
	for _, value := range []string{"1.00001", "1e99999999999999999999999999999999", "NaN", "inf", "-0.1"} {
		if validTolerance(value) {
			t.Errorf("unsupported tolerance accepted: %s", value)
		}
	}
	config, err := parseChecker(map[string]any{"validator_flags": "case_sensitive space_change_sensitive float_tolerance .0"})
	if err != nil {
		t.Fatal(err)
	}
	flags, err := CheckerFlags(config)
	if err != nil || !reflect.DeepEqual(flags, []string{"case_sensitive", "space_change_sensitive", "float_absolute_tolerance", "0.0", "float_relative_tolerance", "0.0"}) {
		t.Fatal("enabled zero tolerance or generated argv wrong")
	}
	disabled := DefaultChecker()
	flags, err = CheckerFlags(disabled)
	if err != nil || len(flags) != 0 || disabled.FloatAbsoluteTolerance != nil || disabled.FloatRelativeTolerance != nil {
		t.Fatal("default checker unexpectedly enables numeric comparison")
	}
	for _, value := range []string{"case_sensitive case_sensitive", "float_tolerance 0.1 float_absolute_tolerance 0.2", "float_absolute_tolerance 0.1 float_tolerance 0.2", "unknown", "float_tolerance", "float_tolerance 1.1"} {
		if _, err := parseChecker(map[string]any{"validator_flags": value}); err == nil {
			t.Errorf("unsupported checker argv accepted: %s", value)
		}
	}
}

func TestLiteralTeXExactByteBounds(t *testing.T) {
	for _, value := range []string{"", "abc", "世界", "\\{}$&#%_^~\n\t", "a\r\nb\rc"} {
		escaped, err := escapedTeX(value, 1000)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := escapedTeX(value, len(escaped)); err != nil {
			t.Fatal("exact byte bound rejected")
		}
		if len(escaped) > 0 {
			if _, err := escapedTeX(value, len(escaped)-1); err == nil {
				t.Fatal("oversized escaped view accepted")
			}
		}
	}
}

func TestManifestAndFileTamperingRejected(t *testing.T) {
	mutations := map[string]func(*Manifest){
		"ordinal": func(m *Manifest) { m.Tests[0].Ordinal = 2 }, "answer-stem": func(m *Manifest) { m.Tests[0].Answer = m.Tests[1].Answer }, "checker": func(m *Manifest) { m.Tests[0].Checker.CaseSensitive = true }, "count": func(m *Manifest) { m.TestCount++ }, "validator": func(m *Manifest) { m.InputValidators = nil }, "reference": func(m *Manifest) { m.ReferenceSolutions[0].Role = "WRONG_ANSWER" }, "source-rewrite": func(m *Manifest) {
			for i := range m.Files {
				if m.Files[i].Role == "INPUT" {
					v := strings.Repeat("0", 64)
					m.Files[i].SourceSHA256 = &v
					break
				}
			}
		}, "inventory-orphan": func(m *Manifest) { m.ReferenceSolutions = nil }, "generated-origin": func(m *Manifest) {
			for i := range m.Files {
				if m.Files[i].Role == "VALIDATION_STATEMENT" {
					v := m.Files[i].NormalizedPath
					m.Files[i].OriginalPath = &v
					break
				}
			}
		}, "group": func(m *Manifest) { m.Tests[1].ValidationGroup = nil },
	}
	for name, mutation := range mutations {
		t.Run(name, func(t *testing.T) {
			a := requireCandidate(t)
			mutation(a.Manifest)
			if ValidateManifest(*a.Manifest) == nil {
				t.Fatal("tampered manifest accepted")
			}
		})
	}
	a := requireCandidate(t)
	files := append([]File(nil), a.NormalizedFiles...)
	files[0].Data = append(bytes.Clone(files[0].Data), 'x')
	if VerifyFiles(*a.Manifest, files) == nil {
		t.Fatal("tampered source bytes accepted")
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(a.ManifestJSON, &object) != nil {
		t.Fatal("invalid manifest JSON")
	}
	if _, exists := object["difficultyScale"]; exists {
		t.Fatal("source difficulty became a fabricated public rating")
	}
}
