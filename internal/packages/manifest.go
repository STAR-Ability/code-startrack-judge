// SPDX-License-Identifier: Apache-2.0

// Package packages owns deterministic, non-executing problem-package adaptation.
package packages

import (
	"encoding/json"
	"fmt"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
)

const (
	ManifestVersion      = "0.2.0"
	AdapterVersion       = "ojlab-kattis-v0.2.1"
	SourceFormat         = "oj-lab-v1"
	RepositoryURL        = "https://github.com/oj-lab/problem-packages"
	PinnedRevision       = "a4e1d6f106879043eb30af640ba46d0fcbf8053f"
	CheckerRevision      = "6010cbaa37a1612117f49566b2fff8646d53faa2"
	CheckerSourceSHA256  = "2901f589366382433562ec550b2f0c979ad94e3a3a4f737ef013bdd4fa334328"
	ReservedManifestPath = "startrack-manifest.json"
)

type SourceIdentity struct {
	Source        string `json:"source"`
	RepositoryURL string `json:"repositoryUrl"`
	Revision      string `json:"revision"`
	PackagePath   string `json:"packagePath"`
}

type FileRef struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"sizeBytes"`
}

type ExecutionLimits struct {
	TimeLimitMS      int64 `json:"timeLimitMs"`
	WallLimitMS      int64 `json:"wallLimitMs"`
	MemoryLimitBytes int64 `json:"memoryLimitBytes"`
	OutputLimitBytes int64 `json:"outputLimitBytes"`
	ProcessLimit     int   `json:"processLimit"`
}

type ExecutionProfiles struct {
	Compile   ExecutionLimits `json:"compile"`
	Checker   ExecutionLimits `json:"checker"`
	Validator ExecutionLimits `json:"validator"`
}

type CheckerImplementation struct {
	RepositoryURL string `json:"repositoryUrl"`
	Revision      string `json:"revision"`
	SourcePath    string `json:"sourcePath"`
	SourceSHA256  string `json:"sourceSha256"`
}

type CheckerConfig struct {
	Type                   string                `json:"type"`
	Profile                string                `json:"profile"`
	Implementation         CheckerImplementation `json:"implementation"`
	CaseSensitive          bool                  `json:"caseSensitive"`
	SpaceChangeSensitive   bool                  `json:"spaceChangeSensitive"`
	FloatAbsoluteTolerance *string               `json:"floatAbsoluteTolerance"`
	FloatRelativeTolerance *string               `json:"floatRelativeTolerance"`
}

type StatementManifest struct {
	Format           string  `json:"format"`
	Source           FileRef `json:"source"`
	ValidationFormat string  `json:"validationFormat"`
	ValidationView   FileRef `json:"validationView"`
	Shortname        string  `json:"shortname"`
}

type TestCase struct {
	Ordinal         int           `json:"ordinal"`
	Visibility      string        `json:"visibility"`
	Input           FileRef       `json:"input"`
	Answer          FileRef       `json:"answer"`
	Checker         CheckerConfig `json:"checker"`
	ValidationGroup *string       `json:"validationGroup"`
}

type ProgramSource struct {
	File       FileRef `json:"file"`
	LanguageID string  `json:"languageId"`
}

type ReferenceSolution struct {
	File       FileRef `json:"file"`
	LanguageID string  `json:"languageId"`
	Role       string  `json:"role"`
}

type FileMapping struct {
	OriginalPath        *string `json:"originalPath"`
	NormalizedPath      string  `json:"normalizedPath"`
	SourceSHA256        *string `json:"sourceSha256"`
	NormalizedSHA256    string  `json:"normalizedSha256"`
	SourceSizeBytes     *int64  `json:"sourceSizeBytes"`
	NormalizedSizeBytes int64   `json:"normalizedSizeBytes"`
	Role                string  `json:"role"`
}

type Adaptation struct {
	Code            string `json:"code"`
	SourceField     string `json:"sourceField"`
	OriginalValue   any    `json:"originalValue"`
	NormalizedValue any    `json:"normalizedValue"`
	Reason          string `json:"reason"`
}

type Manifest struct {
	ManifestVersion    string              `json:"manifestVersion"`
	AdapterVersion     string              `json:"adapterVersion"`
	SourceFormat       string              `json:"sourceFormat"`
	Source             SourceIdentity      `json:"source"`
	JudgeMode          string              `json:"judgeMode"`
	Title              string              `json:"title"`
	Statement          StatementManifest   `json:"statement"`
	LanguageIDs        []string            `json:"languageIds"`
	Limits             ExecutionLimits     `json:"limits"`
	ExecutionProfiles  ExecutionProfiles   `json:"executionProfiles"`
	Checker            CheckerConfig       `json:"checker"`
	TestCount          int                 `json:"testCount"`
	Tests              []TestCase          `json:"tests"`
	ReferenceSolutions []ReferenceSolution `json:"referenceSolutions"`
	InputValidators    []ProgramSource     `json:"inputValidators"`
	Files              []FileMapping       `json:"files"`
	SourceMetadata     map[string]any      `json:"sourceMetadata"`
	Adaptations        []Adaptation        `json:"adaptations"`
}

func (Manifest) String() string {
	return "private package manifest [source metadata and paths redacted]"
}
func (m Manifest) GoString() string { return m.String() }

// CanonicalJSON emits the exact private manifest bytes used inside its archive.
// Semantics and source/file integrity are validated by ValidateManifest first.
func (m Manifest) CanonicalJSON() ([]byte, error) {
	if err := ValidateManifest(m); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("invalid manifest encoding")
	}
	return canonical.Canonicalize(raw)
}

func DefaultChecker() CheckerConfig {
	return CheckerConfig{Type: "DEFAULT", Profile: "kattis-default-v1.20260907", Implementation: CheckerImplementation{RepositoryURL: "https://github.com/Kattis/problemtools", Revision: CheckerRevision, SourcePath: "support/default_validator/default_validator.cc", SourceSHA256: CheckerSourceSHA256}}
}

func DefaultExecutionProfiles() ExecutionProfiles {
	profile := func(processes int) ExecutionLimits {
		return ExecutionLimits{TimeLimitMS: 60000, WallLimitMS: 120000, MemoryLimitBytes: 1073741824, OutputLimitBytes: 8388608, ProcessLimit: processes}
	}
	return ExecutionProfiles{Compile: profile(128), Checker: profile(32), Validator: profile(64)}
}
