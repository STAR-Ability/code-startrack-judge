// SPDX-License-Identifier: Apache-2.0

package packages

import (
	"encoding/json"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
)

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func manifestInvalid() error {
	return rejected("PACKAGE_INVALID", "INVALID_STRUCTURE", "MANIFEST_INVALID")
}
func validateChecker(checker CheckerConfig) error {
	defaultValue := DefaultChecker()
	if checker.Type != defaultValue.Type || checker.Profile != defaultValue.Profile || checker.Implementation != defaultValue.Implementation {
		return manifestInvalid()
	}
	for _, tolerance := range []*string{checker.FloatAbsoluteTolerance, checker.FloatRelativeTolerance} {
		if tolerance != nil && !validTolerance(*tolerance) {
			return manifestInvalid()
		}
	}
	return nil
}
func equalChecker(a, b CheckerConfig) bool {
	rawA, errA := json.Marshal(a)
	rawB, errB := json.Marshal(b)
	return errA == nil && errB == nil && string(rawA) == string(rawB)
}

// ValidateManifest enforces typed and relational invariants before immutable
// registration or runtime admission; a rejected candidate may lack validators.
func ValidateManifest(m Manifest) error {
	if validateIdentity(m.Source) != nil || m.ManifestVersion != ManifestVersion || m.AdapterVersion != AdapterVersion || m.SourceFormat != SourceFormat || m.JudgeMode != "BATCH_PASS_FAIL" || strings.TrimSpace(m.Title) == "" || !utf8.ValidString(m.Title) || utf8.RuneCountInString(m.Title) > 256 || len(m.LanguageIDs) != 1 || m.LanguageIDs[0] != "cpp17" {
		return manifestInvalid()
	}
	if m.Limits.TimeLimitMS <= 0 || m.Limits.TimeLimitMS > 60000 || m.Limits.WallLimitMS != m.Limits.TimeLimitMS*2 || m.Limits.MemoryLimitBytes <= 0 || m.Limits.MemoryLimitBytes > 2147483648 || m.Limits.OutputLimitBytes <= 0 || m.Limits.OutputLimitBytes > 67108864 || m.Limits.ProcessLimit != 32 || m.ExecutionProfiles != DefaultExecutionProfiles() || validateChecker(m.Checker) != nil {
		return manifestInvalid()
	}
	if m.SourceMetadata == nil || len(m.Adaptations) == 0 || len(m.Files) == 0 || len(m.Files) > MaxFiles || len(m.Tests) == 0 || len(m.Tests) > MaxTests || len(m.Tests) != m.TestCount || len(m.InputValidators) == 0 || len(m.InputValidators) > 128 || len(m.ReferenceSolutions) == 0 || len(m.ReferenceSolutions) > 4096 {
		return manifestInvalid()
	}
	inventory := make(map[string]FileMapping, len(m.Files))
	var prior string
	var inventoryBytes int64
	roles := map[string]bool{"STATEMENT": true, "VALIDATION_STATEMENT": true, "INPUT": true, "ANSWER": true, "REFERENCE": true, "INPUT_VALIDATOR": true, "LICENSE": true, "SOURCE_METADATA": true, "OTHER": true}
	var placeholders []File
	for _, file := range m.Files {
		if ValidateSourcePath(file.NormalizedPath) != nil || file.NormalizedPath <= prior && prior != "" || !digestPattern.MatchString(file.NormalizedSHA256) || file.NormalizedSizeBytes < 0 || file.NormalizedSizeBytes > MaxFileBytes || !roles[file.Role] {
			return manifestInvalid()
		}
		prior = file.NormalizedPath
		if file.OriginalPath == nil {
			if file.SourceSHA256 != nil || file.SourceSizeBytes != nil || file.NormalizedPath != "problem_statement/problem.en.tex" || file.Role != "VALIDATION_STATEMENT" {
				return manifestInvalid()
			}
		} else {
			if ValidateSourcePath(*file.OriginalPath) != nil || *file.OriginalPath != file.NormalizedPath || file.SourceSHA256 == nil || !digestPattern.MatchString(*file.SourceSHA256) || file.SourceSizeBytes == nil || *file.SourceSizeBytes < 0 || *file.SourceSizeBytes > MaxFileBytes || file.Role == "VALIDATION_STATEMENT" {
				return manifestInvalid()
			}
			if file.NormalizedPath != "problem.yaml" && (*file.SourceSHA256 != file.NormalizedSHA256 || *file.SourceSizeBytes != file.NormalizedSizeBytes) {
				return manifestInvalid()
			}
		}
		inventoryBytes += file.NormalizedSizeBytes
		if inventoryBytes > MaxTotalBytes {
			return manifestInvalid()
		}
		inventory[file.NormalizedPath] = file
		placeholders = append(placeholders, File{Path: file.NormalizedPath})
	}
	if _, err := validateFiles(placeholders, false); err != nil {
		return manifestInvalid()
	}
	checkRef := func(ref FileRef, role string) bool {
		mapping, exists := inventory[ref.Path]
		return exists && mapping.Role == role && mapping.NormalizedSHA256 == ref.SHA256 && mapping.NormalizedSizeBytes == ref.SizeBytes
	}
	if m.Statement.Format != "MARKDOWN" || m.Statement.Source.Path != "problem_statement/problem.en.md" && m.Statement.Source.Path != "problem_statement/problem.md" || m.Statement.ValidationFormat != "TEX" || m.Statement.ValidationView.Path != "problem_statement/problem.en.tex" || m.Statement.Shortname != "p"+canonical.HashBytes([]byte(m.Source.PackagePath))[:32] || !checkRef(m.Statement.Source, "STATEMENT") || !checkRef(m.Statement.ValidationView, "VALIDATION_STATEMENT") {
		return manifestInvalid()
	}
	seenInputs := map[string]bool{}
	seenAnswers := map[string]bool{}
	sample, secret := 0, 0
	previousInput := ""
	previousVisibility := "SAMPLE"
	for i, test := range m.Tests {
		if test.Ordinal != i+1 || test.Visibility != "SAMPLE" && test.Visibility != "SECRET" || !checkRef(test.Input, "INPUT") || !checkRef(test.Answer, "ANSWER") || strings.TrimSuffix(test.Input.Path, ".in")+".ans" != test.Answer.Path || !strings.HasSuffix(test.Input.Path, ".in") || !strings.HasPrefix(test.Input.Path, "data/"+strings.ToLower(test.Visibility)+"/") || !equalChecker(test.Checker, m.Checker) || seenInputs[test.Input.Path] || seenAnswers[test.Answer.Path] {
			return manifestInvalid()
		}
		group := strings.TrimPrefix(test.Input.Path, "data/"+strings.ToLower(test.Visibility)+"/")
		if offset := strings.LastIndexByte(group, '/'); offset >= 0 {
			group = group[:offset]
		} else {
			group = ""
		}
		if (test.ValidationGroup == nil) != (group == "") || test.ValidationGroup != nil && (*test.ValidationGroup != group || strings.TrimSpace(*test.ValidationGroup) == "" || utf8.RuneCountInString(*test.ValidationGroup) > 128) {
			return manifestInvalid()
		}
		if previousVisibility == "SECRET" && test.Visibility == "SAMPLE" {
			return manifestInvalid()
		}
		if previousVisibility == test.Visibility && previousInput != "" && test.Input.Path <= previousInput {
			return manifestInvalid()
		}
		previousVisibility = test.Visibility
		previousInput = test.Input.Path
		seenInputs[test.Input.Path] = true
		seenAnswers[test.Answer.Path] = true
		if test.Visibility == "SAMPLE" {
			sample++
		} else {
			secret++
		}
	}
	if sample == 0 || secret == 0 {
		return manifestInvalid()
	}
	accepted := false
	prior = ""
	seenReferences := map[string]bool{}
	for _, program := range m.ReferenceSolutions {
		if program.File.Path <= prior && prior != "" || !checkRef(program.File, "REFERENCE") || program.File.SizeBytes == 0 || program.LanguageID != "cpp17" && program.LanguageID != "python3" || program.Role != "ACCEPTED" && program.Role != "WRONG_ANSWER" && program.Role != "TIME_LIMIT" && program.Role != "RUNTIME_ERROR" {
			return manifestInvalid()
		}
		prior = program.File.Path
		seenReferences[program.File.Path] = true
		if program.Role == "ACCEPTED" {
			accepted = true
		}
	}
	if !accepted {
		return manifestInvalid()
	}
	prior = ""
	seenValidators := map[string]bool{}
	for _, program := range m.InputValidators {
		if program.File.Path <= prior && prior != "" || !checkRef(program.File, "INPUT_VALIDATOR") || program.File.SizeBytes == 0 || program.LanguageID != "cpp17" && program.LanguageID != "python3" {
			return manifestInvalid()
		}
		prior = program.File.Path
		seenValidators[program.File.Path] = true
	}
	for _, file := range m.Files {
		if file.Role == "INPUT" && !seenInputs[file.NormalizedPath] || file.Role == "ANSWER" && !seenAnswers[file.NormalizedPath] || file.Role == "REFERENCE" && !seenReferences[file.NormalizedPath] || file.Role == "INPUT_VALIDATOR" && !seenValidators[file.NormalizedPath] || file.Role == "STATEMENT" && file.NormalizedPath != m.Statement.Source.Path || file.Role == "VALIDATION_STATEMENT" && file.NormalizedPath != m.Statement.ValidationView.Path {
			return manifestInvalid()
		}
	}
	validCodes := map[string]bool{"MARKDOWN_TO_TEX": true, "SHORTNAME_MAPPING": true, "EXTENSION_TO_MANIFEST": true, "UNIT_CONVERSION": true, "DEFAULT_APPLIED": true}
	var lastField, lastCode, lastJSON string
	for i, adaptation := range m.Adaptations {
		if !validCodes[adaptation.Code] || adaptation.SourceField == "" || utf8.RuneCountInString(adaptation.SourceField) > 256 || strings.TrimSpace(adaptation.Reason) == "" || utf8.RuneCountInString(adaptation.Reason) > 500 {
			return manifestInvalid()
		}
		raw, err := json.Marshal(adaptation)
		if err != nil {
			return manifestInvalid()
		}
		encoded, err := canonical.Canonicalize(raw)
		if err != nil {
			return manifestInvalid()
		}
		value := string(encoded)
		if i > 0 && (adaptation.SourceField < lastField || adaptation.SourceField == lastField && (adaptation.Code < lastCode || adaptation.Code == lastCode && value <= lastJSON)) {
			return manifestInvalid()
		}
		lastField = adaptation.SourceField
		lastCode = adaptation.Code
		lastJSON = value
	}
	return nil
}

// VerifyFiles binds every runtime-referenced normalized file to its frozen bytes.
// It rejects extra or missing entries; the reserved manifest is stored separately.
func VerifyFiles(manifest Manifest, files []File) error {
	if err := ValidateManifest(manifest); err != nil {
		return err
	}
	if len(files) != len(manifest.Files) {
		return manifestInvalid()
	}
	if _, err := validateFiles(files, true); err != nil {
		return err
	}
	values := make(map[string]File, len(files))
	for _, file := range files {
		values[file.Path] = file
	}
	for _, mapping := range manifest.Files {
		file, exists := values[mapping.NormalizedPath]
		if !exists || int64(len(file.Data)) != mapping.NormalizedSizeBytes || canonical.HashBytes(file.Data) != mapping.NormalizedSHA256 {
			return manifestInvalid()
		}
	}
	return nil
}
