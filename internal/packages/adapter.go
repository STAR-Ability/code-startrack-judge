// SPDX-License-Identifier: Apache-2.0

package packages

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"go.yaml.in/yaml/v3"
)

const maxMetadataBytes = 1 << 20

var decimalLexeme = regexp.MustCompile(`^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$`)

type AdaptError struct{ Code, Stage, Diagnostic string }

func (e *AdaptError) Error() string {
	return "problem package rejected: " + e.Code + "/" + e.Diagnostic
}
func rejected(code, stage, diagnostic string) error {
	return &AdaptError{Code: code, Stage: stage, Diagnostic: diagnostic}
}

type Sample struct {
	Input  string `json:"input"`
	Output string `json:"output"`
}

// Artifact is a private, unqualified adaptation candidate. ManifestReady proves
// structural protocol conformity only; it never proves license or execution.
// Rejected candidates retain original/derived evidence for private ingestion.
type Artifact struct {
	Source            SourceIdentity
	SourceFiles       []File
	SourceArchive     []byte
	SourceSHA256      string
	NormalizedFiles   []File
	NormalizedArchive []byte
	NormalizedSHA256  string
	Manifest          *Manifest
	ManifestJSON      []byte
	ManifestSHA256    string
	ManifestReady     bool
	StatementContent  string
	StatementInput    *string
	StatementOutput   *string
	Samples           []Sample
}

func (*Artifact) String() string     { return "private package candidate [bytes and paths redacted]" }
func (a *Artifact) GoString() string { return a.String() }

func PinnedSource(packagePath string) SourceIdentity {
	return SourceIdentity{Source: "OJ_LAB", RepositoryURL: RepositoryURL, Revision: PinnedRevision, PackagePath: packagePath}
}

func validateIdentity(identity SourceIdentity) error {
	if identity.Source != "OJ_LAB" || identity.RepositoryURL != RepositoryURL || identity.Revision != PinnedRevision || !strings.HasPrefix(identity.PackagePath, "problems/") || ValidatePath(identity.PackagePath) != nil {
		return rejected("PACKAGE_INVALID", "INVALID_STRUCTURE", "SOURCE_IDENTITY_INVALID")
	}
	return nil
}

func decodeMetadata(data []byte) (map[string]any, error) {
	if len(data) > maxMetadataBytes || !utf8.Valid(data) {
		return nil, rejected("PACKAGE_INVALID", "INVALID_STRUCTURE", "METADATA_ENCODING_OR_SIZE")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var root yaml.Node
	if err := decoder.Decode(&root); err != nil {
		return nil, rejected("PACKAGE_INVALID", "INVALID_STRUCTURE", "METADATA_INVALID")
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, rejected("PACKAGE_INVALID", "INVALID_STRUCTURE", "METADATA_MULTIPLE_DOCUMENTS")
	}
	count := 0
	var visit func(*yaml.Node, int) (any, error)
	visit = func(node *yaml.Node, depth int) (any, error) {
		count++
		if count > 16384 || depth > 32 || node.Anchor != "" || node.Kind == yaml.AliasNode {
			return nil, rejected("PACKAGE_INVALID", "INVALID_STRUCTURE", "METADATA_COMPLEXITY")
		}
		if node.Tag != "!!map" && node.Tag != "!!seq" && node.Tag != "!!str" && node.Tag != "!!int" && node.Tag != "!!float" && node.Tag != "!!timestamp" && node.Tag != "!!bool" && node.Tag != "!!null" && node.Kind != yaml.DocumentNode {
			return nil, rejected("PACKAGE_UNSUPPORTED", "UNSUPPORTED", "METADATA_TAG_UNSUPPORTED")
		}
		switch node.Kind {
		case yaml.DocumentNode:
			if len(node.Content) != 1 {
				return nil, rejected("PACKAGE_INVALID", "INVALID_STRUCTURE", "METADATA_INVALID")
			}
			return visit(node.Content[0], depth+1)
		case yaml.MappingNode:
			values := make(map[string]any, len(node.Content)/2)
			for i := 0; i < len(node.Content); i += 2 {
				key := node.Content[i]
				if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Anchor != "" {
					return nil, rejected("PACKAGE_INVALID", "INVALID_STRUCTURE", "METADATA_KEY_INVALID")
				}
				if _, exists := values[key.Value]; exists {
					return nil, rejected("PACKAGE_INVALID", "INVALID_STRUCTURE", "METADATA_DUPLICATE_KEY")
				}
				value, err := visit(node.Content[i+1], depth+1)
				if err != nil {
					return nil, err
				}
				values[key.Value] = value
			}
			return values, nil
		case yaml.SequenceNode:
			values := make([]any, 0, len(node.Content))
			for _, child := range node.Content {
				value, err := visit(child, depth+1)
				if err != nil {
					return nil, err
				}
				values = append(values, value)
			}
			return values, nil
		case yaml.ScalarNode:
			switch node.Tag {
			case "!!null":
				return nil, nil
			case "!!str":
				return node.Value, nil
			case "!!bool":
				value, err := strconv.ParseBool(strings.ToLower(node.Value))
				if err != nil {
					return nil, rejected("PACKAGE_INVALID", "INVALID_STRUCTURE", "METADATA_SCALAR_INVALID")
				}
				return value, nil
			case "!!int":
				value, ok := new(big.Int).SetString(node.Value, 10)
				if ok && value.IsInt64() && value.Cmp(big.NewInt(-9007199254740991)) >= 0 && value.Cmp(big.NewInt(9007199254740991)) <= 0 {
					return value.Int64(), nil
				}
				return map[string]any{"yamlTag": node.Tag, "lexeme": node.Value}, nil
			case "!!float", "!!timestamp":
				// Unknown scalar lexemes remain exact instead of becoming lossy floats.
				return map[string]any{"yamlTag": node.Tag, "lexeme": node.Value}, nil
			}
		}
		return nil, rejected("PACKAGE_INVALID", "INVALID_STRUCTURE", "METADATA_NODE_INVALID")
	}
	value, err := visit(&root, 0)
	if err != nil {
		return nil, err
	}
	mapping, ok := value.(map[string]any)
	if !ok {
		return nil, rejected("PACKAGE_INVALID", "INVALID_STRUCTURE", "METADATA_ROOT_INVALID")
	}
	return mapping, nil
}

// decimalParts compares exact bounded lexemes without allocating 10^exponent.
// Hostile exponents can contain many digits; their magnitude never controls an
// allocation or loop. This is important for untrusted package metadata.
func decimalParts(value string) (coefficient string, scale *big.Int, ok bool) {
	if len(value) > 64 || !decimalLexeme.MatchString(value) {
		return "", nil, false
	}
	parts := strings.Split(strings.ToLower(value), "e")
	exponent := new(big.Int)
	if len(parts) == 2 {
		if _, valid := exponent.SetString(parts[1], 10); !valid {
			return "", nil, false
		}
	}
	mantissa := strings.Split(parts[0], ".")
	digits := mantissa[0]
	fraction := 0
	if len(mantissa) == 2 {
		digits += mantissa[1]
		fraction = len(mantissa[1])
	}
	digits = strings.TrimLeft(digits, "0")
	return digits, new(big.Int).Sub(exponent, big.NewInt(int64(fraction))), true
}

func exactMilliseconds(value string) (int64, bool) {
	digits, scale, ok := decimalParts(value)
	if !ok || digits == "" {
		return 0, false
	}
	scale.Add(scale, big.NewInt(3))
	if !scale.IsInt64() {
		return 0, false
	}
	shift := scale.Int64()
	if shift >= 0 {
		if shift > 5-int64(len(digits)) {
			return 0, false
		}
		digits += strings.Repeat("0", int(shift))
	} else {
		if shift < -int64(len(digits)) {
			return 0, false
		}
		cut := len(digits) + int(shift)
		if strings.Trim(digits[cut:], "0") != "" {
			return 0, false
		}
		digits = digits[:cut]
	}
	ms, err := strconv.ParseInt(digits, 10, 64)
	return ms, err == nil && ms > 0 && ms <= 60000
}

func sourceLimits(metadata map[string]any, timelimit []byte) (ExecutionLimits, []Adaptation, error) {
	lexeme := strings.TrimSpace(string(timelimit))
	if len(lexeme) > 64 || !decimalLexeme.MatchString(lexeme) {
		return ExecutionLimits{}, nil, rejected("PACKAGE_INVALID", "INVALID_STRUCTURE", "CPU_LIMIT_INVALID")
	}
	ms, ok := exactMilliseconds(lexeme)
	if !ok {
		return ExecutionLimits{}, nil, rejected("PACKAGE_INVALID", "INVALID_STRUCTURE", "CPU_LIMIT_OUT_OF_PROFILE")
	}
	values := map[string]any{}
	if raw, exists := metadata["limits"]; exists {
		var valid bool
		values, valid = raw.(map[string]any)
		if !valid {
			return ExecutionLimits{}, nil, rejected("PACKAGE_INVALID", "INVALID_STRUCTURE", "LIMITS_INVALID")
		}
	}
	adaptations := []Adaptation{{Code: "UNIT_CONVERSION", SourceField: ".timelimit", OriginalValue: lexeme, NormalizedValue: ms, Reason: "Exact source seconds converted to integral milliseconds."}, {Code: "DEFAULT_APPLIED", SourceField: "wallLimitMs", OriginalValue: nil, NormalizedValue: ms * 2, Reason: "Frozen adapter wall policy is exactly twice source CPU."}}
	defaults := map[string]int64{"code": 128, "compilation_time": 60, "compilation_memory": 1024, "validation_time": 60, "validation_memory": 1024, "validation_output": 8, "time_multiplier": 5, "time_safety_margin": 2}
	for key, value := range values {
		if key == "memory" || key == "output" {
			continue
		}
		expected, ok := defaults[key]
		actual, integer := value.(int64)
		if !ok || !integer || actual != expected {
			return ExecutionLimits{}, nil, rejected("PACKAGE_UNSUPPORTED", "UNSUPPORTED", "LIMIT_POLICY_UNSUPPORTED")
		}
	}
	read := func(key string, fallback, max int64) (int64, error) {
		value, exists := values[key]
		code := "UNIT_CONVERSION"
		if !exists {
			value = fallback
			code = "DEFAULT_APPLIED"
		}
		integer, ok := value.(int64)
		if !ok || integer <= 0 || integer > max {
			return 0, rejected("PACKAGE_INVALID", "INVALID_STRUCTURE", "RESOURCE_LIMIT_INVALID")
		}
		adaptations = append(adaptations, Adaptation{Code: code, SourceField: "problem.yaml/limits/" + key, OriginalValue: func() any {
			if exists {
				return value
			}
			return nil
		}(), NormalizedValue: integer * 1048576, Reason: "Pinned source MiB converted exactly to bytes; recorded defaults match pinned problemtools."})
		return integer * 1048576, nil
	}
	memory, err := read("memory", 1024, 2048)
	if err != nil {
		return ExecutionLimits{}, nil, err
	}
	output, err := read("output", 8, 64)
	if err != nil {
		return ExecutionLimits{}, nil, err
	}
	return ExecutionLimits{TimeLimitMS: ms, WallLimitMS: ms * 2, MemoryLimitBytes: memory, OutputLimitBytes: output, ProcessLimit: 32}, adaptations, nil
}

func validTolerance(value string) bool {
	digits, scale, ok := decimalParts(value)
	if !ok {
		return false
	}
	if digits == "" {
		return true
	}
	magnitude := new(big.Int).Add(scale, big.NewInt(int64(len(digits))))
	comparison := magnitude.Cmp(big.NewInt(1))
	return comparison < 0 || comparison == 0 && digits[0] == '1' && strings.Trim(digits[1:], "0") == ""
}

func parseChecker(metadata map[string]any) (CheckerConfig, error) {
	checker := DefaultChecker()
	if _, exists := metadata["input_validator_flags"]; exists {
		return checker, rejected("PACKAGE_UNSUPPORTED", "UNSUPPORTED", "INPUT_VALIDATOR_ARGUMENTS_UNSUPPORTED")
	}
	if value, exists := metadata["validation"]; exists && value != "default" {
		return checker, rejected("PACKAGE_UNSUPPORTED", "UNSUPPORTED", "CHECKER_UNSUPPORTED")
	}
	raw, exists := metadata["validator_flags"]
	if !exists {
		return checker, nil
	}
	flags, ok := raw.(string)
	if !ok {
		return checker, rejected("PACKAGE_INVALID", "INVALID_STRUCTURE", "CHECKER_FLAGS_INVALID")
	}
	seen := make(map[string]bool)
	parts := strings.Fields(flags)
	for i := 0; i < len(parts); i++ {
		key := parts[i]
		if seen[key] {
			return checker, rejected("PACKAGE_UNSUPPORTED", "UNSUPPORTED", "CHECKER_FLAGS_CONFLICT")
		}
		seen[key] = true
		switch key {
		case "case_sensitive":
			checker.CaseSensitive = true
		case "space_change_sensitive":
			checker.SpaceChangeSensitive = true
		case "float_tolerance", "float_absolute_tolerance", "float_relative_tolerance":
			if i+1 == len(parts) {
				return checker, rejected("PACKAGE_INVALID", "INVALID_STRUCTURE", "CHECKER_TOLERANCE_INVALID")
			}
			i++
			value := parts[i]
			if strings.HasPrefix(value, ".") {
				value = "0" + value
			}
			if !validTolerance(value) {
				return checker, rejected("PACKAGE_UNSUPPORTED", "UNSUPPORTED", "CHECKER_TOLERANCE_UNSUPPORTED")
			}
			if key == "float_tolerance" {
				if checker.FloatAbsoluteTolerance != nil || checker.FloatRelativeTolerance != nil {
					return checker, rejected("PACKAGE_UNSUPPORTED", "UNSUPPORTED", "CHECKER_FLAGS_CONFLICT")
				}
				checker.FloatAbsoluteTolerance = &value
				checker.FloatRelativeTolerance = &value
			} else if key == "float_absolute_tolerance" {
				if checker.FloatAbsoluteTolerance != nil {
					return checker, rejected("PACKAGE_UNSUPPORTED", "UNSUPPORTED", "CHECKER_FLAGS_CONFLICT")
				}
				checker.FloatAbsoluteTolerance = &value
			} else {
				if checker.FloatRelativeTolerance != nil {
					return checker, rejected("PACKAGE_UNSUPPORTED", "UNSUPPORTED", "CHECKER_FLAGS_CONFLICT")
				}
				checker.FloatRelativeTolerance = &value
			}
		default:
			return checker, rejected("PACKAGE_UNSUPPORTED", "UNSUPPORTED", "CHECKER_FLAGS_UNSUPPORTED")
		}
	}
	return checker, nil
}

// CheckerFlags returns allowlisted argv only. It implements configuration, not
// output comparison; the mature pinned checker is the sole comparator.
func CheckerFlags(config CheckerConfig) ([]string, error) {
	if err := validateChecker(config); err != nil {
		return nil, err
	}
	flags := []string{}
	if config.CaseSensitive {
		flags = append(flags, "case_sensitive")
	}
	if config.SpaceChangeSensitive {
		flags = append(flags, "space_change_sensitive")
	}
	if config.FloatAbsoluteTolerance != nil {
		flags = append(flags, "float_absolute_tolerance", *config.FloatAbsoluteTolerance)
	}
	if config.FloatRelativeTolerance != nil {
		flags = append(flags, "float_relative_tolerance", *config.FloatRelativeTolerance)
	}
	return flags, nil
}

func escapedTeX(value string, maxBytes int) (string, error) {
	value = strings.ReplaceAll(strings.ReplaceAll(value, "\r\n", "\n"), "\r", "\n")
	var out strings.Builder
	for _, r := range value {
		fragment := string(r)
		switch r {
		case '\\':
			fragment = `\textbackslash{}`
		case '{', '}', '$', '&', '#', '%', '_':
			fragment = "\\" + string(r)
		case '^':
			fragment = `\textasciicircum{}`
		case '~':
			fragment = `\textasciitilde{}`
		case '\n':
			fragment = "\\par{}\n"
		case '\t':
			fragment = "    "
		}
		if len(fragment) > maxBytes-out.Len() {
			return "", ErrBounds
		}
		out.WriteString(fragment)
	}
	return out.String(), nil
}

func validationStatement(title, markdown string) ([]byte, error) {
	escapedTitle, err := escapedTeX(title, 16384)
	if err != nil {
		return nil, err
	}
	prefix := "\\problemname{" + escapedTitle + "}\n"
	body, err := escapedTeX(markdown, int(MaxFileBytes)-len(prefix)-1)
	if err != nil {
		return nil, err
	}
	value := prefix + body
	if !strings.HasSuffix(value, "\n") {
		value += "\n"
	}
	return []byte(value), nil
}

func fileRef(file File) FileRef {
	return FileRef{Path: file.Path, SHA256: canonical.HashBytes(file.Data), SizeBytes: int64(len(file.Data))}
}
func language(path string) (string, error) {
	switch strings.ToLower(pathpkgExt(path)) {
	case ".cpp", ".cc", ".cxx":
		return "cpp17", nil
	case ".py":
		return "python3", nil
	}
	return "", rejected("PACKAGE_UNSUPPORTED", "UNSUPPORTED", "INTERNAL_LANGUAGE_UNSUPPORTED")
}
func pathpkgExt(value string) string { return path.Ext(value) }

func sortAdaptations(adaptations []Adaptation) []Adaptation {
	type item struct {
		value     Adaptation
		canonical string
	}
	values := make([]item, 0, len(adaptations))
	seen := map[string]bool{}
	for _, value := range adaptations {
		raw, _ := json.Marshal(value)
		data, _ := canonical.Canonicalize(raw)
		key := string(data)
		if !seen[key] {
			seen[key] = true
			values = append(values, item{value, key})
		}
	}
	sort.Slice(values, func(i, j int) bool {
		a, b := values[i], values[j]
		if a.value.SourceField != b.value.SourceField {
			return a.value.SourceField < b.value.SourceField
		}
		if a.value.Code != b.value.Code {
			return a.value.Code < b.value.Code
		}
		return a.canonical < b.canonical
	})
	result := make([]Adaptation, 0, len(values))
	for _, item := range values {
		result = append(result, item.value)
	}
	return result
}

// Adapt never fetches data, executes source, verifies licensing or publishes.
// The caller supplies the exact pinned source snapshot and stores rejected
// candidates privately. Successful adaptation still needs real qualification.
func Adapt(identity SourceIdentity, files []File) (*Artifact, error) {
	artifact := &Artifact{Source: identity, Samples: []Sample{}}
	// Retain only bounded, inert snapshots on unsafe-path rejection. These paths
	// must never be extracted; accepted archives are constructed after validation.
	var sourceBytes int64
	if len(files) > MaxFiles {
		return artifact, ErrBounds
	}
	for _, file := range files {
		sourceBytes += int64(len(file.Data))
		if int64(len(file.Data)) > MaxFileBytes || sourceBytes > MaxTotalBytes {
			return artifact, ErrBounds
		}
	}
	artifact.SourceFiles = make([]File, len(files))
	for i, file := range files {
		artifact.SourceFiles[i] = File{Path: file.Path, Data: bytes.Clone(file.Data), SourceMode: file.SourceMode}
	}
	files = artifact.SourceFiles
	if err := validateIdentity(identity); err != nil {
		return artifact, err
	}
	for _, file := range files {
		if file.Path == ReservedManifestPath {
			return artifact, rejected("PACKAGE_UNSUPPORTED", "UNSUPPORTED", "RESERVED_MANIFEST_PATH")
		}
	}
	if _, err := validateFiles(files, true); err != nil {
		return artifact, rejected("PACKAGE_INVALID", "INVALID_STRUCTURE", "SOURCE_FILES_UNSAFE")
	}
	var err error
	artifact.SourceArchive, err = BuildArchive(files)
	if err != nil {
		return artifact, err
	}
	artifact.SourceSHA256 = canonical.HashBytes(artifact.SourceArchive)
	byPath := make(map[string]File, len(files))
	for _, file := range files {
		byPath[file.Path] = file
	}
	metadataFile, exists := byPath["problem.yaml"]
	if !exists {
		return artifact, rejected("PACKAGE_INVALID", "INVALID_STRUCTURE", "METADATA_MISSING")
	}
	metadata, err := decodeMetadata(metadataFile.Data)
	if err != nil {
		return artifact, err
	}
	for _, key := range []string{"type", "problem_format_version"} {
		if value, exists := metadata[key]; exists && (key == "type" && value != "pass-fail" || key == "problem_format_version" && value != "legacy") {
			return artifact, rejected("PACKAGE_UNSUPPORTED", "UNSUPPORTED", "MODE_UNSUPPORTED")
		}
	}
	if _, exists := metadata["grading"]; exists {
		return artifact, rejected("PACKAGE_UNSUPPORTED", "UNSUPPORTED", "SCORING_UNSUPPORTED")
	}
	if value, exists := metadata["languages"]; exists && value != "all" {
		return artifact, rejected("PACKAGE_UNSUPPORTED", "UNSUPPORTED", "SOURCE_LANGUAGE_POLICY_UNSUPPORTED")
	}
	title, ok := metadata["name"].(string)
	if !ok || strings.TrimSpace(title) == "" || utf8.RuneCountInString(title) > 256 {
		return artifact, rejected("PACKAGE_INVALID", "INVALID_STRUCTURE", "TITLE_INVALID")
	}
	statement, exists := byPath["problem_statement/problem.en.md"]
	if alternate, found := byPath["problem_statement/problem.md"]; found {
		if exists {
			return artifact, rejected("PACKAGE_UNSUPPORTED", "UNSUPPORTED", "STATEMENT_AMBIGUOUS")
		}
		statement, exists = alternate, true
	}
	if !exists || !utf8.Valid(statement.Data) {
		return artifact, rejected("PACKAGE_INVALID", "INVALID_STRUCTURE", "STATEMENT_INVALID")
	}
	if _, exists := byPath["problem_statement/problem.en.tex"]; exists {
		return artifact, rejected("PACKAGE_UNSUPPORTED", "UNSUPPORTED", "GENERATED_VIEW_COLLISION")
	}
	timelimit, exists := byPath[".timelimit"]
	if !exists {
		return artifact, rejected("PACKAGE_INVALID", "INVALID_STRUCTURE", "CPU_LIMIT_MISSING")
	}
	limits, adaptations, err := sourceLimits(metadata, timelimit.Data)
	if err != nil {
		return artifact, err
	}
	checker, err := parseChecker(metadata)
	if err != nil {
		return artifact, err
	}
	shortname := "p" + canonical.HashBytes([]byte(identity.PackagePath))[:32]
	texBytes, err := validationStatement(title, string(statement.Data))
	if err != nil {
		return artifact, err
	}
	tex := File{Path: "problem_statement/problem.en.tex", Data: texBytes}
	manifest := &Manifest{ManifestVersion: ManifestVersion, AdapterVersion: AdapterVersion, SourceFormat: SourceFormat, Source: identity, JudgeMode: "BATCH_PASS_FAIL", Title: title, Statement: StatementManifest{Format: "MARKDOWN", Source: fileRef(statement), ValidationFormat: "TEX", ValidationView: fileRef(tex), Shortname: shortname}, LanguageIDs: []string{"cpp17"}, Limits: limits, ExecutionProfiles: DefaultExecutionProfiles(), Checker: checker, Tests: []TestCase{}, ReferenceSolutions: []ReferenceSolution{}, InputValidators: []ProgramSource{}, Files: []FileMapping{}, SourceMetadata: metadata}
	artifact.Manifest = manifest
	artifact.StatementContent = string(statement.Data)
	roles := map[string]string{}
	modes := map[string]any{}
	for _, file := range files {
		if strings.HasPrefix(file.Path, "problem_statement/") && strings.HasSuffix(file.Path, ".md") && file.Path != statement.Path {
			return artifact, rejected("PACKAGE_UNSUPPORTED", "UNSUPPORTED", "STATEMENT_LANGUAGE_UNSUPPORTED")
		}
		if (strings.HasSuffix(file.Path, ".in") || strings.HasSuffix(file.Path, ".ans")) && !strings.HasPrefix(file.Path, "data/sample/") && !strings.HasPrefix(file.Path, "data/secret/") {
			return artifact, rejected("PACKAGE_UNSUPPORTED", "UNSUPPORTED", "TEST_DIRECTORY_UNSUPPORTED")
		}
		modes[file.Path] = file.SourceMode
		roles[file.Path] = "OTHER"
	}
	manifest.SourceMetadata = map[string]any{"originalMetadata": metadata, "sourceFileModes": modes, "timeLimitLexeme": strings.TrimSpace(string(timelimit.Data))}
	roles[statement.Path] = "STATEMENT"
	roles["problem.yaml"] = "SOURCE_METADATA"
	roles[".timelimit"] = "SOURCE_METADATA"
	roles[tex.Path] = "VALIDATION_STATEMENT"
	for _, file := range files {
		if strings.EqualFold(path.Base(file.Path), "LICENSE") || strings.HasPrefix(strings.ToUpper(path.Base(file.Path)), "LICENSE.") || strings.EqualFold(path.Base(file.Path), "NOTICE") {
			roles[file.Path] = "LICENSE"
		}
		if strings.HasPrefix(file.Path, "output_validators/") || strings.HasPrefix(file.Path, "graders/") || strings.HasPrefix(file.Path, "include/") || strings.HasPrefix(file.Path, "input_format_validators/") || strings.HasSuffix(file.Path, ".viva") || strings.HasSuffix(file.Path, ".jar") || strings.HasSuffix(file.Path, ".interaction") {
			return artifact, rejected("PACKAGE_UNSUPPORTED", "UNSUPPORTED", "EXECUTION_FORMAT_UNSUPPORTED")
		}
		if path.Base(file.Path) == "testdata.yaml" {
			config, e := decodeMetadata(file.Data)
			if e != nil {
				return artifact, e
			}
			if len(config) > 0 {
				return artifact, rejected("PACKAGE_UNSUPPORTED", "UNSUPPORTED", "GROUP_CONFIGURATION_UNSUPPORTED")
			}
		}
		if strings.HasPrefix(file.Path, "input_validators/") {
			if len(strings.Split(file.Path, "/")) != 2 {
				return artifact, rejected("PACKAGE_UNSUPPORTED", "UNSUPPORTED", "MULTIFILE_VALIDATOR_UNSUPPORTED")
			}
			lang, e := language(file.Path)
			if e != nil {
				return artifact, e
			}
			manifest.InputValidators = append(manifest.InputValidators, ProgramSource{File: fileRef(file), LanguageID: lang})
			roles[file.Path] = "INPUT_VALIDATOR"
		}
		if strings.HasPrefix(file.Path, "submissions/") {
			parts := strings.Split(file.Path, "/")
			if len(parts) != 3 {
				return artifact, rejected("PACKAGE_UNSUPPORTED", "UNSUPPORTED", "MULTIFILE_REFERENCE_UNSUPPORTED")
			}
			role := map[string]string{"accepted": "ACCEPTED", "wrong_answer": "WRONG_ANSWER", "time_limit_exceeded": "TIME_LIMIT", "run_time_error": "RUNTIME_ERROR"}[parts[1]]
			if role == "" {
				return artifact, rejected("PACKAGE_UNSUPPORTED", "UNSUPPORTED", "REFERENCE_ROLE_UNSUPPORTED")
			}
			lang, e := language(file.Path)
			if e != nil {
				return artifact, e
			}
			manifest.ReferenceSolutions = append(manifest.ReferenceSolutions, ReferenceSolution{File: fileRef(file), LanguageID: lang, Role: role})
			roles[file.Path] = "REFERENCE"
		}
	}
	for _, visibility := range []string{"SAMPLE", "SECRET"} {
		prefix := "data/" + strings.ToLower(visibility) + "/"
		var inputs []File
		for _, file := range files {
			if strings.HasPrefix(file.Path, prefix) && strings.HasSuffix(file.Path, ".in") {
				inputs = append(inputs, file)
			}
		}
		sort.Slice(inputs, func(i, j int) bool { return inputs[i].Path < inputs[j].Path })
		for _, input := range inputs {
			answer, exists := byPath[strings.TrimSuffix(input.Path, ".in")+".ans"]
			if !exists {
				return artifact, rejected("PACKAGE_INVALID", "INVALID_STRUCTURE", "ANSWER_MISSING")
			}
			roles[input.Path] = "INPUT"
			roles[answer.Path] = "ANSWER"
			var group *string
			if directory := path.Dir(strings.TrimPrefix(input.Path, prefix)); directory != "." {
				if utf8.RuneCountInString(directory) > 128 {
					return artifact, rejected("PACKAGE_UNSUPPORTED", "UNSUPPORTED", "GROUP_LABEL_UNSUPPORTED")
				}
				group = &directory
			}
			manifest.Tests = append(manifest.Tests, TestCase{Ordinal: len(manifest.Tests) + 1, Visibility: visibility, Input: fileRef(input), Answer: fileRef(answer), Checker: checker, ValidationGroup: group})
			if len(manifest.Tests) > MaxTests {
				return artifact, ErrBounds
			}
			if visibility == "SAMPLE" {
				if !utf8.Valid(input.Data) || !utf8.Valid(answer.Data) {
					return artifact, rejected("PACKAGE_INVALID", "INVALID_STRUCTURE", "SAMPLE_ENCODING_INVALID")
				}
				artifact.Samples = append(artifact.Samples, Sample{Input: string(input.Data), Output: string(answer.Data)})
			}
		}
	}
	for _, file := range files {
		if strings.HasPrefix(file.Path, "data/") && strings.HasSuffix(file.Path, ".ans") && roles[file.Path] != "ANSWER" {
			return artifact, rejected("PACKAGE_INVALID", "INVALID_STRUCTURE", "ORPHAN_ANSWER")
		}
	}
	manifest.TestCount = len(manifest.Tests)
	flags, _ := CheckerFlags(checker)
	legacy := map[string]any{"name": title, "type": "pass-fail", "validation": "default", "validator_flags": strings.Join(flags, " "), "limits": map[string]any{"memory": limits.MemoryLimitBytes / 1048576, "output": limits.OutputLimitBytes / 1048576, "code": 128, "compilation_time": 60, "compilation_memory": 1024, "validation_time": 60, "validation_memory": 1024, "validation_output": 8, "time_multiplier": 5, "time_safety_margin": 2}}
	legacyRaw, _ := json.Marshal(legacy)
	legacyBytes, _ := canonical.Canonicalize(legacyRaw)
	normalized := append([]File(nil), files...)
	for i := range normalized {
		if normalized[i].Path == "problem.yaml" {
			normalized[i].Data = legacyBytes
		}
	}
	normalized = append(normalized, tex)
	sort.Slice(normalized, func(i, j int) bool { return normalized[i].Path < normalized[j].Path })
	sort.Slice(manifest.ReferenceSolutions, func(i, j int) bool {
		return manifest.ReferenceSolutions[i].File.Path < manifest.ReferenceSolutions[j].File.Path
	})
	sort.Slice(manifest.InputValidators, func(i, j int) bool {
		return manifest.InputValidators[i].File.Path < manifest.InputValidators[j].File.Path
	})
	for _, file := range normalized {
		mapping := FileMapping{NormalizedPath: file.Path, NormalizedSHA256: canonical.HashBytes(file.Data), NormalizedSizeBytes: int64(len(file.Data)), Role: roles[file.Path]}
		if original, exists := byPath[file.Path]; exists {
			name := original.Path
			hash := canonical.HashBytes(original.Data)
			size := int64(len(original.Data))
			mapping.OriginalPath = &name
			mapping.SourceSHA256 = &hash
			mapping.SourceSizeBytes = &size
		}
		manifest.Files = append(manifest.Files, mapping)
	}
	adaptations = append(adaptations, Adaptation{Code: "MARKDOWN_TO_TEX", SourceField: statement.Path, OriginalValue: canonical.HashBytes(statement.Data), NormalizedValue: canonical.HashBytes(tex.Data), Reason: "Original Markdown retained; one-pass escaped literal TeX validation view with recorded line/tab normalization."}, Adaptation{Code: "SHORTNAME_MAPPING", SourceField: "packagePath", OriginalValue: identity.PackagePath, NormalizedValue: shortname, Reason: "Deterministic legacy-compatible shortname from original UTF-8 package path."}, Adaptation{Code: "EXTENSION_TO_MANIFEST", SourceField: "problem.yaml", OriginalValue: metadata, NormalizedValue: legacy, Reason: "Original metadata/unknown extensions retained; controlled JCS JSON-as-YAML legacy view."})
	manifest.Adaptations = sortAdaptations(adaptations)
	raw, err := json.Marshal(manifest)
	if err != nil {
		return artifact, rejected("PACKAGE_INVALID", "INVALID_STRUCTURE", "MANIFEST_ENCODING_INVALID")
	}
	artifact.ManifestJSON, err = canonical.Canonicalize(raw)
	if err != nil {
		return artifact, err
	}
	artifact.ManifestSHA256 = canonical.HashBytes(artifact.ManifestJSON)
	artifact.NormalizedFiles = normalized
	archiveFiles := append(append([]File(nil), normalized...), File{Path: ReservedManifestPath, Data: artifact.ManifestJSON})
	artifact.NormalizedArchive, err = BuildArchive(archiveFiles)
	if err != nil {
		return artifact, err
	}
	artifact.NormalizedSHA256 = canonical.HashBytes(artifact.NormalizedArchive)
	if len(manifest.InputValidators) == 0 {
		return artifact, rejected("PACKAGE_VALIDATION_FAILED", "VALIDATION_FAILED", "INPUT_VALIDATOR_MISSING")
	}
	if err := ValidateManifest(*manifest); err != nil {
		return artifact, err
	}
	artifact.ManifestReady = true
	return artifact, nil
}
