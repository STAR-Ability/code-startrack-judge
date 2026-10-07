package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const PackageRepository = "https://github.com/oj-lab/problem-packages"

var shaPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

func validateAll(v ...interface{ Validate() error }) error {
	for _, x := range v {
		if e := x.Validate(); e != nil {
			return e
		}
	}
	return nil
}
func (r ProblemRef) Validate() error {
	if e := r.ProblemID.Validate(); e != nil {
		return e
	}
	if r.Source == SourcePlatform && r.Platform == PlatformStartrack && r.ProblemVersionID != nil {
		return r.ProblemVersionID.Validate()
	}
	if r.Source == SourceExternal && r.Platform == PlatformCodeforces && r.ProblemVersionID == nil {
		return nil
	}
	return &ValidationError{Code: "INVALID_PROBLEM_REF", Field: "problemRef"}
}
func (r JudgeTaskRequest) Validate() error {
	if e := validateAll(r.RequestID, r.SubmissionID, r.ProblemRef); e != nil {
		return e
	}
	if r.ProblemRef.Source != SourcePlatform {
		return &ValidationError{Code: "INVALID_PROBLEM_REF", Field: "problemRef"}
	}
	if r.LanguageID != "cpp17" {
		return &ValidationError{Code: "LANGUAGE_NOT_SUPPORTED", Field: "languageId"}
	}
	if !utf8.ValidString(r.SourceCode) || strings.TrimSpace(r.SourceCode) == "" {
		return Invalid("sourceCode")
	}
	if len(r.SourceCode) > MaxSourceBytes {
		return &ValidationError{Code: "SOURCE_TOO_LARGE", Field: "sourceCode"}
	}
	h := sha256.Sum256([]byte(r.SourceCode))
	if !shaPattern.MatchString(r.SourceSHA256) || hex.EncodeToString(h[:]) != r.SourceSHA256 {
		return Invalid("sourceSha256")
	}
	return nil
}
func (r ByRequestRequest) Validate() error {
	if len(r.RequestIDs) < 1 || len(r.RequestIDs) > 100 {
		return Invalid("requestIds")
	}
	seen := map[UUID]bool{}
	for _, id := range r.RequestIDs {
		if e := id.Validate(); e != nil {
			return e
		}
		if seen[id] {
			return Invalid("requestIds")
		}
		seen[id] = true
	}
	return nil
}
func (r ImportRequest) Validate() error {
	if e := r.RequestID.Validate(); e != nil {
		return e
	}
	if r.Source != "OJ_LAB" || r.RepositoryURL != PackageRepository || !commitPattern.MatchString(r.Revision) {
		return Invalid("source")
	}
	if len(r.PackagePaths) < 1 || len(r.PackagePaths) > 100 {
		return Invalid("packagePaths")
	}
	seen := map[string]bool{}
	for _, p := range r.PackagePaths {
		if !ValidPackagePath(p) || seen[p] {
			return Invalid("packagePaths")
		}
		seen[p] = true
	}
	return nil
}
func (r MetadataVersionRequest) Validate() error {
	if e := validateAll(r.RequestID, r.BaseProblemVersionID); e != nil {
		return e
	}
	if len(r.Tags) > 32 {
		return Invalid("tags")
	}
	for _, tag := range r.Tags {
		trimmed := strings.TrimSpace(tag)
		if !utf8.ValidString(tag) || utf8.RuneCountInString(trimmed) < 1 || utf8.RuneCountInString(trimmed) > 128 {
			return Invalid("tags")
		}
	}
	if r.DifficultyScale == DifficultyUnrated && r.Difficulty == nil {
		return nil
	}
	if r.DifficultyScale == DifficultyPlatform && r.Difficulty != nil && *r.Difficulty > 0 {
		return r.Difficulty.Validate()
	}
	return Invalid("difficulty")
}

// Normalize returns the representation used for persistence and request hashing.
// It is called only after Validate; it never changes submitted source bytes.
func (r MetadataVersionRequest) Normalize() MetadataVersionRequest {
	tags := make(Array[string], 0, len(r.Tags))
	seen := map[string]bool{}
	for _, t := range r.Tags {
		s := strings.TrimSpace(t)
		if !seen[s] {
			tags = append(tags, s)
			seen[s] = true
		}
	}
	r.Tags = tags
	return r
}

func ValidPackagePath(p string) bool {
	if len(p) > 4096 || !utf8.ValidString(p) || !strings.HasPrefix(p, "problems/") || p == "problems/" || path.Clean(p) != p || strings.ContainsAny(p, "\\:\x00") || strings.IndexFunc(p, unicode.IsControl) >= 0 {
		return false
	}
	for strings.Contains(p, "%") {
		lower := strings.ToLower(p)
		if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
			return false
		}
		decoded, e := url.PathUnescape(p)
		if e != nil || !utf8.ValidString(decoded) || strings.IndexFunc(decoded, unicode.IsControl) >= 0 {
			return false
		}
		for _, segment := range strings.Split(decoded, "/") {
			if segment == "." || segment == ".." {
				return false
			}
		}
		if decoded == p {
			break
		}
		p = decoded
	}
	return true
}
func (r PublishRequest) Validate() error { return validateAll(r.RequestID, r.ProblemVersionID) }
func (r WithdrawRequest) Validate() error {
	if e := r.RequestID.Validate(); e != nil {
		return e
	}
	if !utf8.ValidString(r.Reason) || utf8.RuneCountInString(r.Reason) < 1 || utf8.RuneCountInString(r.Reason) > 500 {
		return Invalid("reason")
	}
	return nil
}

func (b TaskBase) Validate() error {
	if e := validateAll(b.RequestID, b.Revision, b.CreatedAt, b.UpdatedAt); e != nil {
		return e
	}
	if b.Revision < 1 {
		return Invalid("revision")
	}
	created, _ := time.Parse(time.RFC3339Nano, string(b.CreatedAt))
	updated, _ := time.Parse(time.RFC3339Nano, string(b.UpdatedAt))
	if updated.Before(created) {
		return Invalid("updatedAt")
	}
	if b.FinishedAt != nil {
		if e := b.FinishedAt.Validate(); e != nil {
			return e
		}
		finished, _ := time.Parse(time.RFC3339Nano, string(*b.FinishedAt))
		if finished.Before(created) || finished.After(updated) {
			return Invalid("finishedAt")
		}
	}
	if b.Error != nil && (b.Error.Code == "" || b.Error.Message == "" || !utf8.ValidString(b.Error.Message)) {
		return Invalid("error")
	}
	return nil
}
func (r JudgeResult) Validate() error {
	if e := validateAll(r.PassedTestCount, r.TotalTestCount, r.JudgedAt); e != nil {
		return e
	}
	if r.PassedTestCount > r.TotalTestCount || r.Score != nil {
		return Invalid("result")
	}
	for _, n := range []*SafeInt{r.TimeMs, r.MemoryBytes} {
		if n != nil {
			if e := n.Validate(); e != nil {
				return e
			}
		}
	}
	if r.CompileLog != nil && (!utf8.ValidString(*r.CompileLog) || len(*r.CompileLog) > MaxCompileLogBytes) {
		return Invalid("compileLog")
	}
	switch r.Verdict {
	case VerdictAC:
		if r.PassedTestCount != r.TotalTestCount {
			return Invalid("passedTestCount")
		}
	case VerdictCE:
		if r.PassedTestCount != 0 || r.TimeMs != nil || r.MemoryBytes != nil {
			return Invalid("result")
		}
	case VerdictWA, VerdictTLE, VerdictMLE, VerdictRE, VerdictOLE, VerdictIE:
	default:
		return Invalid("verdict")
	}
	return nil
}
func (r JudgeTask) Validate() error {
	if e := validateAll(r.TaskBase, r.JudgeTaskID, r.SubmissionID); e != nil {
		return e
	}
	if r.Result != nil {
		if e := r.Result.Validate(); e != nil {
			return e
		}
	}
	switch r.Status {
	case JudgeQueued, JudgeDispatching, JudgeRunning:
		if r.Error != nil || r.Result != nil || r.FinishedAt != nil {
			return Invalid("status")
		}
	case JudgeCompleted:
		if r.Error != nil || r.Result == nil || r.Result.Verdict == VerdictIE || r.FinishedAt == nil {
			return Invalid("status")
		}
	case JudgeFailed:
		if r.Error == nil || r.Result == nil || r.Result.Verdict != VerdictIE || r.FinishedAt == nil {
			return Invalid("status")
		}
	case JudgeCancelled:
		if r.Error == nil || r.Result != nil || r.FinishedAt == nil {
			return Invalid("status")
		}
	default:
		return Invalid("status")
	}
	return nil
}
func (e CallbackEvent[T]) Validate() error {
	if err := validateAll(e.EventID, e.OccurredAt, e.RequestID, e.AggregateID, e.Revision); err != nil {
		return err
	}
	task, ok := any(e.Payload).(JudgeTask)
	if !ok || e.EventType != "JUDGE_TASK_UPDATED" || e.AggregateID != task.JudgeTaskID || e.RequestID != task.RequestID || e.Revision != task.Revision {
		return Invalid("event")
	}
	return task.Validate()
}
