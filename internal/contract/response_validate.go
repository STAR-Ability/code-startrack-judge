package contract

import "strings"

func (v ProblemSource) Validate() error {
	if v != SourcePlatform && v != SourceExternal {
		return Invalid("source")
	}
	return nil
}
func (v Platform) Validate() error {
	if v != PlatformStartrack && v != PlatformCodeforces {
		return Invalid("platform")
	}
	return nil
}
func (v DifficultyScale) Validate() error {
	switch v {
	case DifficultyCF, DifficultyPlatform, DifficultyUnrated:
		return nil
	}
	return Invalid("difficultyScale")
}
func (v PlatformProblemStatus) Validate() error {
	switch v {
	case ProblemDraft, ProblemPublished, ProblemWithdrawn:
		return nil
	}
	return Invalid("status")
}
func (v ImportStatus) Validate() error {
	switch v {
	case ImportQueued, ImportRunning, ImportSucceeded, ImportPartial, ImportFailed:
		return nil
	}
	return Invalid("status")
}
func (v JudgeStatus) Validate() error {
	switch v {
	case JudgeQueued, JudgeDispatching, JudgeRunning, JudgeCompleted, JudgeFailed, JudgeCancelled:
		return nil
	}
	return Invalid("status")
}
func (v JudgeVerdict) Validate() error {
	switch v {
	case VerdictAC, VerdictWA, VerdictTLE, VerdictMLE, VerdictRE, VerdictCE, VerdictOLE, VerdictIE:
		return nil
	}
	return Invalid("verdict")
}

func (m PageMeta) Validate() error {
	if e := validateAll(m.Page, m.PageSize, m.Total); e != nil {
		return e
	}
	if m.Page < 1 || m.PageSize < 1 || m.PageSize > 100 || int64(m.Page) > MaxSafeInteger/int64(m.PageSize) || m.HasNext != (m.Page*m.PageSize < m.Total) {
		return Invalid("meta")
	}
	return nil
}
func (r PlatformProblemRef) Validate() error {
	if e := validateAll(r.ProblemID, r.ProblemVersionID); e != nil {
		return e
	}
	if r.Source != SourcePlatform || r.Platform != PlatformStartrack {
		return &ValidationError{Code: "INVALID_PROBLEM_REF", Field: "problemRef"}
	}
	return nil
}
func (s ProblemSummary) Validate() error {
	if e := validateAll(s.ProblemRef, s.DifficultyScale); e != nil {
		return e
	}
	if s.DifficultyScale == DifficultyUnrated {
		if s.Difficulty != nil {
			return Invalid("difficulty")
		}
	} else {
		if s.Difficulty == nil || *s.Difficulty < 1 {
			return Invalid("difficulty")
		}
	}
	return nil
}
func (s PlatformProblemSummary) Validate() error {
	if e := validateAll(s.ProblemRef, s.Status, s.CatalogVersion, s.TimeLimitMs, s.MemoryLimitBytes, s.UpdatedAt); e != nil {
		return e
	}
	if s.URL != nil || s.TimeLimitMs < 1 || s.MemoryLimitBytes < 1 {
		return Invalid("problem")
	}
	if s.Status != ProblemDraft && (s.Title == nil || strings.TrimSpace(*s.Title) == "") {
		return Invalid("title")
	}
	if s.DifficultyScale == DifficultyUnrated {
		if s.Difficulty != nil {
			return Invalid("difficulty")
		}
	} else if s.DifficultyScale != DifficultyPlatform || s.Difficulty == nil || *s.Difficulty < 1 {
		return Invalid("difficulty")
	}
	for _, language := range s.LanguageIDs {
		if language != "cpp17" {
			return Invalid("languageIds")
		}
	}
	return nil
}
func (c CatalogEntry) Validate() error {
	if c.Status != ProblemPublished && c.Status != ProblemWithdrawn {
		return Invalid("status")
	}
	return c.Problem.Validate()
}
func (s Statement) Validate() error {
	if s.Format != "MARKDOWN" {
		return Invalid("format")
	}
	return nil
}
func (l LanguageCapability) Validate() error {
	if l.LanguageID != "cpp17" || l.LanguageFamily != "CPP" || l.SourceFilename != "main.cpp" || strings.TrimSpace(l.CompilerVersion) == "" || strings.TrimSpace(l.DisplayName) == "" {
		return Invalid("language")
	}
	return nil
}
func (l LanguageCapabilities) Validate() error {
	if l.CapabilityVersion == "" || len(l.Languages) > 1 {
		return Invalid("languages")
	}
	return nil
}
func (i ImportItem) Validate() error {
	switch i.LicenseStatus {
	case "PENDING", "VERIFIED", "MISSING", "REVIEW_REQUIRED":
	default:
		return Invalid("licenseStatus")
	}
	switch i.ValidationStatus {
	case "PENDING", "PASSED", "FAILED":
	default:
		return Invalid("validationStatus")
	}
	if !ValidPackagePath(i.PackagePath) {
		return Invalid("packagePath")
	}
	switch i.Status {
	case "PENDING":
		if i.ProblemID != nil || i.ProblemVersionID != nil || len(i.Errors) != 0 {
			return Invalid("item")
		}
	case "VALIDATED":
		if i.ProblemID == nil || i.ProblemVersionID == nil || i.LicenseStatus != "VERIFIED" || i.ValidationStatus != "PASSED" || len(i.Errors) != 0 {
			return Invalid("item")
		}
	case "REJECTED":
		if i.ProblemID != nil || i.ProblemVersionID != nil || len(i.Errors) == 0 {
			return Invalid("item")
		}
	default:
		return Invalid("status")
	}
	return nil
}
func (j ImportJob) Validate() error {
	if e := validateAll(j.TaskBase, j.ImportJobID, j.Status, j.PackageCount, j.CompletedPackageCount); e != nil {
		return e
	}
	if j.Source != "OJ_LAB" || j.RepositoryURL != PackageRepository || !commitPattern.MatchString(j.SourceRevision) || j.PackageCount < 1 || j.PackageCount > 100 || int64(j.PackageCount) != int64(len(j.Items)) {
		return Invalid("import")
	}
	validated, rejected := 0, 0
	for _, item := range j.Items {
		if e := item.Validate(); e != nil {
			return e
		}
		switch item.Status {
		case "VALIDATED":
			validated++
		case "REJECTED":
			rejected++
		}
	}
	if int64(j.CompletedPackageCount) != int64(validated+rejected) {
		return Invalid("completedPackageCount")
	}
	switch j.Status {
	case ImportQueued, ImportRunning:
		if j.FinishedAt != nil || j.Error != nil {
			return Invalid("status")
		}
	case ImportSucceeded:
		if j.FinishedAt == nil || j.Error != nil || validated != len(j.Items) {
			return Invalid("status")
		}
	case ImportPartial:
		if j.FinishedAt == nil || j.Error == nil || validated == 0 || rejected == 0 || validated+rejected != len(j.Items) {
			return Invalid("status")
		}
	case ImportFailed:
		if j.FinishedAt == nil || j.Error == nil || validated != 0 || rejected != len(j.Items) {
			return Invalid("status")
		}
	}
	return nil
}
