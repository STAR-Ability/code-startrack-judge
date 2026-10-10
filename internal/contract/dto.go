package contract

type ApiResponse[T any] struct {
	Data      T    `json:"data"`
	RequestID UUID `json:"requestId"`
}
type PageMeta struct {
	Page     SafeInt `json:"page"`
	PageSize SafeInt `json:"pageSize"`
	Total    SafeInt `json:"total"`
	HasNext  bool    `json:"hasNext"`
}
type PageResponse[T any] struct {
	Data      Array[T] `json:"data"`
	Meta      PageMeta `json:"meta"`
	RequestID UUID     `json:"requestId"`
}
type ErrorDetail struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details"`
}
type ApiError struct {
	Error     ErrorDetail `json:"error"`
	RequestID UUID        `json:"requestId"`
}
type TaskError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}
type TaskBase struct {
	RequestID  UUID       `json:"requestId"`
	Revision   SafeInt    `json:"revision"`
	Status     string     `json:"status"`
	Error      *TaskError `json:"error" nullable:"true"`
	CreatedAt  Instant    `json:"createdAt"`
	UpdatedAt  Instant    `json:"updatedAt"`
	FinishedAt *Instant   `json:"finishedAt" nullable:"true"`
}
type ProblemSource string
type Platform string
type DifficultyScale string
type PlatformProblemStatus string
type ImportStatus string
type JudgeStatus string
type JudgeVerdict string

const (
	SourcePlatform     ProblemSource         = "PLATFORM"
	SourceExternal     ProblemSource         = "EXTERNAL"
	PlatformStartrack  Platform              = "startrack"
	PlatformCodeforces Platform              = "codeforces"
	DifficultyCF       DifficultyScale       = "CF_RATING"
	DifficultyPlatform DifficultyScale       = "PLATFORM_RATING"
	DifficultyUnrated  DifficultyScale       = "UNRATED"
	ProblemDraft       PlatformProblemStatus = "DRAFT"
	ProblemPublished   PlatformProblemStatus = "PUBLISHED"
	ProblemWithdrawn   PlatformProblemStatus = "WITHDRAWN"
	ImportQueued       ImportStatus          = "QUEUED"
	ImportRunning      ImportStatus          = "RUNNING"
	ImportSucceeded    ImportStatus          = "SUCCEEDED"
	ImportPartial      ImportStatus          = "PARTIAL"
	ImportFailed       ImportStatus          = "FAILED"
	JudgeQueued        JudgeStatus           = "QUEUED"
	JudgeDispatching   JudgeStatus           = "DISPATCHING"
	JudgeRunning       JudgeStatus           = "RUNNING"
	JudgeCompleted     JudgeStatus           = "COMPLETED"
	JudgeFailed        JudgeStatus           = "FAILED"
	JudgeCancelled     JudgeStatus           = "CANCELLED"
	VerdictAC          JudgeVerdict          = "AC"
	VerdictWA          JudgeVerdict          = "WA"
	VerdictTLE         JudgeVerdict          = "TLE"
	VerdictMLE         JudgeVerdict          = "MLE"
	VerdictRE          JudgeVerdict          = "RE"
	VerdictCE          JudgeVerdict          = "CE"
	VerdictOLE         JudgeVerdict          = "OLE"
	VerdictIE          JudgeVerdict          = "IE"
)

type ProblemRef struct {
	Source           ProblemSource `json:"source"`
	Platform         Platform      `json:"platform"`
	ProblemID        ID            `json:"problemId"`
	ProblemVersionID *UUID         `json:"problemVersionId" nullable:"true"`
}
type ProblemSummary struct {
	ProblemRef      ProblemRef      `json:"problemRef"`
	Title           *string         `json:"title" nullable:"true"`
	Difficulty      *SafeInt        `json:"difficulty" nullable:"true"`
	DifficultyScale DifficultyScale `json:"difficultyScale"`
	Tags            Array[string]   `json:"tags"`
	URL             *string         `json:"url" nullable:"true"`
}

// PlatformProblemRef narrows the non-null platform version required by summaries.
type PlatformProblemRef struct {
	Source           ProblemSource `json:"source"`
	Platform         Platform      `json:"platform"`
	ProblemID        ID            `json:"problemId"`
	ProblemVersionID UUID          `json:"problemVersionId"`
}
type PlatformProblemSummary struct {
	ProblemRef       PlatformProblemRef    `json:"problemRef"`
	Title            *string               `json:"title" nullable:"true"`
	Difficulty       *SafeInt              `json:"difficulty" nullable:"true"`
	DifficultyScale  DifficultyScale       `json:"difficultyScale"`
	Tags             Array[string]         `json:"tags"`
	URL              *string               `json:"url" nullable:"true"`
	Status           PlatformProblemStatus `json:"status"`
	CatalogVersion   ID                    `json:"catalogVersion"`
	TimeLimitMs      SafeInt               `json:"timeLimitMs"`
	MemoryLimitBytes SafeInt               `json:"memoryLimitBytes"`
	LanguageIDs      Array[string]         `json:"languageIds"`
	UpdatedAt        Instant               `json:"updatedAt"`
}
type Statement struct {
	Format  string  `json:"format"`
	Content string  `json:"content"`
	Input   *string `json:"input" nullable:"true"`
	Output  *string `json:"output" nullable:"true"`
}
type Sample struct {
	Input  string `json:"input"`
	Output string `json:"output"`
}
type License struct {
	SPDXID    *string `json:"spdxId" nullable:"true"`
	Notice    string  `json:"notice"`
	SourceURL string  `json:"sourceUrl"`
}
type PlatformProblemDetail struct {
	PlatformProblemSummary
	Statement Statement     `json:"statement"`
	Samples   Array[Sample] `json:"samples"`
	License   License       `json:"license"`
}
type CatalogEntry struct {
	Problem ProblemSummary        `json:"problem"`
	Status  PlatformProblemStatus `json:"status"`
}
type CatalogSnapshotPage struct {
	SnapshotID     UUID                `json:"snapshotId"`
	CatalogVersion ID                  `json:"catalogVersion"`
	Items          Array[CatalogEntry] `json:"items"`
	NextCursor     *string             `json:"nextCursor" nullable:"true"`
	ExpiresAt      Instant             `json:"expiresAt"`
}
type LanguageCapability struct {
	LanguageID        string `json:"languageId"`
	DisplayName       string `json:"displayName"`
	LanguageFamily    string `json:"languageFamily"`
	CompilerVersion   string `json:"compilerVersion"`
	SourceFilename    string `json:"sourceFilename"`
	AnalysisSupported bool   `json:"analysisSupported"`
}
type LanguageCapabilities struct {
	Languages         Array[LanguageCapability] `json:"languages"`
	CapabilityVersion string                    `json:"capabilityVersion"`
}
type ImportItem struct {
	PackagePath      string           `json:"packagePath"`
	Status           string           `json:"status"`
	ProblemID        *ID              `json:"problemId" nullable:"true"`
	ProblemVersionID *UUID            `json:"problemVersionId" nullable:"true"`
	LicenseStatus    string           `json:"licenseStatus"`
	ValidationStatus string           `json:"validationStatus"`
	Errors           Array[TaskError] `json:"errors"`
}
type ImportJob struct {
	TaskBase
	ImportJobID           UUID              `json:"importJobId"`
	Status                ImportStatus      `json:"status"`
	Source                string            `json:"source"`
	RepositoryURL         string            `json:"repositoryUrl"`
	SourceRevision        string            `json:"sourceRevision"`
	PackageCount          SafeInt           `json:"packageCount"`
	CompletedPackageCount SafeInt           `json:"completedPackageCount"`
	Items                 Array[ImportItem] `json:"items"`
}
type JudgeResult struct {
	Verdict         JudgeVerdict `json:"verdict"`
	TimeMs          *SafeInt     `json:"timeMs" nullable:"true"`
	MemoryBytes     *SafeInt     `json:"memoryBytes" nullable:"true"`
	PassedTestCount SafeInt      `json:"passedTestCount"`
	TotalTestCount  SafeInt      `json:"totalTestCount"`
	Score           *float64     `json:"score" nullable:"true"`
	CompileLog      *string      `json:"compileLog" nullable:"true"`
	DiagnosticCode  *string      `json:"diagnosticCode" nullable:"true"`
	JudgedAt        Instant      `json:"judgedAt"`
}
type JudgeTask struct {
	TaskBase
	JudgeTaskID  UUID         `json:"judgeTaskId"`
	SubmissionID ID           `json:"submissionId"`
	Status       JudgeStatus  `json:"status"`
	Result       *JudgeResult `json:"result" nullable:"true"`
}
type JudgeTaskRequest struct {
	RequestID    UUID       `json:"requestId"`
	SubmissionID ID         `json:"submissionId"`
	ProblemRef   ProblemRef `json:"problemRef"`
	LanguageID   string     `json:"languageId"`
	SourceCode   string     `json:"sourceCode"`
	SourceSHA256 string     `json:"sourceSha256"`
}
type ByRequestRequest struct {
	RequestIDs Array[UUID] `json:"requestIds"`
}
type ByRequestResponse struct {
	Tasks             Array[JudgeTask] `json:"tasks"`
	MissingRequestIDs Array[UUID]      `json:"missingRequestIds"`
}
type ImportRequest struct {
	RequestID     UUID          `json:"requestId"`
	Source        string        `json:"source"`
	RepositoryURL string        `json:"repositoryUrl"`
	Revision      string        `json:"revision"`
	PackagePaths  Array[string] `json:"packagePaths"`
}
type MetadataVersionRequest struct {
	RequestID            UUID            `json:"requestId"`
	BaseProblemVersionID UUID            `json:"baseProblemVersionId"`
	Tags                 Array[string]   `json:"tags"`
	Difficulty           *SafeInt        `json:"difficulty" nullable:"true"`
	DifficultyScale      DifficultyScale `json:"difficultyScale"`
}
type PublishRequest struct {
	RequestID        UUID `json:"requestId"`
	ProblemVersionID UUID `json:"problemVersionId"`
}
type WithdrawRequest struct {
	RequestID UUID   `json:"requestId"`
	Reason    string `json:"reason"`
}
type WithdrawResponse struct {
	ProblemID      ID                    `json:"problemId"`
	Status         PlatformProblemStatus `json:"status"`
	CatalogVersion ID                    `json:"catalogVersion"`
}
type CallbackEvent[T any] struct {
	EventID     UUID    `json:"eventId"`
	EventType   string  `json:"eventType"`
	OccurredAt  Instant `json:"occurredAt"`
	RequestID   UUID    `json:"requestId"`
	AggregateID UUID    `json:"aggregateId"`
	Revision    SafeInt `json:"revision"`
	Payload     T       `json:"payload"`
}
type CallbackAck struct {
	Accepted  bool `json:"accepted"`
	Duplicate bool `json:"duplicate"`
}
type HealthCapabilities struct {
	Catalog bool `json:"catalog"`
	Judge   bool `json:"judge"`
	Imports bool `json:"imports"`
}
type Health struct {
	Status          string             `json:"status"`
	Service         string             `json:"service"`
	ContractVersion string             `json:"contractVersion"`
	Capabilities    HealthCapabilities `json:"capabilities"`
}

func (r JudgeTaskRequest) BodyRequestID() UUID       { return r.RequestID }
func (r ImportRequest) BodyRequestID() UUID          { return r.RequestID }
func (r MetadataVersionRequest) BodyRequestID() UUID { return r.RequestID }
func (r PublishRequest) BodyRequestID() UUID         { return r.RequestID }
func (r WithdrawRequest) BodyRequestID() UUID        { return r.RequestID }
func (r CallbackEvent[T]) BodyRequestID() UUID       { return r.RequestID }
