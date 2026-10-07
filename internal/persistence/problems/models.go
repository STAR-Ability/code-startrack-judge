// Package problems persists judge-owned immutable problem facts. It does not
// authorize administrators, publish imports, or own backend business data.
package problems

import (
	"encoding/json"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/storage"
)

type Identity struct {
	Source        string
	RepositoryURL string
	PackagePath   string
}

type Problem struct {
	ID               contract.ID
	Identity         Identity
	Status           contract.PlatformProblemStatus
	CurrentVersionID *contract.UUID
	LatestVersionID  *contract.UUID
	CreatedAt        time.Time
	UpdatedAt        time.Time
	PublicUpdatedAt  *time.Time
	WithdrawnAt      *time.Time
	WithdrawalReason *string
}

type ValidationContext struct {
	ProblemtoolsVersion string `json:"problemtoolsVersion"`
	AdapterVersion      string `json:"adapterVersion"`
	ToolchainVersion    string `json:"toolchainVersion"`
	ImageDigest         string `json:"imageDigest"`
	ConfigSHA256        string `json:"configSha256"`
	SourceSHA256        string `json:"sourceSha256"`
	NormalizedSHA256    string `json:"normalizedSha256"`
}

// ArtifactSpec binds byte-derived content independently from approved license
// and qualification evidence. Repeated registration never edits existing rows.
type ArtifactSpec struct {
	ProblemID         contract.ID
	Identity          Identity
	SourceRevision    string
	AdapterVersion    string
	SourceArchive     storage.Object
	NormalizedArchive storage.Object
	Manifest          json.RawMessage
	SourceMetadata    json.RawMessage
	LicenseEvidenceID contract.UUID
	ValidationContext ValidationContext
}

type Artifact struct {
	ID                contract.UUID
	ContentIdentityID contract.UUID
	SourceIdentityID  contract.UUID
	Spec              ArtifactSpec
	ManifestSHA256    string
	EvidenceSetHash   string
	ValidationRunID   *contract.UUID
	CreatedAt         time.Time
}

type VersionSpec struct {
	ProblemID         contract.ID              `json:"-"`
	PackageArtifactID contract.UUID            `json:"packageArtifactId"`
	BaseVersionID     *contract.UUID           `json:"-"`
	Title             string                   `json:"title"`
	StatementFormat   string                   `json:"statementFormat"`
	StatementContent  string                   `json:"statementContent"`
	StatementInput    *string                  `json:"statementInput"`
	StatementOutput   *string                  `json:"statementOutput"`
	Samples           []contract.Sample        `json:"samples"`
	Tags              []string                 `json:"tags"`
	Difficulty        *int64                   `json:"difficulty"`
	DifficultyScale   contract.DifficultyScale `json:"difficultyScale"`
	RatingBasis       *string                  `json:"ratingBasis"`
	TimeLimitMs       int64                    `json:"timeLimitMs"`
	WallLimitMs       int64                    `json:"wallLimitMs"`
	MemoryLimitBytes  int64                    `json:"memoryLimitBytes"`
	OutputLimitBytes  int64                    `json:"outputLimitBytes"`
	LanguageIDs       []string                 `json:"languageIds"`
	JudgeMode         string                   `json:"judgeMode"`
	CheckerConfig     json.RawMessage          `json:"checkerConfig"`
}

type Version struct {
	ID               contract.UUID
	VersionNumber    int64
	Spec             VersionSpec
	MetadataHash     string
	FirstPublishedAt *time.Time
	CreatedAt        time.Time
}

type TestCase struct {
	ID                contract.UUID
	PackageArtifactID contract.UUID
	Ordinal           int64
	Visibility        string
	Input             storage.Object
	Answer            storage.Object
	ValidationGroup   *string
}

type ReferenceSolution struct {
	ID                contract.UUID
	PackageArtifactID contract.UUID
	Role              string
	LanguageID        string
	Source            storage.Object
	UpstreamPath      string
}

// ValidationRun is a completed immutable qualification record. Runtime work
// finishes outside SQL; this record joins the fenced artifact acceptance tx.
type ValidationRun struct {
	ID                contract.UUID
	PackageArtifactID contract.UUID
	Status            string
	Context           ValidationContext
	Results           json.RawMessage
	Errors            []contract.TaskError
	Adaptations       json.RawMessage
	Log               *storage.Object
	EvidenceLogs      []storage.Object
	StartedAt         time.Time
	FinishedAt        time.Time
	CreatedAt         time.Time
}
