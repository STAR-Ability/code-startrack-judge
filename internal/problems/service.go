// Package problems implements versioned, public-safe problem management. ADMIN
// user authorization stays at Backend; license approval has a distinct offline
// operator boundary and is never inferred from import metadata.
package problems

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	persistence "github.com/STAR-Ability/code-startrack-judge/internal/persistence/problems"
)

type Error = persistence.WorkflowError
type Pagination struct{ Page, PageSize contract.SafeInt }
type ListQuery struct {
	Pagination
	Q, Tag                       *string
	MinDifficulty, MaxDifficulty *contract.SafeInt
	Status                       contract.PlatformProblemStatus
}
type Options struct {
	FreshReady func(context.Context) bool
	// LanguageCapabilities returns the currently qualified public language IDs.
	// An absent provider leaves the persisted active-language projection intact.
	LanguageCapabilities func(context.Context) contract.Array[string]
}
type Service struct {
	repo    *persistence.Repository
	options Options
}

func New(repo *persistence.Repository, options Options) *Service {
	return &Service{repo: repo, options: options}
}

func (s *Service) languageSnapshot(ctx context.Context) map[string]struct{} {
	if s.options.LanguageCapabilities == nil {
		return nil
	}
	languages := s.options.LanguageCapabilities(ctx)
	available := make(map[string]struct{}, len(languages))
	for _, language := range languages {
		available[language] = struct{}{}
	}
	return available
}

func filterLanguages(summary *contract.PlatformProblemSummary, available map[string]struct{}) {
	if available == nil {
		return
	}
	languages := make(contract.Array[string], 0, len(summary.LanguageIDs))
	for _, language := range summary.LanguageIDs {
		if _, ok := available[language]; ok {
			languages = append(languages, language)
		}
	}
	summary.LanguageIDs = languages
}

func checkPage(p Pagination) error {
	if p.Page < 1 || p.PageSize < 1 || p.PageSize > 100 || int64(p.Page) > contract.MaxSafeInteger/int64(p.PageSize) {
		return contract.Invalid("page")
	}
	return nil
}
func bounded(err error) error {
	if err == nil {
		return nil
	}
	var domain *Error
	var validation *contract.ValidationError
	if errors.As(err, &domain) || errors.As(err, &validation) {
		return err
	}
	if errors.Is(err, persistence.ErrPublicNotFound) {
		return &Error{Code: "PROBLEM_NOT_FOUND"}
	}
	return &Error{Code: "INTERNAL_ERROR"}
}

func (s *Service) List(ctx context.Context, q ListQuery) (contract.Array[contract.PlatformProblemSummary], contract.PageMeta, error) {
	if err := checkPage(q.Pagination); err != nil {
		return nil, contract.PageMeta{}, err
	}
	if q.Status == "" {
		q.Status = contract.ProblemPublished
	}
	if err := q.Status.Validate(); err != nil {
		return nil, contract.PageMeta{}, err
	}
	if q.Q != nil {
		value := strings.TrimSpace(*q.Q)
		if !utf8.ValidString(value) || utf8.RuneCountInString(value) < 1 || utf8.RuneCountInString(value) > 100 {
			return nil, contract.PageMeta{}, contract.Invalid("q")
		}
		q.Q = &value
	}
	if q.Tag != nil && (!utf8.ValidString(*q.Tag) || utf8.RuneCountInString(*q.Tag) < 1 || utf8.RuneCountInString(*q.Tag) > 128) {
		return nil, contract.PageMeta{}, contract.Invalid("tag")
	}
	for _, v := range []*contract.SafeInt{q.MinDifficulty, q.MaxDifficulty} {
		if v != nil && (*v < 1 || v.Validate() != nil) {
			return nil, contract.PageMeta{}, contract.Invalid("difficulty")
		}
	}
	if q.MinDifficulty != nil && q.MaxDifficulty != nil && *q.MinDifficulty > *q.MaxDifficulty {
		return nil, contract.PageMeta{}, contract.Invalid("difficulty")
	}
	items, meta, err := s.repo.PublicList(ctx, persistence.PublicQuery{Page: q.Page, PageSize: q.PageSize, Q: q.Q, Tag: q.Tag, MinDifficulty: q.MinDifficulty, MaxDifficulty: q.MaxDifficulty, Status: q.Status})
	if err == nil {
		available := s.languageSnapshot(ctx)
		for i := range items {
			filterLanguages(&items[i], available)
		}
	}
	return items, meta, bounded(err)
}
func (s *Service) Current(ctx context.Context, id contract.ID) (contract.PlatformProblemDetail, error) {
	if err := id.Validate(); err != nil {
		return contract.PlatformProblemDetail{}, err
	}
	out, err := s.repo.PublicDetail(ctx, id, nil, true)
	if err == nil {
		filterLanguages(&out.PlatformProblemSummary, s.languageSnapshot(ctx))
	}
	return out, bounded(err)
}
func (s *Service) Version(ctx context.Context, id contract.ID, versionID contract.UUID) (contract.PlatformProblemDetail, error) {
	if err := id.Validate(); err != nil {
		return contract.PlatformProblemDetail{}, err
	}
	if err := versionID.Validate(); err != nil {
		return contract.PlatformProblemDetail{}, err
	}
	out, err := s.repo.PublicDetail(ctx, id, &versionID, false)
	if err == nil {
		filterLanguages(&out.PlatformProblemSummary, s.languageSnapshot(ctx))
	}
	return out, bounded(err)
}
func (s *Service) History(ctx context.Context, id contract.ID, p Pagination) (contract.Array[contract.PlatformProblemSummary], contract.PageMeta, error) {
	if err := id.Validate(); err != nil {
		return nil, contract.PageMeta{}, err
	}
	if err := checkPage(p); err != nil {
		return nil, contract.PageMeta{}, err
	}
	items, meta, err := s.repo.PublicHistory(ctx, id, p.Page, p.PageSize)
	if err == nil {
		available := s.languageSnapshot(ctx)
		for i := range items {
			filterLanguages(&items[i], available)
		}
	}
	return items, meta, bounded(err)
}

func requestHash(operation string, id contract.ID, body any) (string, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	value := string(id)
	return canonical.RequestHash(operation, &value, raw)
}

func (s *Service) Metadata(ctx context.Context, id contract.ID, req contract.MetadataVersionRequest) (contract.PlatformProblemDetail, bool, error) {
	var out contract.PlatformProblemDetail
	if err := id.Validate(); err != nil {
		return out, false, err
	}
	if err := req.Validate(); err != nil {
		return out, false, err
	}
	req = req.Normalize()
	req.RequestID = contract.UUID(strings.ToLower(string(req.RequestID)))
	req.BaseProblemVersionID = contract.UUID(strings.ToLower(string(req.BaseProblemVersionID)))
	hash, err := requestHash("METADATA_VERSION", id, req)
	if err != nil {
		return out, false, bounded(err)
	}
	result, err := s.repo.Operation(ctx, "METADATA_VERSION", req.RequestID, hash, id, s.options.FreshReady, func(tx *persistence.Tx) (any, error) {
		if _, err := tx.LoadProblem(id, true); errors.Is(err, persistence.ErrNotFound) {
			return nil, &Error{Code: "PROBLEM_NOT_FOUND"}
		} else if err != nil {
			return nil, err
		}
		base, err := tx.LoadVersion(id, req.BaseProblemVersionID)
		if errors.Is(err, persistence.ErrNotFound) {
			return nil, &Error{Code: "PROBLEM_VERSION_CONFLICT"}
		}
		if err != nil {
			return nil, err
		}
		spec := base.Spec
		spec.BaseVersionID = &base.ID
		spec.Tags = append([]string{}, req.Tags...)
		spec.DifficultyScale = req.DifficultyScale
		spec.Difficulty = nil
		spec.RatingBasis = nil
		if req.Difficulty != nil {
			value := int64(*req.Difficulty)
			spec.Difficulty = &value
			basis := "MANUAL:" + string(req.RequestID)
			spec.RatingBasis = &basis
		}
		version, err := tx.CreateVersion(spec)
		if errors.Is(err, persistence.ErrDetailTooLarge) {
			return nil, &Error{Code: "INVALID_ARGUMENT"}
		}
		if err != nil {
			return nil, err
		}
		detail, err := tx.PublicDetail(id, &version.ID, false)
		if err != nil {
			return nil, err
		}
		filterLanguages(&detail.PlatformProblemSummary, s.languageSnapshot(ctx))
		return detail, nil
	})
	if err != nil {
		return out, result.Replay, bounded(err)
	}
	if err := json.Unmarshal(result.Result, &out); err != nil {
		return out, result.Replay, bounded(err)
	}
	return out, result.Replay, nil
}
func (s *Service) Publish(ctx context.Context, id contract.ID, req contract.PublishRequest) (contract.PlatformProblemDetail, error) {
	var out contract.PlatformProblemDetail
	if err := id.Validate(); err != nil {
		return out, err
	}
	if err := req.Validate(); err != nil {
		return out, err
	}
	req.RequestID = contract.UUID(strings.ToLower(string(req.RequestID)))
	req.ProblemVersionID = contract.UUID(strings.ToLower(string(req.ProblemVersionID)))
	hash, err := requestHash("PUBLISH", id, req)
	if err != nil {
		return out, bounded(err)
	}
	result, err := s.repo.Operation(ctx, "PUBLISH", req.RequestID, hash, id, s.options.FreshReady, func(tx *persistence.Tx) (any, error) {
		detail, err := tx.PublishVersion(id, req.ProblemVersionID)
		if err != nil {
			return nil, err
		}
		filterLanguages(&detail.PlatformProblemSummary, s.languageSnapshot(ctx))
		return detail, nil
	})
	if err != nil {
		return out, bounded(err)
	}
	if err := json.Unmarshal(result.Result, &out); err != nil {
		return out, bounded(err)
	}
	return out, nil
}
func (s *Service) Withdraw(ctx context.Context, id contract.ID, req contract.WithdrawRequest) (contract.WithdrawResponse, error) {
	var out contract.WithdrawResponse
	if err := id.Validate(); err != nil {
		return out, err
	}
	if err := req.Validate(); err != nil {
		return out, err
	}
	req.RequestID = contract.UUID(strings.ToLower(string(req.RequestID)))
	hash, err := requestHash("WITHDRAW", id, req)
	if err != nil {
		return out, bounded(err)
	}
	result, err := s.repo.Operation(ctx, "WITHDRAW", req.RequestID, hash, id, s.options.FreshReady, func(tx *persistence.Tx) (any, error) { return tx.WithdrawProblem(id, req.Reason) })
	if err != nil {
		return out, bounded(err)
	}
	if err := json.Unmarshal(result.Result, &out); err != nil {
		return out, bounded(err)
	}
	return out, nil
}
