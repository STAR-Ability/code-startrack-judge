package httpapi

import (
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
)

type Pagination struct {
	Page     contract.SafeInt
	PageSize contract.SafeInt
	Offset   int64
}
type ProblemListQuery struct {
	Pagination
	Q             *string
	Tag           *string
	MinDifficulty *contract.SafeInt
	MaxDifficulty *contract.SafeInt
	Status        contract.PlatformProblemStatus
}
type SnapshotQuery struct {
	Cursor *string
	Limit  contract.SafeInt
}

// ParseQuery rejects malformed escapes, duplicate and unknown parameters. It
// must be used instead of URL.Query, which silently drops malformed parameters.
func ParseQuery(raw string, allowed ...string) (url.Values, error) {
	values, e := url.ParseQuery(raw)
	if e != nil {
		return nil, contract.Invalid("query")
	}
	names := map[string]bool{}
	for _, s := range allowed {
		names[s] = true
	}
	for name, list := range values {
		if !names[name] || len(list) != 1 || !utf8.ValidString(name) || !utf8.ValidString(list[0]) {
			return nil, contract.Invalid("query")
		}
	}
	return values, nil
}
func unsigned(values url.Values, name string, def, min, max int64) (contract.SafeInt, error) {
	list, ok := values[name]
	if !ok {
		return contract.SafeInt(def), nil
	}
	s := list[0]
	if s == "" {
		return 0, contract.Invalid(name)
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, contract.Invalid(name)
		}
	}
	n, e := strconv.ParseInt(s, 10, 64)
	if e != nil || n < min || n > max {
		return 0, contract.Invalid(name)
	}
	return contract.SafeInt(n), nil
}
func pagination(values url.Values) (Pagination, error) {
	p, e := unsigned(values, "page", 1, 1, contract.MaxSafeInteger)
	if e != nil {
		return Pagination{}, e
	}
	s, e := unsigned(values, "pageSize", 20, 1, 100)
	if e != nil {
		return Pagination{}, e
	}
	if int64(p) > contract.MaxSafeInteger/int64(s) {
		return Pagination{}, contract.Invalid("page")
	}
	return Pagination{Page: p, PageSize: s, Offset: int64(p-1) * int64(s)}, nil
}
func ParsePagination(raw string) (Pagination, error) {
	v, e := ParseQuery(raw, "page", "pageSize")
	if e != nil {
		return Pagination{}, e
	}
	return pagination(v)
}
func PageMeta(p Pagination, total contract.SafeInt) (contract.PageMeta, error) {
	if e := total.Validate(); e != nil {
		return contract.PageMeta{}, e
	}
	if p.Page < 1 || p.PageSize < 1 || p.PageSize > 100 || int64(p.Page) > contract.MaxSafeInteger/int64(p.PageSize) {
		return contract.PageMeta{}, contract.Invalid("page")
	}
	return contract.PageMeta{Page: p.Page, PageSize: p.PageSize, Total: total, HasNext: p.Page*p.PageSize < total}, nil
}
func ParseProblemListQuery(raw string) (ProblemListQuery, error) {
	v, e := ParseQuery(raw, "page", "pageSize", "q", "tag", "minDifficulty", "maxDifficulty", "status")
	if e != nil {
		return ProblemListQuery{}, e
	}
	p, e := pagination(v)
	if e != nil {
		return ProblemListQuery{}, e
	}
	out := ProblemListQuery{Pagination: p, Status: contract.ProblemPublished}
	if s, ok := v["q"]; ok {
		q := strings.TrimSpace(s[0])
		if utf8.RuneCountInString(q) < 1 || utf8.RuneCountInString(q) > 100 {
			return out, contract.Invalid("q")
		}
		out.Q = &q
	}
	if s, ok := v["tag"]; ok {
		tag := s[0]
		if utf8.RuneCountInString(tag) < 1 || utf8.RuneCountInString(tag) > 128 {
			return out, contract.Invalid("tag")
		}
		out.Tag = &tag
	}
	if _, ok := v["minDifficulty"]; ok {
		n, e := unsigned(v, "minDifficulty", 0, 1, contract.MaxSafeInteger)
		if e != nil {
			return out, e
		}
		out.MinDifficulty = &n
	}
	if _, ok := v["maxDifficulty"]; ok {
		n, e := unsigned(v, "maxDifficulty", 0, 1, contract.MaxSafeInteger)
		if e != nil {
			return out, e
		}
		out.MaxDifficulty = &n
	}
	if out.MinDifficulty != nil && out.MaxDifficulty != nil && *out.MinDifficulty > *out.MaxDifficulty {
		return out, contract.Invalid("difficulty")
	}
	if s, ok := v["status"]; ok {
		out.Status = contract.PlatformProblemStatus(s[0])
		switch out.Status {
		case contract.ProblemPublished, contract.ProblemDraft, contract.ProblemWithdrawn:
		default:
			return out, contract.Invalid("status")
		}
	}
	return out, nil
}
func ParseSnapshotQuery(raw string) (SnapshotQuery, error) {
	v, e := ParseQuery(raw, "cursor", "limit")
	if e != nil {
		return SnapshotQuery{}, e
	}
	n, e := unsigned(v, "limit", 100, 1, 1000)
	if e != nil {
		return SnapshotQuery{}, e
	}
	out := SnapshotQuery{Limit: n}
	if s, ok := v["cursor"]; ok {
		if s[0] == "" || len(s[0]) > 8192 {
			return out, contract.Invalid("cursor")
		}
		out.Cursor = &s[0]
	}
	return out, nil
}
