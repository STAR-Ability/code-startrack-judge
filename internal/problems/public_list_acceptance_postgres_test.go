// SPDX-License-Identifier: Apache-2.0

package problems

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	persistence "github.com/STAR-Ability/code-startrack-judge/internal/persistence/problems"
)

// The synthetic qualification facts only admit immutable query fixtures. All
// filtering, pagination, publication, and MVCC reads use actual PostgreSQL.
func TestPostgresPublicListFiltersSortPaginationAndNullDifficulty(t *testing.T) {
	db := isolatedDB(t)
	ctx := context.Background()
	if _, err := db.Exec(strings.Replace(secondProblemFixture, "'Gamma'", "'gAmma 100%_'", 1)); err != nil {
		t.Fatal("cannot register the second isolated query fixture")
	}
	s := New(persistence.New(db, nil), Options{})
	rating := contract.SafeInt(1800)
	for _, item := range []struct {
		id         contract.ID
		base       contract.UUID
		difficulty *contract.SafeInt
		scale      contract.DifficultyScale
		tags       contract.Array[string]
	}{
		{"1", "00000000-0000-0000-0000-000000000011", nil, contract.DifficultyUnrated, contract.Array[string]{"graph"}},
		{"10", "00000000-0000-0000-0000-000000000045", &rating, contract.DifficultyPlatform, contract.Array[string]{"graph", "DP"}},
	} {
		draft, _, err := s.Metadata(ctx, item.id, contract.MetadataVersionRequest{RequestID: uuid(t), BaseProblemVersionID: item.base, Tags: item.tags, Difficulty: item.difficulty, DifficultyScale: item.scale})
		if err != nil {
			t.Fatal("cannot create the isolated query metadata")
		}
		if _, err := s.Publish(ctx, item.id, contract.PublishRequest{RequestID: uuid(t), ProblemVersionID: draft.ProblemRef.ProblemVersionID}); err != nil {
			t.Fatal("cannot publish the isolated query metadata")
		}
	}
	// Use one fixed timestamp to exercise numeric ID tie breaking independently
	// of machine timing. This changes only disposable public-state fixture data.
	if _, err := db.Exec(`UPDATE judge.platform_problems SET public_updated_at='2026-10-08T00:00:00Z' WHERE id IN (1,10)`); err != nil {
		t.Fatal("cannot establish the isolated sorting tie")
	}
	str := func(s string) *string { return &s }
	num := func(n contract.SafeInt) *contract.SafeInt { return &n }
	for _, tc := range []struct {
		name  string
		query ListQuery
		ids   []contract.ID
		total contract.SafeInt
		next  bool
	}{
		{"default published and numeric tie", ListQuery{}, []contract.ID{"10", "1"}, 2, false},
		{"trimmed case insensitive title", ListQuery{Q: str("  GAMMA  ")}, []contract.ID{"10"}, 1, false},
		{"problem number substring", ListQuery{Q: str("1")}, []contract.ID{"10", "1"}, 2, false},
		{"literal percent underscore", ListQuery{Q: str("%_")}, []contract.ID{"10"}, 1, false},
		{"no wildcard expansion", ListQuery{Q: str("A_pha")}, []contract.ID{}, 0, false},
		{"exact tag", ListQuery{Tag: str("DP")}, []contract.ID{"10"}, 1, false},
		{"tag case remains exact", ListQuery{Tag: str("dp")}, []contract.ID{}, 0, false},
		{"tag is not substring", ListQuery{Tag: str("grap")}, []contract.ID{}, 0, false},
		{"inclusive difficulty boundaries exclude null", ListQuery{MinDifficulty: num(1800), MaxDifficulty: num(1800)}, []contract.ID{"10"}, 1, false},
		{"minimum excludes lower rating and null", ListQuery{MinDifficulty: num(1801)}, []contract.ID{}, 0, false},
		{"maximum excludes higher rating and null", ListQuery{MaxDifficulty: num(1799)}, []contract.ID{}, 0, false},
		{"combined filters", ListQuery{Q: str("gamma"), Tag: str("graph"), MinDifficulty: num(1700), MaxDifficulty: num(1900)}, []contract.ID{"10"}, 1, false},
		{"first page", ListQuery{Pagination: Pagination{Page: 1, PageSize: 1}}, []contract.ID{"10"}, 2, true},
		{"final page", ListQuery{Pagination: Pagination{Page: 2, PageSize: 1}}, []contract.ID{"1"}, 2, false},
		{"out of range", ListQuery{Pagination: Pagination{Page: 3, PageSize: 1}}, []contract.ID{}, 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.query.Page == 0 {
				tc.query.Pagination = Pagination{Page: 1, PageSize: 20}
			}
			items, meta, err := s.List(ctx, tc.query)
			if err != nil {
				t.Fatal("public list query failed")
			}
			ids := make([]contract.ID, 0, len(items))
			for _, item := range items {
				ids = append(ids, item.ProblemRef.ProblemID)
				if item.Status != contract.ProblemPublished || item.CatalogVersion != "3" {
					t.Fatal("public list returned a draft or mixed catalog state")
				}
				if item.ProblemRef.ProblemID == "1" {
					raw, _ := json.Marshal(item)
					if item.Difficulty != nil || item.DifficultyScale != contract.DifficultyUnrated || !strings.Contains(string(raw), `"difficulty":null`) {
						t.Fatal("unrated difficulty was coerced or omitted")
					}
				}
			}
			if !reflect.DeepEqual(ids, tc.ids) || meta.Total != tc.total || meta.HasNext != tc.next || meta.Page != tc.query.Page || meta.PageSize != tc.query.PageSize {
				t.Fatalf("public list filter/page mismatch: ids=%v meta=%+v", ids, meta)
			}
		})
	}
	if _, err := db.Exec(`UPDATE judge.platform_problems SET public_updated_at='2026-10-08T00:00:01Z' WHERE id=1`); err != nil {
		t.Fatal("cannot establish isolated timestamp precedence")
	}
	items, _, err := s.List(ctx, ListQuery{Pagination: Pagination{Page: 1, PageSize: 20}})
	if err != nil || len(items) != 2 || items[0].ProblemRef.ProblemID != "1" {
		t.Fatal("timestamp descending order did not precede numeric ID descending order")
	}
	if _, err := s.Withdraw(ctx, "10", contract.WithdrawRequest{RequestID: uuid(t), Reason: "Synthetic query fixture"}); err != nil {
		t.Fatal("cannot withdraw the isolated query fixture")
	}
	items, meta, err := s.List(ctx, ListQuery{Pagination: Pagination{Page: 1, PageSize: 20}, Status: contract.ProblemWithdrawn, Tag: str("DP")})
	if err != nil || len(items) != 1 || items[0].ProblemRef.ProblemID != "10" || meta.Total != 1 || items[0].Status != contract.ProblemWithdrawn || items[0].CatalogVersion != "4" {
		t.Fatal("withdrawn status filtering lost the last published metadata")
	}
}
