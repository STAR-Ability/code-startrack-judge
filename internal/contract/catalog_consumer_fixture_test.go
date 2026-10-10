package contract_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
)

// This independent Backend consumer fixture documents the v0.2 catalog contract.
// It is test-only, owns no product Backend cache, and provides no Linux proof.
const catalogFixtureSourceOwner = "judge-problem-service"
const catalogFixtureLimit = 2

type catalogFixtureKey struct {
	sourceOwner string
	source      contract.ProblemSource
	platform    contract.Platform
	problemID   contract.ID
}

func catalogKey(ref contract.ProblemRef) catalogFixtureKey {
	// Version is retained in the entry, while the logical problem key excludes it.
	return catalogFixtureKey{catalogFixtureSourceOwner, ref.Source, ref.Platform, ref.ProblemID}
}

type catalogFixtureSnapshot struct {
	sourceOwner    string
	snapshotID     contract.UUID
	catalogVersion contract.ID
	entries        map[catalogFixtureKey]contract.CatalogEntry
}

func (s *catalogFixtureSnapshot) lookup(ref contract.ProblemRef) (contract.CatalogEntry, bool) {
	entry, ok := s.entries[catalogKey(ref)]
	// A reader receives detached mutable fields, never the published cache storage.
	entry.Problem.ProblemRef.ProblemVersionID = catalogClonePointer(entry.Problem.ProblemRef.ProblemVersionID)
	entry.Problem.Title = catalogClonePointer(entry.Problem.Title)
	entry.Problem.Difficulty = catalogClonePointer(entry.Problem.Difficulty)
	entry.Problem.URL = catalogClonePointer(entry.Problem.URL)
	entry.Problem.Tags = append(contract.Array[string]{}, entry.Problem.Tags...)
	return entry, ok
}

func catalogClonePointer[T any](value *T) *T {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

type catalogFixtureResponse struct {
	status int
	body   []byte
}

type catalogFixtureConsumer struct {
	current atomic.Pointer[catalogFixtureSnapshot]
}

func (c *catalogFixtureConsumer) refresh(fetch func(*string, int) (catalogFixtureResponse, error), now func() time.Time) error {
	staged := &catalogFixtureSnapshot{sourceOwner: catalogFixtureSourceOwner, entries: map[catalogFixtureKey]contract.CatalogEntry{}}
	var cursor *string // Every refresh, including after 410, starts without a cursor.
	var earliestExpiry time.Time
	seenCursors := map[string]bool{}
	for {
		response, err := fetch(cursor, catalogFixtureLimit)
		if err != nil {
			return err
		}
		if response.status != 200 {
			var failure contract.ApiError
			if err := contract.DecodeJSON(response.body, &failure); err != nil {
				return err
			}
			return fmt.Errorf("catalog page returned %d: %s", response.status, failure.Error.Code)
		}
		var envelope contract.ApiResponse[contract.CatalogSnapshotPage]
		if err := contract.DecodeJSON(response.body, &envelope); err != nil {
			return err
		}
		page := envelope.Data
		expires, err := time.Parse(time.RFC3339Nano, string(page.ExpiresAt))
		if err != nil || !now().Before(expires) {
			return errors.New("catalog snapshot expired")
		}
		if staged.snapshotID == "" {
			staged.snapshotID, staged.catalogVersion = page.SnapshotID, page.CatalogVersion
			earliestExpiry = expires
		} else if page.SnapshotID != staged.snapshotID || page.CatalogVersion != staged.catalogVersion {
			return errors.New("inconsistent catalog snapshot")
		}
		if expires.Before(earliestExpiry) {
			earliestExpiry = expires
		}
		for _, entry := range page.Items {
			key := catalogKey(entry.Problem.ProblemRef)
			if _, exists := staged.entries[key]; exists {
				return errors.New("duplicate catalog identity")
			}
			staged.entries[key] = entry // Keep WITHDRAWN summaries as tombstones.
		}
		if page.NextCursor == nil {
			if !now().Before(earliestExpiry) {
				return errors.New("catalog snapshot expired before publication")
			}
			c.current.Store(staged) // The only publication: one complete immutable map.
			return nil
		}
		if seenCursors[*page.NextCursor] {
			return errors.New("repeated catalog cursor")
		}
		seenCursors[*page.NextCursor] = true
		cursor = page.NextCursor // Pass the opaque token verbatim; never assemble it.
	}
}

func catalogFixtureBytes(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func catalogFixturePage(t *testing.T, name string) contract.ApiResponse[contract.CatalogSnapshotPage] {
	t.Helper()
	var page contract.ApiResponse[contract.CatalogSnapshotPage]
	if err := contract.DecodeJSON(catalogFixtureBytes(t, name), &page); err != nil {
		t.Fatal(err)
	}
	return page
}

func catalogFixtureEncode(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func catalogFixtureNow() time.Time {
	return time.Date(2026, 10, 8, 4, 0, 0, 0, time.UTC)
}

func catalogFixtureOldCache(t *testing.T) (*catalogFixtureConsumer, *catalogFixtureSnapshot) {
	t.Helper()
	old := catalogFixturePage(t, "catalog-consumer-page-1.json")
	old.Data.SnapshotID = "123e4567-e89b-12d3-a456-426614174090"
	old.Data.CatalogVersion = "17"
	old.Data.NextCursor = nil
	old.Data.Items[0].Problem.Title = new("Previously cached")
	consumer := new(catalogFixtureConsumer)
	response := catalogFixtureResponse{200, catalogFixtureEncode(t, old)}
	if err := consumer.refresh(func(cursor *string, limit int) (catalogFixtureResponse, error) {
		if cursor != nil || limit != catalogFixtureLimit {
			return catalogFixtureResponse{}, errors.New("old fixture request changed")
		}
		return response, nil
	}, catalogFixtureNow); err != nil {
		t.Fatal(err)
	}
	return consumer, consumer.current.Load()
}

func catalogFixtureFetch(t *testing.T, first, second catalogFixtureResponse) func(*string, int) (catalogFixtureResponse, error) {
	t.Helper()
	var page contract.ApiResponse[contract.CatalogSnapshotPage]
	if err := contract.DecodeJSON(first.body, &page); err != nil {
		t.Fatal(err)
	}
	call := 0
	return func(cursor *string, limit int) (catalogFixtureResponse, error) {
		call++
		if limit != catalogFixtureLimit {
			return catalogFixtureResponse{}, errors.New("consumer changed the fixed limit")
		}
		switch call {
		case 1:
			if cursor != nil {
				return catalogFixtureResponse{}, errors.New("consumer did not start a fresh snapshot")
			}
			return first, nil
		case 2:
			if cursor == nil || *cursor != *page.Data.NextCursor {
				return catalogFixtureResponse{}, errors.New("consumer changed the opaque cursor")
			}
			if second.status == 0 {
				return catalogFixtureResponse{}, io.ErrUnexpectedEOF
			}
			return second, nil
		default:
			return catalogFixtureResponse{}, errors.New("unexpected continuation request")
		}
	}
}

func TestCatalogConsumerFixtureAtomicReplacement(t *testing.T) {
	consumer, old := catalogFixtureOldCache(t)
	first := catalogFixtureResponse{200, catalogFixtureBytes(t, "catalog-consumer-page-1.json")}
	second := catalogFixtureResponse{200, catalogFixtureBytes(t, "catalog-consumer-page-2.json")}
	fetch := catalogFixtureFetch(t, first, second)
	collecting, resume := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- consumer.refresh(func(cursor *string, limit int) (catalogFixtureResponse, error) {
			if cursor != nil {
				close(collecting)
				<-resume
			}
			return fetch(cursor, limit)
		}, catalogFixtureNow)
	}()
	select {
	case <-collecting:
	case err := <-done:
		t.Fatalf("refresh ended before collecting all pages: %v", err)
	}
	// A reader during the blocked continuation sees the complete old snapshot.
	observed := consumer.current.Load()
	if observed != old || observed.catalogVersion != "17" || len(observed.entries) != 2 {
		close(resume)
		<-done
		t.Fatal("a partial snapshot replaced the old cache")
	}
	close(resume)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	published := consumer.current.Load()
	if published == old || published.sourceOwner != catalogFixtureSourceOwner || published.catalogVersion != "18" || len(published.entries) != 3 {
		t.Fatal("the complete snapshot was not atomically replaced")
	}
	if old.catalogVersion != "17" || len(old.entries) != 2 {
		t.Fatal("publication mutated the previous snapshot")
	}
}

func TestCatalogConsumerFixtureRetainsOldCache(t *testing.T) {
	first := catalogFixtureResponse{200, catalogFixtureBytes(t, "catalog-consumer-page-1.json")}
	second := catalogFixturePage(t, "catalog-consumer-page-2.json")
	mutated := func(change func(*contract.CatalogSnapshotPage)) catalogFixtureResponse {
		page := catalogFixturePage(t, "catalog-consumer-page-2.json")
		change(&page.Data)
		return catalogFixtureResponse{200, catalogFixtureEncode(t, page)}
	}
	errorResponse := func(status int, code string) catalogFixtureResponse {
		return catalogFixtureResponse{status, catalogFixtureEncode(t, contract.ApiError{
			RequestID: "123e4567-e89b-12d3-a456-426614174112",
			Error:     contract.ErrorDetail{Code: code, Message: "Catalog refresh failed.", Details: map[string]any{}},
		})}
	}
	tests := []struct {
		name     string
		response catalogFixtureResponse
	}{
		{"incomplete transport", catalogFixtureResponse{}},
		{"different snapshot", mutated(func(page *contract.CatalogSnapshotPage) { page.SnapshotID = "123e4567-e89b-12d3-a456-426614174099" })},
		{"different catalog version", mutated(func(page *contract.CatalogSnapshotPage) { page.CatalogVersion = "19" })},
		{"expired response", errorResponse(410, "SNAPSHOT_EXPIRED")},
		{"server error", errorResponse(503, "JUDGE_UNAVAILABLE")},
		{"malformed page", catalogFixtureResponse{200, []byte(`{"data":{}}`)}},
		{"expired successful page", mutated(func(page *contract.CatalogSnapshotPage) { page.ExpiresAt = "2026-10-08T04:00:00Z" })},
		{"draft status", mutated(func(page *contract.CatalogSnapshotPage) { page.Items[0].Status = contract.ProblemDraft })},
		{"missing required nullable member", catalogFixtureResponse{200, []byte(strings.Replace(string(catalogFixtureEncode(t, second)), `"nextCursor":null,`, "", 1))}},
		{"repeated cursor", mutated(func(page *contract.CatalogSnapshotPage) { page.NextCursor = new("opaque.fixturE/page+2=") })},
		{"duplicate problem", mutated(func(page *contract.CatalogSnapshotPage) {
			page.Items[0] = catalogFixturePage(t, "catalog-consumer-page-1.json").Data.Items[0]
		})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			consumer, old := catalogFixtureOldCache(t)
			ref := catalogFixturePage(t, "catalog-consumer-page-1.json").Data.Items[0].Problem.ProblemRef
			before := catalogFixtureEncode(t, old.entries[catalogKey(ref)])
			if err := consumer.refresh(catalogFixtureFetch(t, first, test.response), catalogFixtureNow); err == nil {
				t.Fatal("incomplete or invalid snapshot was accepted")
			}
			if consumer.current.Load() != old || old.catalogVersion != "17" || len(old.entries) != 2 {
				t.Fatal("failed refresh replaced the old cache")
			}
			after := catalogFixtureEncode(t, old.entries[catalogKey(ref)])
			if string(before) != string(after) {
				t.Fatal("failed refresh mutated the old cache")
			}
		})
	}
}

func TestCatalogConsumerFixtureExpiryRequiresWholeRefetch(t *testing.T) {
	consumer, old := catalogFixtureOldCache(t)
	first := catalogFixtureResponse{200, catalogFixtureBytes(t, "catalog-consumer-page-1.json")}
	expired := catalogFixtureResponse{410, []byte(`{"error":{"code":"SNAPSHOT_EXPIRED","message":"Snapshot expired.","details":{}},"requestId":"123e4567-e89b-12d3-a456-426614174112"}`)}
	if err := consumer.refresh(catalogFixtureFetch(t, first, expired), catalogFixtureNow); err == nil || !strings.Contains(err.Error(), "SNAPSHOT_EXPIRED") {
		t.Fatalf("expected snapshot expiration, got %v", err)
	}
	if consumer.current.Load() != old {
		t.Fatal("expiration replaced the complete old cache")
	}
	// The next refresh has to refetch page one; no page from the expired staging map survives.
	freshFirst := catalogFixturePage(t, "catalog-consumer-page-1.json")
	freshSecond := catalogFixturePage(t, "catalog-consumer-page-2.json")
	for _, page := range []*contract.CatalogSnapshotPage{&freshFirst.Data, &freshSecond.Data} {
		page.SnapshotID = "123e4567-e89b-12d3-a456-426614174120"
		page.CatalogVersion = "19"
	}
	freshFirst.Data.Items[0].Problem.Title = new("Freshly fetched title")
	freshFirst.Data.NextCursor = new("opaque.rEstarted/page+2=")
	if err := consumer.refresh(catalogFixtureFetch(t,
		catalogFixtureResponse{200, catalogFixtureEncode(t, freshFirst)},
		catalogFixtureResponse{200, catalogFixtureEncode(t, freshSecond)},
	), catalogFixtureNow); err != nil {
		t.Fatal(err)
	}
	entry, ok := consumer.current.Load().lookup(freshFirst.Data.Items[0].Problem.ProblemRef)
	if !ok || *entry.Problem.Title != "Freshly fetched title" || consumer.current.Load().catalogVersion != "19" {
		t.Fatal("restart reused the expired first page")
	}
}

func TestCatalogConsumerFixtureExpiryBeforePublication(t *testing.T) {
	consumer, old := catalogFixtureOldCache(t)
	first := catalogFixtureResponse{200, catalogFixtureBytes(t, "catalog-consumer-page-1.json")}
	second := catalogFixtureResponse{200, catalogFixtureBytes(t, "catalog-consumer-page-2.json")}
	clockCalls := 0
	now := func() time.Time {
		clockCalls++
		if clockCalls < 3 {
			return catalogFixtureNow()
		}
		return catalogFixtureNow().Add(30 * time.Minute)
	}
	if err := consumer.refresh(catalogFixtureFetch(t, first, second), now); err == nil {
		t.Fatal("snapshot expiring at publication was accepted")
	}
	if consumer.current.Load() != old {
		t.Fatal("expired staging map replaced the old cache")
	}
}

func TestCatalogConsumerFixtureReadOnlyTombstonesAndEmptySnapshot(t *testing.T) {
	consumer, _ := catalogFixtureOldCache(t)
	first := catalogFixturePage(t, "catalog-consumer-page-1.json")
	second := catalogFixtureResponse{200, catalogFixtureBytes(t, "catalog-consumer-page-2.json")}
	if err := consumer.refresh(catalogFixtureFetch(t, catalogFixtureResponse{200, catalogFixtureEncode(t, first)}, second), catalogFixtureNow); err != nil {
		t.Fatal(err)
	}
	snapshot := consumer.current.Load()
	tombstone, ok := snapshot.lookup(first.Data.Items[1].Problem.ProblemRef)
	if !ok || !reflect.DeepEqual(tombstone, first.Data.Items[1]) || tombstone.Status != contract.ProblemWithdrawn {
		t.Fatal("withdrawn entry lost its last published summary")
	}
	reader, ok := snapshot.lookup(first.Data.Items[0].Problem.ProblemRef)
	if !ok {
		t.Fatal("published entry missing")
	}
	*reader.Problem.Title = "Reader edited title"
	*reader.Problem.Difficulty = 1
	*reader.Problem.ProblemRef.ProblemVersionID = "123e4567-e89b-12d3-a456-426614174199"
	reader.Problem.Tags[0] = "reader edited tag"
	reader.Status = contract.ProblemWithdrawn
	unchanged, _ := snapshot.lookup(first.Data.Items[0].Problem.ProblemRef)
	if !reflect.DeepEqual(unchanged, first.Data.Items[0]) {
		t.Fatal("reader could mutate published catalog metadata")
	}
	empty := catalogFixturePage(t, "catalog-consumer-page-2.json")
	empty.Data.SnapshotID = "123e4567-e89b-12d3-a456-426614174130"
	empty.Data.CatalogVersion = "20"
	empty.Data.Items = contract.Array[contract.CatalogEntry]{}
	if err := consumer.refresh(catalogFixtureFetch(t, catalogFixtureResponse{200, catalogFixtureEncode(t, empty)}, catalogFixtureResponse{}), catalogFixtureNow); err != nil {
		t.Fatal(err)
	}
	if current := consumer.current.Load(); current == snapshot || current.catalogVersion != "20" || len(current.entries) != 0 {
		t.Fatal("complete empty catalog did not replace the cache")
	}
}

func TestCatalogConsumerFixtureNamespacedIdentity(t *testing.T) {
	// These are shared identity vectors, not a claim that Judge publishes external catalogs.
	var refs contract.Array[contract.ProblemRef]
	if err := contract.DecodeJSON(catalogFixtureBytes(t, "catalog-consumer-identities.json"), &refs); err != nil {
		t.Fatal(err)
	}
	identities := map[catalogFixtureKey]contract.ProblemRef{}
	for _, ref := range refs {
		key := catalogKey(ref)
		if key.sourceOwner != "judge-problem-service" || key.source != ref.Source || key.platform != ref.Platform || key.problemID != ref.ProblemID {
			t.Fatal("cache key lost source ownership or a namespace component")
		}
		identities[key] = ref
	}
	if len(identities) != 2 || refs[0].ProblemID != refs[1].ProblemID {
		t.Fatal("PLATFORM and EXTERNAL identities with equal IDs collided")
	}
	versionChanged := refs[0]
	versionChanged.ProblemVersionID = new(contract.UUID("123e4567-e89b-12d3-a456-426614174198"))
	if catalogKey(versionChanged) != catalogKey(refs[0]) || identities[catalogKey(refs[0])].ProblemVersionID == nil || *identities[catalogKey(refs[0])].ProblemVersionID != *refs[0].ProblemVersionID {
		t.Fatal("logical identity or retained immutable version changed")
	}
	otherOwner := catalogKey(refs[0])
	otherOwner.sourceOwner = "another-service"
	if otherOwner == catalogKey(refs[0]) {
		t.Fatal("source owner is absent from the cache key")
	}
}
