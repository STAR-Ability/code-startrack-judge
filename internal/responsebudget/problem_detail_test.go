// SPDX-License-Identifier: Apache-2.0

package responsebudget

import (
	"encoding/json"
	"math/rand"
	"strings"
	"testing"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
)

func budgetDetail() contract.PlatformProblemDetail {
	title := "Complete public detail"
	return contract.PlatformProblemDetail{
		PlatformProblemSummary: contract.PlatformProblemSummary{
			ProblemRef: contract.PlatformProblemRef{Source: contract.SourcePlatform, Platform: contract.PlatformStartrack, ProblemID: "1", ProblemVersionID: envelopeUUID},
			Title:      &title, DifficultyScale: contract.DifficultyUnrated, Status: contract.ProblemDraft, CatalogVersion: "1",
			TimeLimitMs: 1000, MemoryLimitBytes: 256 << 20, LanguageIDs: []string{"cpp17"}, UpdatedAt: "2026-10-08T00:00:00Z",
		},
		Statement: contract.Statement{Format: "MARKDOWN", Content: "Statement"},
		Samples:   []contract.Sample{{Input: "input", Output: "answer"}},
		License:   contract.License{Notice: "Public notice", SourceURL: contract.PackageRepository},
	}
}

func TestProblemDetailCountMatchesActualJSONEncoder(t *testing.T) {
	random := rand.New(rand.NewSource(802))
	alphabet := []rune{'a', '"', '\\', '\b', '\f', '\n', '\r', '\t', 0, 0x1f, '<', '>', '&', '\u2028', '\u2029', '中', '🙂', utf8Replacement}
	for i := range 200 {
		var content strings.Builder
		for range i {
			content.WriteRune(alphabet[random.Intn(len(alphabet))])
		}
		value := content.String()
		d := budgetDetail()
		d.Title, d.Statement.Input, d.Statement.Output, d.License.SPDXID = &value, &value, &value, &value
		d.Statement.Content, d.License.Notice, d.License.SourceURL = value, value, value
		d.Samples = []contract.Sample{{Input: value, Output: value}, {Input: "", Output: value}}
		d.Tags = []string{value, ""}
		if i%2 == 0 {
			rating := contract.SafeInt(contract.MaxSafeInteger)
			d.Difficulty, d.DifficultyScale = &rating, contract.DifficultyPlatform
		}
		encoded, err := json.Marshal(contract.ApiResponse[contract.PlatformProblemDetail]{Data: d, RequestID: envelopeUUID})
		if err != nil {
			t.Fatal(err)
		}
		if actual := problemDetailSize(d, contract.MaxResultBytes); actual != int64(len(encoded)) {
			t.Fatalf("vector %d counted %d, encoder wrote %d", i, actual, len(encoded))
		}
	}
	d := budgetDetail()
	d.Title, d.Samples, d.Tags, d.LanguageIDs = nil, nil, nil, nil
	d.Statement.Content = string([]byte{'a', 0xff, 0xfe})
	encoded, err := json.Marshal(contract.ApiResponse[contract.PlatformProblemDetail]{Data: d, RequestID: envelopeUUID})
	if err != nil || problemDetailSize(d, contract.MaxResultBytes) != int64(len(encoded)) {
		t.Fatal("explicit nulls, empty arrays or invalid-byte escaping differ from the encoder")
	}
}

const utf8Replacement = '\ufffd'

func TestProblemDetailEscapedBoundaryAndFutureGrowth(t *testing.T) {
	d := budgetDetail()
	d.ProblemRef.ProblemID, d.CatalogVersion = "9223372036854775807", "9223372036854775807"
	d.Status, d.UpdatedAt = contract.ProblemWithdrawn, "9999-12-31T23:59:59.999999999Z"
	d.Statement.Content = ""
	baseline, err := json.Marshal(contract.ApiResponse[contract.PlatformProblemDetail]{Data: d, RequestID: envelopeUUID})
	if err != nil {
		t.Fatal(err)
	}
	remaining := int(contract.MaxResultBytes) - len(baseline)
	d.Statement.Content = strings.Repeat("<", remaining/6) + strings.Repeat("a", remaining%6)
	encoded, err := json.Marshal(contract.ApiResponse[contract.PlatformProblemDetail]{Data: d, RequestID: envelopeUUID})
	if err != nil || int64(len(encoded)) != contract.MaxResultBytes || !ProblemDetailFits(d) {
		t.Fatal("complete detail at the encoder ceiling was rejected")
	}
	d.Statement.Content += "a"
	if ProblemDetailFits(d) {
		t.Fatal("one-byte overflow was accepted")
	}
	// The same immutable content is already too large while its current DRAFT
	// envelope is shorter; future catalog/status/time growth remains reserved.
	d.ProblemRef.ProblemID, d.CatalogVersion = "1", "1"
	d.Status, d.UpdatedAt = contract.ProblemDraft, "2026-10-08T00:00:00Z"
	shorter, err := json.Marshal(contract.ApiResponse[contract.PlatformProblemDetail]{Data: d, RequestID: envelopeUUID})
	if err != nil || int64(len(shorter)) > contract.MaxResultBytes || ProblemDetailFits(d) {
		t.Fatal("short current identity bypassed the prospective publication budget")
	}
}

func TestProblemDetailCounterDoesNotAllocateSerializedContent(t *testing.T) {
	d := budgetDetail()
	d.Statement.Content = strings.Repeat("<>&\"\\\n\u2028中", 100)
	if allocations := testing.AllocsPerRun(100, func() { ProblemDetailFits(d) }); allocations != 0 {
		t.Fatalf("size-only guard allocated %.1f objects per call", allocations)
	}
}
