package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

const requestUUID = "123e4567-e89b-12d3-a456-426614174000"
const versionUUID = "123e4567-e89b-12d3-a456-426614174001"

func TestSharedConsumerFixtures(t *testing.T) {
	for _, fixture := range []struct {
		name string
		dst  any
	}{
		{"judge-request.json", new(JudgeTaskRequest)},
		{"queued-task.json", new(JudgeTask)},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			data, e := os.ReadFile("testdata/" + fixture.name)
			if e != nil {
				t.Fatal(e)
			}
			if e := DecodeJSON(data, fixture.dst); e != nil {
				t.Fatal(e)
			}
			encoded, e := json.Marshal(fixture.dst)
			if e != nil {
				t.Fatal(e)
			}
			var before, after map[string]json.RawMessage
			if e := json.Unmarshal(data, &before); e != nil {
				t.Fatal(e)
			}
			if e := json.Unmarshal(encoded, &after); e != nil {
				t.Fatal(e)
			}
			if len(before) != len(after) {
				t.Fatal("fixture lost required nullable members")
			}
			for name, value := range before {
				if string(value) == "null" && string(after[name]) != "null" {
					t.Fatalf("nullable %s changed", name)
				}
			}
		})
	}
}

func judgeFixture() []byte {
	source := "int main() { return 0; }\n"
	h := sha256.Sum256([]byte(source))
	version := UUID(versionUUID)
	b, _ := json.Marshal(JudgeTaskRequest{RequestID: UUID(requestUUID), SubmissionID: "9223372036854775807", ProblemRef: ProblemRef{Source: SourcePlatform, Platform: PlatformStartrack, ProblemID: "42", ProblemVersionID: &version}, LanguageID: "cpp17", SourceCode: source, SourceSHA256: hex.EncodeToString(h[:])})
	return b
}
func TestStrictJudgeContract(t *testing.T) {
	valid := string(judgeFixture())
	var request JudgeTaskRequest
	if e := DecodeJSON([]byte(valid), &request); e != nil {
		t.Fatal(e)
	}
	if request.SourceCode != "int main() { return 0; }\n" || request.SubmissionID != "9223372036854775807" {
		t.Fatalf("source or bigint identity changed: %#v", request)
	}
	tests := map[string]string{
		"missing":           strings.Replace(valid, `"languageId":"cpp17",`, "", 1),
		"nonnull":           strings.Replace(valid, `"sourceCode":"int main() { return 0; }\n"`, `"sourceCode":null`, 1),
		"unknown callback":  strings.TrimSuffix(valid, "}") + `,"callbackUrl":"http://attacker/"}`,
		"unknown template":  strings.TrimSuffix(valid, "}") + `,"sourceFilename":"other.cpp"}`,
		"unknown nested":    strings.Replace(valid, `"source":"PLATFORM"`, `"source":"PLATFORM","command":"sh"`, 1),
		"duplicate":         strings.TrimSuffix(valid, "}") + `,"languageId":"cpp17"}`,
		"escaped duplicate": strings.TrimSuffix(valid, "}") + `,"language\u0049d":"cpp17"}`,
		"wrong case":        strings.Replace(valid, `"languageId"`, `"LanguageId"`, 1),
		"trailing":          valid + ` {}`,
		"id number":         strings.Replace(valid, `"submissionId":"9223372036854775807"`, `"submissionId":42`, 1),
		"id overflow":       strings.Replace(valid, `"submissionId":"9223372036854775807"`, `"submissionId":"9223372036854775808"`, 1),
		"id leading zero":   strings.Replace(valid, `"problemId":"42"`, `"problemId":"042"`, 1),
		"null version":      strings.Replace(valid, `"problemVersionId":"`+versionUUID+`"`, `"problemVersionId":null`, 1),
		"wrong hash":        strings.Replace(valid, request.SourceSHA256, strings.Repeat("0", 64), 1),
		"unpaired high":     strings.Replace(valid, `"sourceCode":"int main() { return 0; }\n"`, `"sourceCode":"\ud800"`, 1),
		"unpaired low":      strings.Replace(valid, `"sourceCode":"int main() { return 0; }\n"`, `"sourceCode":"\udfff"`, 1),
		"high then BMP":     strings.Replace(valid, `"sourceCode":"int main() { return 0; }\n"`, `"sourceCode":"\ud800\u0041"`, 1),
		"invalid utf8":      strings.Replace(valid, `cpp17`, string([]byte{0xff}), 1),
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			var dst JudgeTaskRequest
			if e := DecodeJSON([]byte(body), &dst); e == nil {
				t.Fatal("invalid body admitted")
			}
		})
	}
}
func TestEscapedUnicodePreservesSourceBytes(t *testing.T) {
	body := string(judgeFixture())
	source := "😀\n"
	h := sha256.Sum256([]byte(source))
	var parsed map[string]any
	if e := json.Unmarshal([]byte(body), &parsed); e != nil {
		t.Fatal(e)
	}
	parsed["sourceCode"] = source
	parsed["sourceSha256"] = hex.EncodeToString(h[:])
	raw, _ := json.Marshal(parsed)
	raw = []byte(strings.Replace(string(raw), "😀", `\ud83d\ude00`, 1))
	var dst JudgeTaskRequest
	if e := DecodeJSON(raw, &dst); e != nil {
		t.Fatal(e)
	}
	if dst.SourceCode != source {
		t.Fatal("Unicode normalization changed source")
	}
}
func TestScalarWireBoundaries(t *testing.T) {
	for _, s := range []string{`"1"`, `"9007199254740992"`, `"9223372036854775807"`} {
		var id ID
		if e := DecodeJSON([]byte(s), &id); e != nil {
			t.Fatalf("valid bigint %s: %v", s, e)
		}
	}
	for _, s := range []string{`1`, `"0"`, `"-1"`, `"01"`, `"+1"`, `"1.0"`, `"9223372036854775808"`, `null`} {
		var id ID
		if DecodeJSON([]byte(s), &id) == nil {
			t.Errorf("admitted invalid bigint %s", s)
		}
	}
	for _, s := range []string{`0`, `9007199254740991`, `1.0`, `1e0`, `100.00e-2`, `0.1e1`, `-0.0`} {
		var count SafeInt
		if DecodeJSON([]byte(s), &count) != nil {
			t.Errorf("rejected safe count %s", s)
		}
	}
	for _, s := range []string{`-1`, `9007199254740992`, `1.1`, `9007199254740991.1`, `1e9999999999999999999999`, `0.1e0`, `"1"`, `null`} {
		var count SafeInt
		if DecodeJSON([]byte(s), &count) == nil {
			t.Errorf("admitted invalid count %s", s)
		}
	}
	for _, s := range []string{`"2026-10-08T02:04:06Z"`, `"2026-10-08T02:04:06.123456789Z"`} {
		var instant Instant
		if DecodeJSON([]byte(s), &instant) != nil {
			t.Errorf("rejected UTC instant %s", s)
		}
	}
	for _, s := range []string{`"2026-10-08T02:04:06+00:00"`, `"2026-10-08T02:04:06,1Z"`, `"2026-02-30T02:04:06Z"`, `"2026-10-08t02:04:06z"`} {
		var instant Instant
		if DecodeJSON([]byte(s), &instant) == nil {
			t.Errorf("admitted invalid UTC instant %s", s)
		}
	}
	if got := UTC(time.Date(2026, 10, 8, 10, 0, 0, 0, time.FixedZone("local", 8*3600))); got != "2026-10-08T02:00:00Z" {
		t.Fatalf("UTC conversion: %s", got)
	}
}
func TestNullableRequiredAndEmptyArrays(t *testing.T) {
	var summary ProblemSummary
	body := `{"problemRef":{"source":"PLATFORM","platform":"startrack","problemId":"1","problemVersionId":"` + versionUUID + `"},"title":null,"difficulty":null,"difficultyScale":"UNRATED","tags":[],"url":null}`
	if e := DecodeJSON([]byte(body), &summary); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{strings.Replace(body, `"title":null,`, "", 1), strings.Replace(body, `"tags":[]`, `"tags":null`, 1)} {
		if DecodeJSON([]byte(bad), &summary) == nil {
			t.Fatal("missing or undeclared null accepted")
		}
	}
	encoded, e := json.Marshal(ByRequestResponse{})
	if e != nil {
		t.Fatal(e)
	}
	if string(encoded) != `{"tasks":[],"missingRequestIds":[]}` {
		t.Fatalf("empty array semantics: %s", encoded)
	}
}
func TestSourceLimitsAndHash(t *testing.T) {
	var request JudgeTaskRequest
	if e := DecodeJSON(judgeFixture(), &request); e != nil {
		t.Fatal(e)
	}
	for _, length := range []int{MaxSourceBytes, MaxSourceBytes + 1} {
		request.SourceCode = strings.Repeat("x", length)
		h := sha256.Sum256([]byte(request.SourceCode))
		request.SourceSHA256 = hex.EncodeToString(h[:])
		e := request.Validate()
		if (length == MaxSourceBytes) != (e == nil) {
			t.Fatalf("source size %d: %v", length, e)
		}
	}
	request.SourceCode = " \t\n\u2003"
	if request.Validate() == nil {
		t.Fatal("blank source accepted")
	}
	request.SourceCode = "x"
	h := sha256.Sum256([]byte("x"))
	request.SourceSHA256 = strings.ToUpper(hex.EncodeToString(h[:]))
	if request.Validate() == nil {
		t.Fatal("uppercase source hash accepted")
	}
}
func TestManagementRequestBoundaries(t *testing.T) {
	r := ImportRequest{RequestID: UUID(requestUUID), Source: "OJ_LAB", RepositoryURL: PackageRepository, Revision: strings.Repeat("a", 40), PackagePaths: Array[string]{"problems/hello"}}
	if e := r.Validate(); e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{"/problems/hello", "problems/../secret", "problems/a/../b", "problems/a//b", "problems/a/", "problems/", "problems/a\\b", "problems/http://a", "problems/a\x00b", "problems/%2e%2e", "problems/x%2f..%2fsecret", "problems/%252e%252e", "problems/a%5cb"} {
		r.PackagePaths = Array[string]{p}
		if r.Validate() == nil {
			t.Errorf("invalid package path %q accepted", p)
		}
	}
	r.PackagePaths = Array[string]{"problems/a", "problems/a"}
	if r.Validate() == nil {
		t.Fatal("duplicate package admitted")
	}
	n := SafeInt(1200)
	m := MetadataVersionRequest{RequestID: UUID(requestUUID), BaseProblemVersionID: UUID(versionUUID), Tags: Array[string]{" a "}, Difficulty: &n, DifficultyScale: DifficultyPlatform}
	if e := m.Validate(); e != nil {
		t.Fatal(e)
	}
	if m.Normalize().Tags[0] != "a" {
		t.Fatal("tags not normalized")
	}
	m.Tags = Array[string]{"a", " a "}
	if e := m.Validate(); e != nil {
		t.Fatal(e)
	}
	if len(m.Normalize().Tags) != 1 {
		t.Fatal("tags not deduplicated")
	}
	m.Tags = nil
	m.DifficultyScale = DifficultyUnrated
	if m.Validate() == nil {
		t.Fatal("unrated non-null difficulty admitted")
	}
	by := ByRequestRequest{RequestIDs: Array[UUID]{UUID(requestUUID), UUID(requestUUID)}}
	if by.Validate() == nil {
		t.Fatal("duplicate recovery identity admitted")
	}
}
func TestTaskAndCallbackStateInvariants(t *testing.T) {
	now := Instant("2026-10-08T00:00:00Z")
	task := JudgeTask{TaskBase: TaskBase{RequestID: UUID(requestUUID), Revision: 1, CreatedAt: now, UpdatedAt: now}, JudgeTaskID: UUID(versionUUID), SubmissionID: "1", Status: JudgeQueued}
	if e := task.Validate(); e != nil {
		t.Fatal(e)
	}
	task.FinishedAt = &now
	if task.Validate() == nil {
		t.Fatal("inflight task carrying terminal timestamp admitted")
	}
	task.Status = JudgeCompleted
	task.Result = &JudgeResult{Verdict: VerdictCE, TotalTestCount: 2, JudgedAt: now}
	if e := task.Validate(); e != nil {
		t.Fatal(e)
	}
	event := CallbackEvent[JudgeTask]{EventID: UUID(requestUUID), EventType: "JUDGE_TASK_UPDATED", OccurredAt: now, RequestID: task.RequestID, AggregateID: task.JudgeTaskID, Revision: task.Revision, Payload: task}
	if e := event.Validate(); e != nil {
		t.Fatal(e)
	}
	event.Revision = 2
	if event.Validate() == nil {
		t.Fatal("conflicting event revision admitted")
	}
	task.Status = JudgeFailed
	if task.Validate() == nil {
		t.Fatal("CE infrastructure failure admitted")
	}
}
