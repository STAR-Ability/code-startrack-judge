// SPDX-License-Identifier: Apache-2.0
package runtime

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultCheckerExactExitAndBinaryFeedback(t *testing.T) {
	for _, expectedCode := range []int{42, 43} {
		fixture := checkerFixture{name: "test_fixture", exitCode: expectedCode, files: map[string][]byte{
			"judge.ans": []byte("answer"), "user.out": []byte("output"), "expected_message.txt": {0xff, 0, '\n'},
		}}
		valid := MatureResponse{OK: true, WaitStatus: expectedCode << 8, FeedbackBase64: base64.StdEncoding.EncodeToString(fixture.files["expected_message.txt"])}
		if !defaultCheckerEvidence(fixture, valid, nil).Passed {
			t.Fatal("exact original exit and binary feedback rejected")
		}
		for _, name := range []string{"wrong_exit", "literal_exit", "signal", "not_ok", "empty_feedback", "changed_feedback", "invalid_feedback", "runtime_error"} {
			t.Run(name, func(t *testing.T) {
				response := valid
				var runErr error
				switch name {
				case "wrong_exit":
					response.WaitStatus = (85 - expectedCode) << 8
				case "literal_exit":
					response.WaitStatus = expectedCode
				case "signal":
					response.WaitStatus = 9
				case "not_ok":
					response.OK = false
				case "empty_feedback":
					response.FeedbackBase64 = ""
				case "changed_feedback":
					response.FeedbackBase64 = base64.StdEncoding.EncodeToString([]byte{0xff, 0})
				case "invalid_feedback":
					response.FeedbackBase64 = "!invalid!"
				case "runtime_error":
					runErr = errors.New("synthetic infrastructure failure")
				}
				if defaultCheckerEvidence(fixture, response, runErr).Passed {
					t.Fatal("failed checker regression was accepted")
				}
			})
		}
	}
	fixture := checkerFixture{name: "test_empty_message", exitCode: 42, files: map[string][]byte{}}
	if !defaultCheckerEvidence(fixture, MatureResponse{OK: true, WaitStatus: 42 << 8}, nil).Passed {
		t.Fatal("absent or empty original feedback should pass")
	}
}

func TestDefaultCheckerPinnedCorpusAndDrift(t *testing.T) {
	source := os.Getenv("STARTRACK_PROBLEMTOOLS_SOURCE_DIR")
	if source == "" {
		t.Skip("exact pinned upstream source not configured; no Linux execution claim")
	}
	root := filepath.Join(source, "tests/default_validator_tests")
	read := func(path string, max int64) ([]byte, error) { return os.ReadFile(path) }
	fixtures, records, e := loadDefaultCheckerFixtures(root, read)
	if e != nil || len(fixtures) != 24 || len(records) != 108 {
		t.Fatal("exact pinned corpus manifest rejected")
	}
	accepted, rejected, total := 0, 0, int64(0)
	for _, fixture := range fixtures {
		if fixture.exitCode == 42 {
			accepted++
		} else if fixture.exitCode == 43 {
			rejected++
		}
	}
	for _, record := range records {
		total += record.Size
	}
	if accepted != 7 || rejected != 17 || total != 10055 {
		t.Fatal("pinned fixture coverage drifted")
	}
	changedRead := func(path string, max int64) ([]byte, error) {
		body, e := os.ReadFile(path)
		if filepath.Base(path) == "user.out" {
			body = append(body, 'x')
		}
		return body, e
	}
	if _, _, e := loadDefaultCheckerFixtures(root, changedRead); e == nil {
		t.Fatal("changed corpus bytes were accepted")
	}
	target := t.TempDir()
	for _, record := range records {
		relative := record.Path[len("tests/default_validator_tests/"):]
		path := filepath.Join(target, relative)
		if os.MkdirAll(filepath.Dir(path), 0700) != nil {
			t.Fatal("fixture copy directory unavailable")
		}
		body, e := os.ReadFile(filepath.Join(root, relative))
		if e != nil || os.WriteFile(path, body, 0600) != nil {
			t.Fatal("inert fixture copy unavailable")
		}
	}
	if _, _, e := loadDefaultCheckerFixtures(target, read); e != nil {
		t.Fatal("verbatim inert corpus copy rejected")
	}
	if os.WriteFile(filepath.Join(target, fixtures[0].name, "unexpected"), []byte("extra"), 0600) != nil {
		t.Fatal("extra fixture file unavailable")
	}
	if _, _, e := loadDefaultCheckerFixtures(target, read); e == nil {
		t.Fatal("unexpected corpus file was accepted")
	}
}
