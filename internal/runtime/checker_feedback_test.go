// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/STAR-Ability/code-startrack-judge/internal/runtime/restclient"
)

// Exercise checker capture through the private REST projection and real session
// cleanup. Synthetic wire bytes do not execute a checker or qualify Linux DAC.
func TestMatureCheckerFeedbackCaptureAndFailureCleanup(t *testing.T) {
	const feedbackName = "feedback/judgemessage.txt"
	const privateCanary = "private-checker-feedback-diagnostic"
	for _, tc := range []struct {
		name            string
		checker         bool
		exit            int
		feedback        []byte
		missing         bool
		openFailure     bool
		downloadFailure bool
		cleanupFailure  bool
		wantCode        string
	}{
		{name: "accepted empty file", checker: true, exit: 42},
		{name: "wrong answer exact binary feedback", checker: true, exit: 43, feedback: []byte{0xff, 0, 'W', 'A', '\n'}},
		{name: "accepted missing file", checker: true, exit: 42, missing: true, wantCode: "MATURE_CHECKER_FEEDBACK_MISSING"},
		{name: "wrong answer missing file", checker: true, exit: 43, missing: true, wantCode: "MATURE_CHECKER_FEEDBACK_MISSING"},
		{name: "feedback open failure", checker: true, exit: 43, openFailure: true, wantCode: "MATURE_SANDBOX_INFRASTRUCTURE_FAILED"},
		{name: "feedback download failure", checker: true, exit: 43, downloadFailure: true, wantCode: "SANDBOX_OPERATION_UNCERTAIN"},
		{name: "cleanup fault overrides missing feedback", checker: true, exit: 43, missing: true, cleanupFailure: true, wantCode: "SANDBOX_CLEANUP_FAILED"},
		{name: "non checker needs no feedback"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, _, _ := testAdapter(t)
			allocated := map[restclient.FileID][]byte{}
			deleted := map[restclient.FileID]int{}
			downloaded := map[restclient.FileID]int{}
			next, runs := byte(0), 0
			var firstInput, feedbackID restclient.FileID
			newID := func(contents []byte) restclient.FileID {
				next++
				id := restclient.FileID(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte{0, 0, 0, 0, next}))
				allocated[id] = contents
				return id
			}
			stdout, stderr := []byte("private-stdout\n"), []byte("private-stderr\n")
			client, err := restclient.New(restclient.Options{Token: strings.Repeat("r", 64), RoundTripper: outputTransport(func(request *http.Request) (*http.Response, error) {
				response := httptest.NewRecorder()
				switch {
				case request.Method == http.MethodPost && request.URL.Path == "/file":
					id := newID(nil)
					if firstInput == "" {
						firstInput = id
					}
					if json.NewEncoder(response).Encode(id) != nil {
						t.Fatal("synthetic upload acknowledgement failed")
					}
				case request.Method == http.MethodPost && request.URL.Path == "/run":
					runs++
					var body struct {
						Commands []struct {
							CopyOutCached []string `json:"copyOutCached"`
						} `json:"cmd"`
					}
					if json.NewDecoder(request.Body).Decode(&body) != nil || len(body.Commands) != 1 {
						t.Fatal("synthetic checker request invalid")
					}
					wantOutputs := []string{"stdout", "stderr"}
					if tc.checker {
						wantOutputs = append(wantOutputs, feedbackName)
					}
					if !slices.Equal(body.Commands[0].CopyOutCached, wantOutputs) {
						t.Fatal("checker feedback must use the exact mandatory cached output")
					}
					files := map[string]restclient.FileID{"stdout": newID(stdout), "stderr": newID(stderr)}
					if tc.checker && !tc.missing && !tc.openFailure {
						feedbackID = newID(tc.feedback)
						files[feedbackName] = feedbackID
					}
					status := restclient.NonzeroExit
					if !tc.checker {
						status = restclient.Accepted
					}
					var failures []outputWireError
					if tc.openFailure {
						status = restclient.FileError
						failures = []outputWireError{{feedbackName, "CopyOutOpen", privateCanary}}
					}
					writeOutputWire(t, response, status, tc.exit, "", failures, files)
				case request.Method == http.MethodGet:
					id := restclient.FileID(strings.TrimPrefix(request.URL.Path, "/file/"))
					contents, exists := allocated[id]
					if !exists {
						t.Fatal("download used an unacknowledged cache ID")
					}
					downloaded[id]++
					if id == feedbackID && tc.downloadFailure {
						response.WriteHeader(http.StatusServiceUnavailable)
						response.WriteString(privateCanary)
					} else {
						response.Write(contents)
					}
				case request.Method == http.MethodDelete:
					id := restclient.FileID(strings.TrimPrefix(request.URL.Path, "/file/"))
					if _, exists := allocated[id]; !exists {
						t.Fatal("cleanup used an unacknowledged cache ID")
					}
					deleted[id]++
					if id == firstInput && tc.cleanupFailure {
						response.WriteHeader(http.StatusServiceUnavailable)
						response.WriteString(privateCanary)
					}
				default:
					t.Fatal("unexpected checker fixture route")
				}
				return response.Result(), nil
			})})
			if err != nil {
				t.Fatal(err)
			}
			a.factory = restFactory{client}
			argv := []string{"/w/main"}
			if tc.checker {
				argv = []string{"/usr/local/bin/startrack-checker-launcher", "/w/default_validator", "/w/input", "/w/answer", "/w/feedback"}
			}
			response, err := a.matureRunBytes(context.Background(), "checker-feedback-proof", argv, nil, nil, checkerLimits())
			if tc.wantCode == "" {
				if err != nil || !response.OK || !response.Compiled || response.WaitStatus != tc.exit<<8 || response.CPUNS != 123 {
					t.Fatal("captured checker outcome changed", err)
				}
				if response.StdoutBase64 != base64.StdEncoding.EncodeToString(stdout) || response.StderrBase64 != base64.StdEncoding.EncodeToString(stderr) || response.FeedbackBase64 != base64.StdEncoding.EncodeToString(tc.feedback) {
					t.Fatal("feedback bytes were lost or mixed with stdio")
				}
			} else {
				var failure *Failure
				if !errors.As(err, &failure) || failure.Code != tc.wantCode || failure.Ambiguous != tc.cleanupFailure {
					t.Fatal("checker capture failure lost structural classification", err)
				}
			}
			if strings.Contains(fmt.Sprintf("%v %v", response, err), privateCanary) {
				t.Fatal("private capture diagnostic escaped redaction")
			}
			if feedbackID != "" && downloaded[feedbackID] != 1 {
				t.Fatal("captured feedback was not downloaded exactly once")
			}
			if runs != 1 || len(allocated) == 0 || len(allocated) != len(deleted) {
				t.Fatal("checker capture omitted execution or acknowledged-cache cleanup")
			}
			for id := range allocated {
				if deleted[id] != 1 {
					t.Fatal("checker capture cleanup omitted or multiply deleted an acknowledged cache ID")
				}
			}
			if tc.cleanupFailure && a.Snapshot(context.Background()).Qualified {
				t.Fatal("checker cleanup fault left the runtime ready")
			}
		})
	}
}
