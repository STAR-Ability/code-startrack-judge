package restclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testToken = "runtime-only-test-canary-credential-1234567890"
const inputID FileID = "ABCD2345"
const stdoutID FileID = "EFGH2345"
const stderrID FileID = "IJKL2345"

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func mockClient(t *testing.T, limits Limits, handler http.HandlerFunc) *Client {
	t.Helper()
	client, err := New(Options{Token: testToken, Limits: limits, RoundTripper: transportFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme != "http" || r.URL.Host != "127.0.0.1:5050" || r.Host != "127.0.0.1:5050" {
			t.Errorf("destination escaped: %s", r.URL)
		}
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			t.Error("missing scoped runtime auth")
		}
		if r.Header.Get("Accept-Encoding") != "identity" {
			t.Error("unexpected content decoding")
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, r)
		return recorder.Result(), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func fixtureRequest() Request {
	return Request{RequestID: "task-42-attempt-1", Commands: []Command{{
		Args:          []string{"/usr/bin/g++", "-std=c++17", "main.cc", "-o", "main"},
		Env:           []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"},
		Files:         []File{{ID: inputID}, {Collector: "stdout", LimitBytes: 64}, {Collector: "stderr", LimitBytes: 64}},
		CopyIn:        map[string]FileID{"main.cc": inputID},
		CopyOutCached: []Output{{Name: "stdout"}, {Name: "stderr"}},
		CPULimitNS:    1_000_000_123, ClockLimitNS: 2_000_000_456, MemoryLimitBytes: 2_097_153,
		StackLimitBytes: 1_048_576, ProcessLimit: 16, CopyOutMaxBytes: 128,
		StrictMemoryLimit: true, DataSegmentLimit: true, AddressSpaceLimit: true,
	}}}
}

func fixtureResponse(status Status) string {
	return fmt.Sprintf(`[{"status":%q,"exitStatus":0,"time":30000123,"memory":2097153,"runTime":52000456,"procPeak":2,"fileIds":{"stdout":"EFGH2345","stderr":"IJKL2345"}}]`, status)
}

func requireKind(t *testing.T, err error, want ErrorKind, retryable bool) {
	t.Helper()
	var failure *Error
	if !errors.As(err, &failure) || failure.Kind != want || failure.Retryable != retryable {
		t.Fatalf("got %v, want %s retryable=%v", err, want, retryable)
	}
	if strings.Contains(err.Error(), testToken) || strings.Contains(err.Error(), "hidden-answer-canary") {
		t.Fatal("raw diagnostic leaked")
	}
}

func TestMultipartCachedBinaryRoundtripAndCancellationCleanup(t *testing.T) {
	input := []byte{0x00, 0xff, 0xc3, 0x28, 0x80, '\r', '\n'}
	output := []byte{0xff, 0x00, 0xfe, 0x01}
	deleted := make(map[FileID]int)
	client := mockClient(t, Limits{}, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/file":
			mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil || mediaType != "multipart/form-data" {
				t.Fatal("wrong upload media type")
			}
			reader := multipart.NewReader(r.Body, params["boundary"])
			part, err := reader.NextPart()
			if err != nil {
				t.Fatal(err)
			}
			if part.FormName() != "file" || part.FileName() != "blob" {
				t.Fatal("unowned multipart metadata")
			}
			got, err := io.ReadAll(part)
			if err != nil || !bytes.Equal(got, input) {
				t.Fatal("binary input changed")
			}
			if _, err := reader.NextPart(); !errors.Is(err, io.EOF) {
				t.Fatal("extra multipart fields")
			}
			_, _ = fmt.Fprintf(w, "%q", inputID)
		case r.Method == "POST" && r.URL.Path == "/run":
			var raw map[string]any
			if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
				t.Fatal(err)
			}
			if raw["requestId"] != "task-42-attempt-1" {
				t.Fatal("execution correlation changed")
			}
			cmd := raw["cmd"].([]any)[0].(map[string]any)
			for key, want := range map[string]float64{"cpuLimit": 1_000_000_123, "clockLimit": 2_000_000_456, "memoryLimit": 2_097_153, "stackLimit": 1_048_576, "procLimit": 16, "copyOutMax": 128} {
				if cmd[key] != want {
					t.Errorf("%s: got %v, want %v", key, cmd[key], want)
				}
			}
			for _, absent := range []string{"cpuTimeLimit", "clockTimeLimit", "copyOut", "realCpuLimit", "tty", "pipeMapping"} {
				if _, found := cmd[absent]; found {
					t.Errorf("unsupported wire field %s", absent)
				}
			}
			files := cmd["files"].([]any)
			if files[0].(map[string]any)["fileId"] != string(inputID) || len(files[0].(map[string]any)) != 1 {
				t.Fatal("input bypassed binary cache")
			}
			copyIn := cmd["copyIn"].(map[string]any)["main.cc"].(map[string]any)
			if copyIn["fileId"] != string(inputID) || len(copyIn) != 1 {
				t.Fatal("copy-in was not cached")
			}
			if cmd["strictMemoryLimit"] != true || cmd["dataSegmentLimit"] != true || cmd["addressSpaceLimit"] != true {
				t.Fatal("memory policy changed")
			}
			_, _ = io.WriteString(w, fixtureResponse(Accepted))
		case r.Method == "GET" && r.URL.Path == "/file/"+string(stdoutID):
			_, _ = w.Write(output)
		case r.Method == "GET" && r.URL.Path == "/file/"+string(stderrID):
			_, _ = w.Write([]byte{0})
		case r.Method == "DELETE":
			if r.Context().Err() != nil {
				t.Fatal("cleanup inherited cancelled context")
			}
			id := FileID(strings.TrimPrefix(r.URL.Path, "/file/"))
			deleted[id]++
			w.WriteHeader(200)
		default:
			t.Fatalf("unexpected call %s %s", r.Method, r.URL.Path)
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	session := client.NewSession()
	id, err := session.Upload(ctx, input)
	if err != nil || id != inputID {
		t.Fatalf("upload: %v", err)
	}
	results, err := session.Run(ctx, fixtureRequest())
	if err != nil {
		t.Fatal(err)
	}
	result := results[0]
	if result.Status != Accepted || result.CPUTimeNS != 30_000_123 || result.WallTimeNS != 52_000_456 || result.MemoryBytes != 2_097_153 || result.ProcessPeak != 2 {
		t.Fatal("result units changed")
	}
	got, err := session.Download(ctx, result.CachedFiles["stdout"], 64)
	if err != nil || !bytes.Equal(got, output) {
		t.Fatal("binary output changed")
	}
	got, err = session.Download(ctx, result.CachedFiles["stderr"], 64)
	if err != nil || !bytes.Equal(got, []byte{0}) {
		t.Fatal("NUL stderr changed")
	}
	cancel()
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	for _, id := range []FileID{inputID, stdoutID, stderrID} {
		if deleted[id] != 1 {
			t.Errorf("cleanup count for owned ID: %d", deleted[id])
		}
	}
}

func TestStatusAndUnitMapping(t *testing.T) {
	for _, status := range []Status{Invalid, Accepted, WrongAnswer, PartiallyCorrect, MemoryLimit, TimeLimit, OutputLimit, FileError, NonzeroExit, Signalled, DangerousSyscall, JudgementFailed, InvalidInteraction, InternalError} {
		t.Run(string(status), func(t *testing.T) {
			client := mockClient(t, Limits{}, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, fixtureResponse(status)) })
			results, err := client.Run(context.Background(), fixtureRequest())
			if err != nil || results[0].Status != status || results[0].CPUTimeNS != 30_000_123 || results[0].MemoryBytes != 2_097_153 {
				t.Fatalf("mapping failed: %v", err)
			}
		})
	}
}

func TestIntegerUnitsAboveJSONFloatPrecision(t *testing.T) {
	const exact uint64 = 9_007_199_254_740_993
	request := fixtureRequest()
	request.Commands[0].CPULimitNS = exact
	request.Commands[0].ClockLimitNS = exact + 2
	request.Commands[0].MemoryLimitBytes = exact + 4
	client := mockClient(t, Limits{}, func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		decoder.UseNumber()
		var raw map[string]any
		if err := decoder.Decode(&raw); err != nil {
			t.Fatal(err)
		}
		command := raw["cmd"].([]any)[0].(map[string]any)
		for key, want := range map[string]uint64{"cpuLimit": exact, "clockLimit": exact + 2, "memoryLimit": exact + 4} {
			if command[key].(json.Number).String() != fmt.Sprint(want) {
				t.Errorf("%s integer lost precision", key)
			}
		}
		_, _ = fmt.Fprintf(w, `[{"status":"Accepted","exitStatus":0,"time":%d,"memory":%d,"runTime":%d,"fileIds":{"stdout":"EFGH2345","stderr":"IJKL2345"}}]`, exact, exact+4, exact+2)
	})
	results, err := client.Run(context.Background(), request)
	if err != nil || results[0].CPUTimeNS != exact || results[0].WallTimeNS != exact+2 || results[0].MemoryBytes != exact+4 {
		t.Fatalf("response integer lost precision: %v", err)
	}
}

func TestProtocolErrorsAndOutputReclamation(t *testing.T) {
	valid := fixtureResponse(Accepted)
	cases := map[string]string{
		"grpc-envelope":           `{"results":` + valid + `}`,
		"unknown-status":          strings.Replace(valid, "Accepted", "AC", 1),
		"unknown-field":           strings.Replace(valid, `"status"`, `"unexpected":true,"status"`, 1),
		"missing-measurement":     strings.Replace(valid, `"time":30000123,`, "", 1),
		"duplicate-member":        strings.Replace(valid, `"status":"Accepted"`, `"status":"Accepted","status":"Accepted"`, 1),
		"trailing-value":          valid + ` {}`,
		"missing-result":          `[]`,
		"null-result":             `null`,
		"invalid-id":              strings.Replace(valid, "EFGH2345", "../../host", 1),
		"unrequested-output":      strings.Replace(valid, "stdout", "hidden-answer-canary", 1),
		"input-as-output":         strings.Replace(valid, "EFGH2345", "ABCD2345", 1),
		"aliased-outputs":         strings.Replace(valid, "IJKL2345", "EFGH2345", 1),
		"inline-output":           strings.Replace(valid, `"fileIds"`, `"files":{"stdout":"hidden-answer-canary"},"fileIds"`, 1),
		"negative-duration":       strings.Replace(valid, "30000123", "-1", 1),
		"duration-overflow":       strings.Replace(valid, "30000123", "18446744073709551615", 1),
		"nonfinite-duration":      strings.Replace(valid, "30000123", "1e999", 1),
		"missing-required-output": strings.Replace(valid, `"stdout":"EFGH2345",`, "", 1),
		"invalid-utf8":            "[\xff]",
		"invalid-surrogate":       strings.Replace(valid, `"fileIds"`, `"error":"\ud800","fileIds"`, 1),
	}
	for name, response := range cases {
		t.Run(name, func(t *testing.T) {
			client := mockClient(t, Limits{}, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "DELETE" {
					w.WriteHeader(200)
					return
				}
				_, _ = io.WriteString(w, response)
			})
			_, err := client.Run(context.Background(), fixtureRequest())
			requireKind(t, err, ProtocolError, false)
		})
	}
	deleted := make(map[string]bool)
	client := mockClient(t, Limits{}, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			deleted[r.URL.Path] = true
			w.WriteHeader(200)
			return
		}
		_, _ = io.WriteString(w, strings.Replace(valid, "Accepted", "corrupt", 1))
	})
	_, err := client.Run(context.Background(), fixtureRequest())
	requireKind(t, err, ProtocolError, false)
	if !deleted["/file/"+string(stdoutID)] || !deleted["/file/"+string(stderrID)] || deleted["/file/"+string(inputID)] {
		t.Fatal("protocol failure did not safely reclaim acknowledged outputs")
	}
	client = mockClient(t, Limits{}, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			w.WriteHeader(503)
			return
		}
		_, _ = io.WriteString(w, strings.Replace(valid, "Accepted", "corrupt", 1))
	})
	_, err = client.Run(context.Background(), fixtureRequest())
	requireKind(t, err, ProtocolError, false)
	var failure *Error
	if !errors.As(err, &failure) || !failure.CleanupFailed {
		t.Fatal("protocol cleanup failure hidden")
	}
}

func TestInputValidationRejectsUnsafeTransportFeatures(t *testing.T) {
	mutations := map[string]func(*Request){
		"host-path":             func(r *Request) { r.Commands[0].CopyIn = map[string]FileID{"../../etc/passwd": inputID} },
		"url-file-id":           func(r *Request) { r.Commands[0].Files[0].ID = "http://remote" },
		"ambiguous-file":        func(r *Request) { r.Commands[0].Files[0].Collector = "stdout" },
		"secret-environment":    func(r *Request) { r.Commands[0].Env = []string{"BACKEND_JUDGE_TOKEN=" + testToken} },
		"duplicate-environment": func(r *Request) { r.Commands[0].Env = []string{"PATH=/usr/bin", "PATH=/bin"} },
		"nul-argv":              func(r *Request) { r.Commands[0].Args[1] = "a\x00b" },
		"invalid-utf8-argv":     func(r *Request) { r.Commands[0].Args[1] = "a\xffb" },
		"missing-clock-limit":   func(r *Request) { r.Commands[0].ClockLimitNS = 0 },
		"duration-overflow":     func(r *Request) { r.Commands[0].CPULimitNS = ^uint64(0) },
		"unbounded-output":      func(r *Request) { r.Commands[0].Files[1].LimitBytes = 0 },
		"unbounded-processes":   func(r *Request) { r.Commands[0].ProcessLimit = 0 },
		"absolute-output":       func(r *Request) { r.Commands[0].CopyOutCached[0].Name = "/etc/secret" },
		"duplicate-output":      func(r *Request) { r.Commands[0].CopyOutCached[1].Name = "stdout" },
		"uncached-collector":    func(r *Request) { r.Commands[0].CopyOutCached = []Output{{Name: "stderr"}} },
		"duplicate-collector":   func(r *Request) { r.Commands[0].Files[2].Collector = "stdout" },
		"stdin-collector":       func(r *Request) { r.Commands[0].Files[0] = File{Collector: "stdout", LimitBytes: 64} },
		"cached-stdout":         func(r *Request) { r.Commands[0].Files[1] = File{ID: inputID} },
		"command-count":         func(r *Request) { r.Commands = nil },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			client := mockClient(t, Limits{}, func(http.ResponseWriter, *http.Request) { t.Fatal("invalid request reached transport") })
			request := fixtureRequest()
			mutate(&request)
			_, err := client.Run(context.Background(), request)
			requireKind(t, err, RequestError, false)
		})
	}
}

func TestBoundsAndResponseClosing(t *testing.T) {
	client := mockClient(t, Limits{FileBytes: 3}, func(http.ResponseWriter, *http.Request) { t.Fatal("oversized upload reached transport") })
	_, err := client.Upload(context.Background(), []byte{1, 2, 3, 4})
	requireKind(t, err, BoundsError, false)
	for _, contentLength := range []int64{-1, 100} {
		t.Run(fmt.Sprint(contentLength), func(t *testing.T) {
			closed := atomic.Bool{}
			client, err := New(Options{Token: testToken, RoundTripper: transportFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Header: make(http.Header), ContentLength: contentLength, Body: &closingReader{Reader: strings.NewReader("1234"), closed: &closed}}, nil
			})})
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Download(context.Background(), inputID, 3)
			requireKind(t, err, BoundsError, false)
			if !closed.Load() {
				t.Fatal("bounded response leaked body")
			}
		})
	}
	client = mockClient(t, Limits{RequestBytes: 3}, func(http.ResponseWriter, *http.Request) { t.Fatal("oversized JSON request reached transport") })
	_, err = client.Run(context.Background(), fixtureRequest())
	requireKind(t, err, BoundsError, false)
	client = mockClient(t, Limits{ResponseBytes: 3}, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `"ABCD2345"`) })
	_, err = client.Upload(context.Background(), []byte{})
	requireKind(t, err, BoundsError, false)
	client = mockClient(t, Limits{Files: 4}, func(http.ResponseWriter, *http.Request) { t.Fatal("file-count overflow reached transport") })
	_, err = client.Run(context.Background(), fixtureRequest())
	requireKind(t, err, BoundsError, false)
}

type closingReader struct {
	io.Reader
	closed *atomic.Bool
}

func (r *closingReader) Close() error { r.closed.Store(true); return nil }

func TestFixedDestinationRedirectsProxyAndCredentialRedaction(t *testing.T) {
	for _, token := range []string{"", "short", "GENERATED_placeholder_that_is_at_least_32_chars", testToken + "\n"} {
		_, err := New(Options{Token: token})
		requireKind(t, err, ConfigurationError, false)
	}
	_, err := New(Options{Token: testToken, Limits: Limits{FileBytes: 65 << 20}})
	requireKind(t, err, ConfigurationError, false)
	t.Setenv("HTTP_PROXY", "http://proxy-secret-canary.example:1")
	t.Setenv("HTTPS_PROXY", "http://proxy-secret-canary.example:1")
	production, err := New(Options{Token: testToken})
	if err != nil {
		t.Fatal(err)
	}
	transport := production.http.Transport.(fixedTransport).next.(*http.Transport)
	if transport.Proxy != nil || !transport.DisableCompression {
		t.Fatal("proxy/compression enabled")
	}
	if _, err := transport.DialContext(context.Background(), "tcp", "example.com:80"); err == nil {
		t.Fatal("dial escaped fixed loopback")
	}
	for _, formatted := range []string{fmt.Sprintf("%v", production), fmt.Sprintf("%#v", production), fmt.Sprintf("%+v", Options{Token: testToken})} {
		if strings.Contains(formatted, testToken) {
			t.Fatal("credential formatting leak")
		}
	}
	encoded, _ := json.Marshal(Options{Token: testToken})
	if bytes.Contains(encoded, []byte(testToken)) {
		t.Fatal("credential JSON leak")
	}
	calls := 0
	client := mockClient(t, Limits{}, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Location", "http://remote.example/steal")
		w.WriteHeader(302)
	})
	_, err = client.Upload(context.Background(), []byte{0})
	requireKind(t, err, RedirectError, false)
	if calls != 1 {
		t.Fatal("redirect followed")
	}
	for _, address := range []string{"http://example.com:5050/file", "http://127.0.0.1:5051/file", "https://127.0.0.1:5050/file", Endpoint + "/config", Endpoint + "/file/../../etc", Endpoint + "/file?remote=1"} {
		r, _ := http.NewRequest("POST", address, nil)
		_, err := (fixedTransport{next: transportFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("unsafe request reached underlying transport")
			return nil, nil
		})}).RoundTrip(r)
		requireKind(t, err, TransportError, false)
	}
}

func TestStatusErrorsAreSanitizedAndClassified(t *testing.T) {
	for _, item := range []struct {
		status    int
		kind      ErrorKind
		retryable bool
	}{{400, RejectedError, false}, {401, AuthenticationError, false}, {403, AuthenticationError, false}, {404, MissingFileError, false}, {429, UnavailableError, true}, {500, UnavailableError, true}, {503, UnavailableError, true}} {
		t.Run(fmt.Sprint(item.status), func(t *testing.T) {
			client := mockClient(t, Limits{}, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(item.status)
				_, _ = io.WriteString(w, testToken+" hidden-answer-canary")
			})
			_, err := client.Download(context.Background(), inputID, 128)
			requireKind(t, err, item.kind, item.retryable)
		})
	}
	client := mockClient(t, Limits{}, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(404) })
	if err := client.Delete(context.Background(), inputID); err != nil {
		t.Fatal("already-removed cache entry was not idempotent")
	}
	client = mockClient(t, Limits{}, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = io.WriteString(w, "compressed")
	})
	_, err := client.Download(context.Background(), inputID, 128)
	requireKind(t, err, ProtocolError, false)
	client, err = New(Options{Token: testToken, RoundTripper: transportFunc(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("%s hidden-answer-canary", testToken)
	})})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Download(context.Background(), inputID, 128)
	requireKind(t, err, TransportError, true)
}

func TestCancellationAndOwnedSessionCleanupFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	client := mockClient(t, Limits{}, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			if r.Context().Err() != nil {
				t.Fatal("cancelled cleanup")
			}
			calls++
			w.WriteHeader(200)
			return
		}
		_, _ = fmt.Fprintf(w, "%q", inputID)
	})
	session := client.NewSession()
	if _, err := session.Upload(ctx, []byte{0}); err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := session.Run(ctx, fixtureRequest()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel not preserved: %v", err)
	}
	if err := session.Close(); err != nil || calls != 1 {
		t.Fatal("owned cancelled input not reclaimed")
	}
	if _, err := session.Upload(context.Background(), nil); err == nil {
		t.Fatal("closed session accepted files")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	client, err := New(Options{Token: testToken, RoundTripper: transportFunc(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() })})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Download(ctx, inputID, 128)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("deadline not preserved")
	}
	deletes := 0
	client = mockClient(t, Limits{}, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			deletes++
			if deletes == 1 {
				w.WriteHeader(503)
			} else {
				w.WriteHeader(200)
			}
			return
		}
		_, _ = fmt.Fprintf(w, "%q", inputID)
	})
	session = client.NewSession()
	if _, err := session.Upload(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	requireKind(t, session.Close(), CleanupError, true)
	if err := session.Close(); err != nil || deletes != 2 {
		t.Fatal("failed cleanup could not retry owned IDs")
	}
	client = mockClient(t, Limits{}, func(http.ResponseWriter, *http.Request) { t.Fatal("session used foreign cached input") })
	session = client.NewSession()
	_, err = session.Run(context.Background(), fixtureRequest())
	requireKind(t, err, RequestError, false)
}

func TestInFlightCancellationPreservesOwnedInputCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	deleted := atomic.Bool{}
	client, err := New(Options{Token: testToken, RoundTripper: transportFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/run" {
			close(started)
			<-r.Context().Done()
			return nil, r.Context().Err()
		}
		recorder := httptest.NewRecorder()
		if r.Method == "DELETE" {
			if r.Context().Err() != nil {
				t.Error("cleanup context inherited cancellation")
			}
			deleted.Store(true)
		} else {
			_, _ = fmt.Fprintf(recorder, "%q", inputID)
		}
		return recorder.Result(), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	session := client.NewSession()
	if _, err := session.Upload(ctx, nil); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := session.Run(ctx, fixtureRequest()); done <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("execution did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("in-flight cancellation not preserved: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("execution did not cancel")
	}
	if err := session.Close(); err != nil || !deleted.Load() {
		t.Fatal("in-flight cancellation lost acknowledged input cleanup")
	}
}

func TestOptionalOutputsAndPrivateDiagnostics(t *testing.T) {
	request := fixtureRequest()
	request.Commands[0].CopyOutCached = append(request.Commands[0].CopyOutCached, Output{Name: "main", Optional: true})
	client := mockClient(t, Limits{}, func(w http.ResponseWriter, r *http.Request) {
		var raw map[string]any
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
			t.Fatal(err)
		}
		copyOut := raw["cmd"].([]any)[0].(map[string]any)["copyOutCached"].([]any)
		if len(copyOut) != 3 || copyOut[2] != "main?" {
			t.Fatal("optional suffix mismatch")
		}
		_, _ = io.WriteString(w, `[{"status":"Nonzero Exit Status","exitStatus":1,"time":0,"memory":0,"runTime":0,"error":"hidden-answer-canary","fileError":[{"name":"/private/answer","type":"CopyOutOpen","message":"hidden-answer-canary"}]}]`)
	})
	results, err := client.Run(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	result := results[0]
	if result.Status != NonzeroExit || !result.HasError || result.FileErrorCount != 1 {
		t.Fatal("lost structural diagnostics")
	}
	encoded, _ := json.Marshal(result)
	if bytes.Contains(encoded, []byte("hidden-answer-canary")) || strings.Contains(fmt.Sprintf("%#v", result), "/private/answer") {
		t.Fatal("private diagnostics retained")
	}
}

func TestPinnedFileErrorStringEnums(t *testing.T) {
	for _, kind := range []string{"CopyInOpenFile", "CopyInCreateDir", "CopyInCreateFile", "CopyInCopyContent", "CopyOutOpen", "CopyOutNotRegularFile", "CopyOutSizeExceeded", "CopyOutCreateFile", "CopyOutCopyContent", "CollectSizeExceeded", "Symlink"} {
		t.Run(kind, func(t *testing.T) {
			status := FileError
			if kind == "CopyOutSizeExceeded" || kind == "CollectSizeExceeded" {
				status = OutputLimit
			}
			client := mockClient(t, Limits{}, func(w http.ResponseWriter, _ *http.Request) {
				_, _ = fmt.Fprintf(w, `[{"status":%q,"exitStatus":0,"time":123,"memory":456,"runTime":789,"fileError":[{"name":"stdout","type":%q,"message":"hidden-answer-canary"}]}]`, status, kind)
			})
			results, err := client.Run(context.Background(), fixtureRequest())
			if err != nil || len(results) != 1 || results[0].Status != status || results[0].FileErrorCount != 1 || len(results[0].FileErrorTypes) != 1 || results[0].FileErrorTypes[0] != FileErrorType(kind) {
				t.Fatalf("pinned file error response rejected: %v", err)
			}
		})
	}
	for _, raw := range []string{`4`, `"ErrCopyOutOpen"`, `"unknown"`, `null`} {
		t.Run("invalid-"+raw, func(t *testing.T) {
			client := mockClient(t, Limits{}, func(w http.ResponseWriter, _ *http.Request) {
				_, _ = fmt.Fprintf(w, `[{"status":"File Error","exitStatus":0,"time":0,"memory":0,"runTime":0,"fileError":[{"name":"stdout","type":%s}]}]`, raw)
			})
			_, err := client.Run(context.Background(), fixtureRequest())
			requireKind(t, err, ProtocolError, false)
		})
	}
}
