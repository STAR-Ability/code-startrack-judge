package callbacks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
)

const testToken = "outbound-token-only-36-characters-minimum"
const testRequest contract.UUID = "10000000-0000-4000-8000-000000000001"
const testTask contract.UUID = "20000000-0000-4000-8000-000000000001"
const testEvent contract.UUID = "30000000-0000-4000-8000-000000000001"

func delivery(t *testing.T, revision int64) *Delivery {
	t.Helper()
	timestamp := contract.UTC(time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC))
	task := contract.JudgeTask{TaskBase: contract.TaskBase{RequestID: testRequest, Revision: contract.SafeInt(revision), CreatedAt: timestamp, UpdatedAt: timestamp}, JudgeTaskID: testTask, SubmissionID: "1", Status: contract.JudgeQueued}
	event := contract.CallbackEvent[contract.JudgeTask]{EventID: testEvent, EventType: "JUDGE_TASK_UPDATED", OccurredAt: timestamp, RequestID: testRequest, AggregateID: testTask, Revision: contract.SafeInt(revision), Payload: task}
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = canonical.Canonicalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	return &Delivery{EventID: testEvent, RequestID: testRequest, TaskID: testTask, Revision: revision, PayloadHash: canonical.HashBytes(raw), CanonicalJSON: raw, LeaseToken: "40000000-0000-4000-8000-000000000001", AttemptCount: 1}
}

func mockClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != "backend:8081" {
			return nil, fmt.Errorf("unexpected destination")
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}
	client, err := newClient(testToken, transport)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

func ack(w http.ResponseWriter, duplicate bool) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(contract.ApiResponse[contract.CallbackAck]{Data: contract.CallbackAck{Accepted: true, Duplicate: duplicate}, RequestID: testRequest})
}

func TestExactBodyIdentityAndACK(t *testing.T) {
	d := delivery(t, 1)
	for _, duplicate := range []bool{false, true} {
		client := mockClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" || r.Host != "backend:8081" || r.URL.Path != "/internal/v2/events/judge" || r.Header.Get("X-Request-Id") != string(testRequest) || r.Header.Get("Authorization") != "Bearer "+testToken {
				t.Error("fixed transport/identity/credential mismatch")
			}
			raw, _ := io.ReadAll(r.Body)
			if !bytes.Equal(raw, d.CanonicalJSON) || canonical.HashBytes(raw) != d.PayloadHash {
				t.Error("event bytes changed")
			}
			ack(w, duplicate)
		})
		got := client.Send(context.Background(), d)
		if !got.Accepted || got.Duplicate != duplicate || got.ErrorCode != "" {
			t.Fatalf("ACK=%+v", got)
		}
	}
}

func TestFailureDoesNotBecomeACK(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		code   Code
	}{
		{"auth", 401, "secret-do-not-retain", Unauthorized}, {"forbidden", 403, "", Unauthorized},
		{"mapping-race", 404, "", UnknownTask}, {"conflict", 409, "", Conflict}, {"invalid", 400, "", InvalidArgument},
		{"overloaded", 429, "", Unavailable}, {"server", 503, "", Unavailable}, {"created", 201, "", UnexpectedHTTP}, {"empty", 204, "", UnexpectedHTTP},
		{"missing-accepted", 200, `{"data":{"duplicate":false},"requestId":"` + string(testRequest) + `"}`, InvalidACK},
		{"missing-duplicate", 200, `{"data":{"accepted":true},"requestId":"` + string(testRequest) + `"}`, InvalidACK},
		{"null", 200, `{"data":{"accepted":true,"duplicate":null},"requestId":"` + string(testRequest) + `"}`, InvalidACK},
		{"false", 200, `{"data":{"accepted":false,"duplicate":false},"requestId":"` + string(testRequest) + `"}`, Rejected},
		{"wrong-correlation", 200, `{"data":{"accepted":true,"duplicate":false},"requestId":"` + string(testEvent) + `"}`, InvalidACK},
		{"duplicate-json-key", 200, `{"data":{"accepted":false,"accepted":true,"duplicate":false},"requestId":"` + string(testRequest) + `"}`, InvalidACK},
		{"extra-field", 200, `{"data":{"accepted":true,"duplicate":false,"log":"hidden"},"requestId":"` + string(testRequest) + `"}`, InvalidACK},
		{"bare-ack", 200, `{"accepted":true,"duplicate":false}`, InvalidACK}, {"oversize", 200, strings.Repeat(" ", maxACKBytes+1), InvalidACK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := mockClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			})
			if got := client.Send(context.Background(), delivery(t, 1)); got.Accepted || got.Duplicate || got.ErrorCode != tc.code {
				t.Fatalf("failure=%+v", got)
			}
		})
	}
}

func TestRedirectAndMalformedEventNeverLeakCredential(t *testing.T) {
	hits := 0
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; ack(w, false) }))
	defer other.Close()
	client := mockClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	})
	if got := client.Send(context.Background(), delivery(t, 1)); got.ErrorCode != UnexpectedHTTP || hits != 0 {
		t.Fatalf("redirect=%+v, hits=%d", got, hits)
	}
	d := delivery(t, 1)
	d.CanonicalJSON = append(d.CanonicalJSON, ' ')
	if got := client.Send(context.Background(), d); got.ErrorCode != IntegrityFailure {
		t.Fatal("changed hash sent")
	}
	d.PayloadHash = canonical.HashBytes(d.CanonicalJSON)
	if got := client.Send(context.Background(), d); got.ErrorCode != IntegrityFailure {
		t.Fatal("noncanonical bytes sent")
	}
	if strings.Contains(fmt.Sprintf("%+v %#v", client, client), testToken) {
		t.Fatal("client formatting leaked credential")
	}
}

func TestNetworkCancellationRetainsEvent(t *testing.T) {
	client := mockClient(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := client.Send(ctx, delivery(t, 1)); got.ErrorCode != Unavailable {
		t.Fatalf("cancel=%+v", got)
	}
}

func TestOutOfOrderDuplicateAndMappingRetry(t *testing.T) {
	var mu sync.Mutex
	mapped := false
	revision := int64(0)
	seen := map[string]string{}
	client := mockClient(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if !mapped {
			w.WriteHeader(404)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var e contract.CallbackEvent[contract.JudgeTask]
		if contract.DecodeJSON(raw, &e) != nil {
			w.WriteHeader(400)
			return
		}
		hash := canonical.HashBytes(raw)
		if old, ok := seen[string(e.EventID)]; ok {
			if old != hash {
				w.WriteHeader(409)
				return
			}
			ack(w, true)
			return
		}
		seen[string(e.EventID)] = hash
		if int64(e.Revision) <= revision {
			ack(w, true)
			return
		}
		revision = int64(e.Revision)
		ack(w, false)
	})
	old := delivery(t, 1)
	if client.Send(context.Background(), old).ErrorCode != UnknownTask {
		t.Fatal("mapping failure not retained")
	}
	mapped = true
	newer := delivery(t, 2)
	var e contract.CallbackEvent[contract.JudgeTask]
	if contract.DecodeJSON(newer.CanonicalJSON, &e) != nil {
		t.Fatal("fixture invalid")
	}
	e.EventID = "30000000-0000-4000-8000-000000000002"
	raw, _ := json.Marshal(e)
	newer.CanonicalJSON, _ = canonical.Canonicalize(raw)
	newer.EventID = e.EventID
	newer.PayloadHash = canonical.HashBytes(newer.CanonicalJSON)
	if !client.Send(context.Background(), newer).Accepted {
		t.Fatal("new revision refused")
	}
	if got := client.Send(context.Background(), old); !got.Accepted || !got.Duplicate {
		t.Fatal("stale revision not acknowledged")
	}
	if got := client.Send(context.Background(), old); !got.Accepted || !got.Duplicate {
		t.Fatal("duplicate not acknowledged")
	}
	if revision != 2 {
		t.Fatal("old event regressed backend")
	}
	conflict := delivery(t, 2)
	if got := client.Send(context.Background(), conflict); got.ErrorCode != Conflict {
		t.Fatal("identity conflict accepted")
	}
}

type memoryRepository struct {
	d        *Delivery
	complete Outcome
}

func (r *memoryRepository) Claim(context.Context) (*Delivery, error) { return r.d, nil }
func (r *memoryRepository) Complete(_ context.Context, _ *Delivery, o Outcome) error {
	r.complete = o
	return nil
}

type fixedSender struct{ outcome Outcome }

func (s fixedSender) Send(context.Context, *Delivery) Outcome { return s.outcome }

func TestWorkerBoundsDiagnosticsAndInvalidSender(t *testing.T) {
	var logs bytes.Buffer
	repo := &memoryRepository{d: delivery(t, 1)}
	worker, err := NewWorker(repo, fixedSender{Outcome{Accepted: true, ErrorCode: Conflict}}, slog.New(slog.NewJSONHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if did, err := worker.RunOnce(context.Background()); !did || err != nil {
		t.Fatal("worker did not reserve/complete")
	}
	if repo.complete.Accepted || repo.complete.ErrorCode != InvalidACK {
		t.Fatal("invalid sender outcome delivered")
	}
	if strings.Contains(logs.String(), "payload") || strings.Contains(logs.String(), testToken) || strings.Contains(logs.String(), "sourceCode") {
		t.Fatal("unsafe callback logging")
	}
}

func TestFullDayRetryClock(t *testing.T) {
	deadline := 24 * time.Hour
	elapsed := time.Duration(0)
	attempt := 0
	var first []time.Duration
	for elapsed < deadline {
		attempt++
		delay := Backoff(attempt)
		if attempt <= 6 {
			first = append(first, delay)
		}
		elapsed += delay
		if elapsed > deadline {
			elapsed = deadline
		}
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second}
	for i := range want {
		if first[i] != want[i] {
			t.Fatal("retry sequence changed")
		}
	}
	if elapsed != deadline || attempt != 2884 || Backoff(attempt) != 30*time.Second {
		t.Fatalf("original window: elapsed=%s attempts=%d", elapsed, attempt)
	}
}
