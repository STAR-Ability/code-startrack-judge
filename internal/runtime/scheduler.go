package runtime

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/config"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
)

const SchedulerSocket = "/run/startrack/judger.sock"
const MaxControlBytes = 64 << 20
const MaxAttemptBlobBytes = 512 << 20

type schedulerControl struct {
	Task       *TaskInput       `json:"task"`
	Validation *ValidationInput `json:"validation"`
	Mature     *MatureInput     `json:"mature"`
}
type schedulerEvent struct {
	Sequence     uint64              `json:"sequence"`
	FencingToken contract.UUID       `json:"fencingToken"`
	Progress     *Progress           `json:"progress"`
	Outcome      *Outcome            `json:"outcome"`
	Validation   *ValidationOutcome  `json:"validation"`
	Failure      *Failure            `json:"failure"`
	Evidence     *ValidationEvidence `json:"evidence"`
	Mature       *MatureOutcome      `json:"mature"`
	PrivateLog   []byte              `json:"privateLog,omitempty"`
}

func (schedulerEvent) String() string     { return "private scheduler event [evidence redacted]" }
func (e schedulerEvent) GoString() string { return e.String() }

type schedulerAck struct {
	FencingToken contract.UUID `json:"fencingToken"`
	Sequence     uint64        `json:"sequence"`
	Accepted     bool          `json:"accepted"`
}
type pendingAck struct {
	sequence uint64
	response chan bool
}

type SchedulerServer struct {
	adapter     *Adapter
	token       string
	spoolRoot   string
	capacity    chan struct{}
	waiters     chan struct{}
	removeSpool func(string) error
	mu          sync.Mutex
	active      map[contract.UUID]*pendingAck
}

func (s *SchedulerServer) String() string   { return "private scheduler server [credentials redacted]" }
func (s *SchedulerServer) GoString() string { return s.String() }
func NewSchedulerServer(adapter *Adapter, token, spoolRoot string) (*SchedulerServer, error) {
	if adapter == nil || !config.ValidServiceToken(token) || !filepath.IsAbs(spoolRoot) || filepath.Clean(spoolRoot) != spoolRoot {
		return nil, failure("SCHEDULER_CONFIGURATION_INVALID", false)
	}
	info, e := os.Lstat(spoolRoot)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return nil, failure("SCHEDULER_CONFIGURATION_INVALID", false)
	}
	return &SchedulerServer{adapter: adapter, token: token, spoolRoot: spoolRoot, capacity: make(chan struct{}, 1), waiters: make(chan struct{}, 128), removeSpool: os.RemoveAll, active: map[contract.UUID]*pendingAck{}}, nil
}
func (s *SchedulerServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if recover() != nil {
			s.adapter.failClosed()
			// net/http suppresses the panic value and stack for ErrAbortHandler.
			// No private program, token or tool diagnostic reaches its ErrorLog.
			panic(http.ErrAbortHandler)
		}
	}()
	if r.URL == nil || r.URL.RawQuery != "" || r.URL.Fragment != "" || r.URL.RawPath != "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.token)) != 1 {
		http.Error(w, "scheduler authorization failed", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/snapshot":
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.adapter.Snapshot(r.Context()))
	case r.Method == http.MethodPost && r.URL.Path == "/ack":
		s.ack(w, r)
	case r.Method == http.MethodPost && (r.URL.Path == "/execute" || r.URL.Path == "/validate" || r.URL.Path == "/mature"):
		s.execute(w, r)
	default:
		http.Error(w, "scheduler route unavailable", http.StatusNotFound)
	}
}
func strictDecode(raw []byte, target any) error {
	if canonical.ValidateJSON(raw) != nil {
		return failure("SCHEDULER_PROTOCOL_INVALID", false)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		return failure("SCHEDULER_PROTOCOL_INVALID", false)
	}
	if e := d.Decode(new(any)); !errors.Is(e, io.EOF) {
		return failure("SCHEDULER_PROTOCOL_INVALID", false)
	}
	return nil
}
func (s *SchedulerServer) ack(w http.ResponseWriter, r *http.Request) {
	raw, e := io.ReadAll(io.LimitReader(r.Body, 4097))
	var ack schedulerAck
	if e != nil || len(raw) > 4096 || strictDecode(raw, &ack) != nil || ack.FencingToken.Validate() != nil || ack.Sequence == 0 {
		http.Error(w, "scheduler acknowledgment invalid", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	pending := s.active[ack.FencingToken]
	if pending == nil || pending.sequence != ack.Sequence {
		s.mu.Unlock()
		http.Error(w, "scheduler acknowledgment stale", http.StatusConflict)
		return
	}
	select {
	case pending.response <- ack.Accepted:
		delete(s.active, ack.FencingToken)
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "scheduler acknowledgment duplicate", http.StatusConflict)
	}
	s.mu.Unlock()
}
func (s *SchedulerServer) execute(w http.ResponseWriter, r *http.Request) {
	select {
	case s.waiters <- struct{}{}:
		defer func() { <-s.waiters }()
	default:
		http.Error(w, "scheduler capacity unavailable", http.StatusServiceUnavailable)
		return
	}
	select {
	case s.capacity <- struct{}{}:
		defer func() { <-s.capacity }()
	case <-r.Context().Done():
		http.Error(w, "scheduler request cancelled", http.StatusRequestTimeout)
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	control, reader, cleanup, e := s.readInput(w, r)
	if e != nil {
		http.Error(w, "scheduler input invalid", http.StatusBadRequest)
		return
	}
	cleaned := false
	defer func() {
		if !cleaned {
			if cleanup() != nil {
				s.adapter.failClosed()
			}
		}
	}()
	if (r.URL.Path == "/execute" && (control.Task == nil || control.Validation != nil || control.Mature != nil)) || (r.URL.Path == "/validate" && (control.Validation == nil || control.Task != nil || control.Mature != nil)) || (r.URL.Path == "/mature" && (control.Mature == nil || control.Task != nil || control.Validation != nil)) {
		http.Error(w, "scheduler input invalid", http.StatusBadRequest)
		return
	}
	ctx = context.WithValue(ctx, blobReaderContextKey{}, reader)
	var fence contract.UUID
	if control.Task != nil {
		fence = control.Task.FencingToken
	} else if control.Validation != nil {
		fence = control.Validation.FencingToken
	} else {
		fence = control.Mature.FencingToken
	}
	if fence.Validate() != nil {
		http.Error(w, "scheduler fence invalid", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	encoder := json.NewEncoder(w)
	sequence := uint64(0)
	flush := func() {
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
	progress := func(ctx context.Context, p Progress) error {
		sequence++
		pending := &pendingAck{sequence: sequence, response: make(chan bool, 1)}
		s.mu.Lock()
		if s.active[fence] != nil {
			s.mu.Unlock()
			return failure("SCHEDULER_FENCE_DUPLICATE", true)
		}
		s.active[fence] = pending
		s.mu.Unlock()
		defer func() {
			s.mu.Lock()
			if s.active[fence] == pending {
				delete(s.active, fence)
			}
			s.mu.Unlock()
		}()
		if e := encoder.Encode(schedulerEvent{Sequence: sequence, FencingToken: fence, Progress: &p}); e != nil {
			return failure("SCHEDULER_STREAM_FAILED", true)
		}
		flush()
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		select {
		case accepted := <-pending.response:
			if !accepted {
				return failure("SCHEDULER_ACK_REJECTED", true)
			}
			return nil
		case <-ctx.Done():
			return failure("SCHEDULER_STREAM_FAILED", true)
		case <-timer.C:
			return failure("SCHEDULER_ACK_EXPIRED", true)
		}
	}
	event := schedulerEvent{FencingToken: fence}
	if control.Task != nil {
		out, e := s.adapter.Execute(ctx, *control.Task, progress)
		if e != nil {
			event.Failure = boundedFailure(e)
		} else {
			event.Outcome = &out
		}
	} else if control.Validation != nil {
		out, e := s.adapter.ValidateProgramsWithEvidence(ctx, *control.Validation, func(_ context.Context, evidence ValidationEvidence) error {
			if e := encoder.Encode(schedulerEvent{FencingToken: fence, Evidence: &evidence}); e != nil {
				return failure("SCHEDULER_STREAM_FAILED", true)
			}
			flush()
			return nil
		})
		if e != nil {
			event.Failure = boundedFailure(e)
		} else {
			event.Validation = &out
		}
	} else {
		out, e := s.adapter.RunMature(ctx, *control.Mature)
		if e != nil {
			event.Failure = boundedFailure(e)
			event.PrivateLog = out.RawLog
		} else {
			event.Mature = &out
		}
	}
	if e := cleanup(); e != nil {
		s.adapter.failClosed()
		privateLog := event.PrivateLog
		if event.Mature != nil {
			privateLog = event.Mature.RawLog
		}
		event = schedulerEvent{FencingToken: fence, Failure: failure("SCHEDULER_SPOOL_CLEANUP_FAILED", true), PrivateLog: privateLog}
	}
	cleaned = true
	encoder.Encode(event)
	flush()
}
func boundedFailure(e error) *Failure {
	var f *Failure
	if errors.As(e, &f) {
		return f
	}
	return failure("SCHEDULER_OPERATION_FAILED", true)
}

func controlRefs(c schedulerControl) (map[string]BlobRef, error) {
	refs := map[string]BlobRef{}
	add := func(ref BlobRef) error {
		if !ref.valid() {
			return failure("SCHEDULER_BLOB_INVALID", false)
		}
		if prior, exists := refs[ref.SHA256]; exists && prior != ref {
			return failure("SCHEDULER_BLOB_INVALID", false)
		}
		refs[ref.SHA256] = ref
		return nil
	}
	var cases []Case
	if c.Task != nil {
		cases = c.Task.Cases
	}
	if c.Validation != nil {
		cases = c.Validation.Cases
		for _, p := range append(append([]Program{}, c.Validation.InputValidators...), c.Validation.AcceptedReferences...) {
			if e := add(p.File); e != nil {
				return nil, e
			}
		}
	}
	if c.Mature != nil {
		if !c.Mature.valid() {
			return nil, failure("MATURE_INPUT_INVALID", false)
		}
		for _, f := range c.Mature.Manifest.Files {
			if e := add(BlobRef{SHA256: f.NormalizedSHA256, SizeBytes: f.NormalizedSizeBytes}); e != nil {
				return nil, e
			}
		}
	}
	for _, test := range cases {
		if e := add(test.Input); e != nil {
			return nil, e
		}
		if e := add(test.Answer); e != nil {
			return nil, e
		}
	}
	total := int64(0)
	for _, ref := range refs {
		total += ref.SizeBytes
		if total > MaxAttemptBlobBytes {
			return nil, failure("SCHEDULER_BLOB_BOUNDS", false)
		}
	}
	return refs, nil
}

type spoolReader struct {
	directory string
	refs      map[string]BlobRef
}

func (s *spoolReader) ReadBlob(ctx context.Context, digest string, size, max int64) ([]byte, error) {
	ref, ok := s.refs[digest]
	if !ok || ref.SizeBytes != size || size > max || ctx.Err() != nil {
		return nil, failure("PRIVATE_INPUT_MISSING", false)
	}
	data, e := os.ReadFile(filepath.Join(s.directory, digest))
	if e != nil || !bytesMatch(data, ref) {
		return nil, failure("PRIVATE_INPUT_INTEGRITY_FAILED", false)
	}
	return data, nil
}
func (s *SchedulerServer) readInput(w http.ResponseWriter, r *http.Request) (control schedulerControl, reader *spoolReader, cleanup func() error, err error) {
	contentType, params, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || contentType != "multipart/form-data" || params["boundary"] == "" {
		return control, nil, nil, failure("SCHEDULER_PROTOCOL_INVALID", false)
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxAttemptBlobBytes+MaxControlBytes+(32<<20))
	parts := multipart.NewReader(r.Body, params["boundary"])
	part, e := parts.NextPart()
	if e != nil || part.FormName() != "control" || part.FileName() != "" {
		return control, nil, nil, failure("SCHEDULER_PROTOCOL_INVALID", false)
	}
	raw, e := io.ReadAll(io.LimitReader(part, MaxControlBytes+1))
	part.Close()
	if e != nil || len(raw) > MaxControlBytes || strictDecode(raw, &control) != nil {
		return control, nil, nil, failure("SCHEDULER_PROTOCOL_INVALID", false)
	}
	refs, e := controlRefs(control)
	if e != nil {
		return control, nil, nil, e
	}
	if len(refs) > 65536 {
		return control, nil, nil, failure("SCHEDULER_BLOB_BOUNDS", false)
	}
	directory, e := os.MkdirTemp(s.spoolRoot, "attempt-")
	if e != nil {
		return control, nil, nil, failure("SCHEDULER_SPOOL_FAILED", false)
	}
	remove := func() error { return s.removeSpool(directory) }
	cleanup = remove
	success := false
	defer func() {
		if !success {
			if remove() != nil {
				s.adapter.failClosed()
			}
		}
	}()
	seen := map[string]bool{}
	for {
		part, e = parts.NextPart()
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return control, nil, nil, failure("SCHEDULER_PROTOCOL_INVALID", false)
		}
		digest := part.FileName()
		ref, exists := refs[digest]
		if part.FormName() != "blob" || !exists || seen[digest] || !digestPattern.MatchString(digest) {
			part.Close()
			return control, nil, nil, failure("SCHEDULER_BLOB_INVALID", false)
		}
		data, e := io.ReadAll(io.LimitReader(part, ref.SizeBytes+1))
		part.Close()
		if e != nil || !bytesMatch(data, ref) {
			return control, nil, nil, failure("SCHEDULER_BLOB_INVALID", false)
		}
		file, e := os.OpenFile(filepath.Join(directory, digest), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return control, nil, nil, failure("SCHEDULER_SPOOL_FAILED", false)
		}
		_, e = file.Write(data)
		closeErr := file.Close()
		if e != nil || closeErr != nil {
			return control, nil, nil, failure("SCHEDULER_SPOOL_FAILED", false)
		}
		seen[digest] = true
	}
	if len(seen) != len(refs) {
		return control, nil, nil, failure("SCHEDULER_BLOB_MISSING", false)
	}
	success = true
	return control, &spoolReader{directory: directory, refs: refs}, cleanup, nil
}
