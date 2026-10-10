package runtime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"sort"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/config"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/runtime/restclient"
)

// SchedulerClient is the API/worker's only execution interface. It knows the
// scheduler credential and private blob reader, never the go-judge credential.
type SchedulerClient struct {
	http   *http.Client
	token  string
	reader BlobReader
}

func (c *SchedulerClient) String() string   { return "private scheduler client [credentials redacted]" }
func (c *SchedulerClient) GoString() string { return c.String() }
func (c *SchedulerClient) Close()           { c.http.CloseIdleConnections() }
func NewSchedulerClient(token string, reader BlobReader) (*SchedulerClient, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		if network != "tcp" || addr != "scheduler.invalid:80" {
			return nil, failure("SCHEDULER_TRANSPORT_FAILED", false)
		}
		return dialer.DialContext(ctx, "unix", SchedulerSocket)
	}, DisableCompression: true, MaxIdleConns: 4, MaxIdleConnsPerHost: 4, IdleConnTimeout: 30 * time.Second, MaxResponseHeaderBytes: 32 << 10}
	return newSchedulerClient(token, reader, transport)
}
func newSchedulerClient(token string, reader BlobReader, transport http.RoundTripper) (*SchedulerClient, error) {
	if !config.ValidServiceToken(token) || reader == nil || transport == nil {
		return nil, failure("SCHEDULER_CONFIGURATION_INVALID", false)
	}
	return &SchedulerClient{http: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, token: token, reader: reader}, nil
}
func (c *SchedulerClient) request(ctx context.Context, method, route, contentType string, body io.Reader) (*http.Response, error) {
	if ctx == nil {
		return nil, failure("SCHEDULER_REQUEST_INVALID", false)
	}
	req, e := http.NewRequestWithContext(ctx, method, "http://scheduler.invalid"+route, body)
	if e != nil {
		return nil, failure("SCHEDULER_REQUEST_INVALID", false)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept-Encoding", "identity")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	response, e := c.http.Do(req)
	if e != nil {
		return nil, failure("SCHEDULER_OPERATION_UNCERTAIN", method == http.MethodPost)
	}
	if response == nil || response.Body == nil {
		return nil, failure("SCHEDULER_PROTOCOL_INVALID", method == http.MethodPost)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" {
		response.Body.Close()
		return nil, failure("SCHEDULER_REQUEST_REJECTED", response.StatusCode == 429 || response.StatusCode == 503 || response.StatusCode == 408)
	}
	return response, nil
}
func (c *SchedulerClient) Snapshot(ctx context.Context) Snapshot {
	unavailable := Snapshot{Languages: emptyLanguages()}
	response, e := c.request(ctx, http.MethodGet, "/snapshot", "", nil)
	if e != nil {
		return unavailable
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, 64<<10+1))
	var snapshot Snapshot
	if e != nil || len(raw) > 64<<10 || strictDecode(raw, &snapshot) != nil || snapshot.Identity.Validate() != nil || snapshot.Languages.Validate() != nil {
		return unavailable
	}
	if snapshot.Qualified && (!snapshot.SandboxReady || !snapshot.ToolchainReady || len(snapshot.Languages.Languages) != 1 || snapshot.Languages.Languages[0].CompilerVersion != snapshot.Identity.CompilerVersion) {
		return unavailable
	}
	for _, language := range snapshot.Languages.Languages {
		if language.Validate() != nil {
			return unavailable
		}
	}
	if !snapshot.Qualified && len(snapshot.Languages.Languages) != 0 {
		return unavailable
	}
	if snapshot.MatureReady && (!snapshot.Qualified || snapshot.ProblemtoolsVersion != ProblemtoolsVersion || snapshot.ProblemtoolsRevision != ProblemtoolsRevision || snapshot.HelperProfile != MatureHelperProfile) {
		return unavailable
	}
	if !snapshot.MatureReady && (snapshot.ProblemtoolsVersion != "" || snapshot.ProblemtoolsRevision != "" || snapshot.HelperProfile != "") {
		return unavailable
	}
	return snapshot
}
func emptyLanguages() contract.LanguageCapabilities {
	return contract.LanguageCapabilities{Languages: contract.Array[contract.LanguageCapability]{}, CapabilityVersion: "unavailable"}
}

func (c *SchedulerClient) Execute(ctx context.Context, input TaskInput, onProgress ProgressFunc) (Outcome, error) {
	event, e := c.dispatch(ctx, "/execute", schedulerControl{Task: &input}, onProgress, nil)
	if e != nil {
		return Outcome{}, e
	}
	if event.Outcome == nil || event.Validation != nil || event.Mature != nil {
		return Outcome{}, failure("SCHEDULER_PROTOCOL_INVALID", true)
	}
	return *event.Outcome, nil
}
func (c *SchedulerClient) ValidatePrograms(ctx context.Context, input ValidationInput) (out ValidationOutcome, err error) {
	if uint64(len(input.Cases))*uint64(len(input.InputValidators)+len(input.AcceptedReferences)) > MaxCollectedEvidence {
		return out, failure("VALIDATION_EVIDENCE_SINK_REQUIRED", false)
	}
	validators := []ProgramCaseEvidence{}
	references := []ProgramCaseEvidence{}
	out, err = c.ValidateProgramsWithEvidence(ctx, input, func(_ context.Context, e ValidationEvidence) error {
		if e.Kind == "VALIDATOR" {
			validators = append(validators, e.Case)
		} else {
			references = append(references, e.Case)
		}
		return nil
	})
	out.ValidatorCases = validators
	out.ReferenceCases = references
	return out, err
}
func (c *SchedulerClient) ValidateProgramsWithEvidence(ctx context.Context, input ValidationInput, sink ValidationEvidenceFunc) (ValidationOutcome, error) {
	if sink == nil {
		return ValidationOutcome{}, failure("VALIDATION_EVIDENCE_SINK_REQUIRED", false)
	}
	event, e := c.dispatch(ctx, "/validate", schedulerControl{Validation: &input}, nil, sink)
	if e != nil {
		return ValidationOutcome{}, e
	}
	if event.Validation == nil || event.Outcome != nil || event.Mature != nil {
		return ValidationOutcome{}, failure("SCHEDULER_PROTOCOL_INVALID", true)
	}
	return *event.Validation, nil
}
func (c *SchedulerClient) RunMature(ctx context.Context, input MatureInput) (MatureOutcome, error) {
	if !input.valid() {
		return MatureOutcome{}, failure("MATURE_INPUT_INVALID", false)
	}
	event, e := c.dispatch(ctx, "/mature", schedulerControl{Mature: &input}, nil, nil)
	if e != nil {
		return MatureOutcome{RawLog: event.PrivateLog}, e
	}
	if event.Mature == nil || event.Outcome != nil || event.Validation != nil || !event.Mature.valid() || !event.Mature.Completed {
		return MatureOutcome{}, failure("SCHEDULER_PROTOCOL_INVALID", true)
	}
	return *event.Mature, nil
}
func (c *SchedulerClient) dispatch(ctx context.Context, route string, control schedulerControl, onProgress ProgressFunc, onEvidence ValidationEvidenceFunc) (schedulerEvent, error) {
	refs, e := controlRefs(control)
	if e != nil {
		return schedulerEvent{}, e
	}
	raw, e := json.Marshal(control)
	if e != nil || len(raw) > MaxControlBytes {
		return schedulerEvent{}, failure("SCHEDULER_REQUEST_INVALID", false)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	reader, writer := io.Pipe()
	parts := multipart.NewWriter(writer)
	go func() {
		fail := func() { writer.CloseWithError(failure("SCHEDULER_INPUT_FAILED", false)) }
		part, e := parts.CreateFormField("control")
		if e != nil {
			fail()
			return
		}
		if _, e = part.Write(raw); e != nil {
			fail()
			return
		}
		keys := make([]string, 0, len(refs))
		for digest := range refs {
			keys = append(keys, digest)
		}
		sort.Strings(keys)
		for _, digest := range keys {
			ref := refs[digest]
			data, e := c.reader.ReadBlob(ctx, ref.SHA256, ref.SizeBytes, MaxFileBytes)
			if e != nil || !bytesMatch(data, ref) {
				fail()
				return
			}
			part, e := parts.CreateFormFile("blob", digest)
			if e != nil {
				fail()
				return
			}
			if _, e = part.Write(data); e != nil {
				fail()
				return
			}
		}
		if e = parts.Close(); e != nil {
			fail()
			return
		}
		writer.Close()
	}()
	defer reader.Close()
	response, e := c.request(ctx, http.MethodPost, route, parts.FormDataContentType(), reader)
	if e != nil {
		return schedulerEvent{}, e
	}
	defer response.Body.Close()
	scanner := bufio.NewScanner(response.Body)
	scanner.Buffer(make([]byte, 4096), 4<<20)
	sequence := uint64(0)
	var fence contract.UUID
	if control.Task != nil {
		fence = control.Task.FencingToken
	} else if control.Validation != nil {
		fence = control.Validation.FencingToken
	} else {
		fence = control.Mature.FencingToken
	}
	var validators, references, validatorFailures, referenceFailures uint64
	for scanner.Scan() {
		var event schedulerEvent
		if strictDecode(scanner.Bytes(), &event) != nil || event.FencingToken != fence {
			return schedulerEvent{}, failure("SCHEDULER_PROTOCOL_INVALID", true)
		}
		if len(event.PrivateLog) > 2<<20 || len(event.PrivateLog) > 0 && (control.Mature == nil || event.Failure == nil) {
			return schedulerEvent{}, failure("SCHEDULER_PROTOCOL_INVALID", true)
		}
		if event.Progress != nil {
			sequence++
			if event.Sequence != sequence || event.Outcome != nil || event.Validation != nil || event.Failure != nil || event.Evidence != nil || event.Mature != nil {
				return schedulerEvent{}, failure("SCHEDULER_PROTOCOL_INVALID", true)
			}
			var callbackError error
			if onProgress != nil {
				callbackError = onProgress(ctx, *event.Progress)
			}
			ackRaw, _ := json.Marshal(schedulerAck{FencingToken: fence, Sequence: sequence, Accepted: callbackError == nil})
			ackResponse, ackError := c.request(ctx, http.MethodPost, "/ack", "application/json", bytes.NewReader(ackRaw))
			if ackError != nil {
				return schedulerEvent{}, failure("SCHEDULER_OPERATION_UNCERTAIN", true)
			}
			ackResponse.Body.Close()
			if callbackError != nil {
				return schedulerEvent{}, failure("SCHEDULER_PROGRESS_REJECTED", true)
			}
			continue
		}
		if event.Sequence != 0 {
			return schedulerEvent{}, failure("SCHEDULER_PROTOCOL_INVALID", true)
		}
		if event.Evidence != nil {
			if control.Validation == nil || onEvidence == nil || event.Outcome != nil || event.Validation != nil || event.Failure != nil || event.Mature != nil || !digestPattern.MatchString(event.Evidence.Case.SourceSHA256) || event.Evidence.Case.Ordinal < 1 || event.Evidence.Case.Ordinal > len(control.Validation.Cases) {
				return schedulerEvent{}, failure("SCHEDULER_PROTOCOL_INVALID", true)
			}
			ev := event.Evidence.Case
			casesPerProgram := uint64(len(control.Validation.Cases))
			if casesPerProgram == 0 || ev.MemoryBytes > uint64(contract.MaxSafeInteger) || ev.Verdict.Validate() != nil || ev.Passed != (ev.Verdict == contract.VerdictAC) || len(ev.DiagnosticCode) > 64 {
				return schedulerEvent{}, failure("SCHEDULER_PROTOCOL_INVALID", true)
			}
			switch event.Evidence.Kind {
			case "VALIDATOR":
				if references != 0 || validators/casesPerProgram >= uint64(len(control.Validation.InputValidators)) || ev.SourceSHA256 != control.Validation.InputValidators[validators/casesPerProgram].File.SHA256 || ev.Ordinal != int(validators%casesPerProgram)+1 || ev.Passed && (ev.Status != restclient.NonzeroExit || ev.ExitCode != 42) {
					return schedulerEvent{}, failure("SCHEDULER_PROTOCOL_INVALID", true)
				}
				validators++
				if !ev.Passed {
					validatorFailures++
				}
			case "REFERENCE":
				if validators != uint64(len(control.Validation.InputValidators))*casesPerProgram || references/casesPerProgram >= uint64(len(control.Validation.AcceptedReferences)) || ev.SourceSHA256 != control.Validation.AcceptedReferences[references/casesPerProgram].File.SHA256 || ev.Ordinal != int(references%casesPerProgram)+1 || ev.Passed && (ev.Status != restclient.Accepted || ev.ExitCode != 0) {
					return schedulerEvent{}, failure("SCHEDULER_PROTOCOL_INVALID", true)
				}
				references++
				if !ev.Passed {
					referenceFailures++
				}
			default:
				return schedulerEvent{}, failure("SCHEDULER_PROTOCOL_INVALID", true)
			}
			if validators > uint64(len(control.Validation.Cases))*uint64(len(control.Validation.InputValidators)) || references > uint64(len(control.Validation.Cases))*uint64(len(control.Validation.AcceptedReferences)) {
				return schedulerEvent{}, failure("SCHEDULER_PROTOCOL_INVALID", true)
			}
			if e = onEvidence(ctx, *event.Evidence); e != nil {
				return schedulerEvent{}, failure("VALIDATION_EVIDENCE_FAILED", true)
			}
			continue
		}
		if event.Failure != nil {
			if event.Outcome != nil || event.Validation != nil || event.Mature != nil || event.Failure.Code == "" || len(event.Failure.Code) > 64 {
				return schedulerEvent{}, failure("SCHEDULER_PROTOCOL_INVALID", true)
			}
			return event, event.Failure
		}
		if event.Outcome == nil && event.Validation == nil && event.Mature == nil {
			return schedulerEvent{}, failure("SCHEDULER_PROTOCOL_INVALID", true)
		}
		if event.Validation != nil {
			if control.Validation == nil || event.Outcome != nil || event.Mature != nil || validators != event.Validation.ValidatorCaseCount || references != event.Validation.ReferenceCaseCount || validators != uint64(len(control.Validation.Cases))*uint64(len(control.Validation.InputValidators)) || references != uint64(len(control.Validation.Cases))*uint64(len(control.Validation.AcceptedReferences)) || event.Validation.ValidatorsPassed != (validators > 0 && validatorFailures == 0) || event.Validation.ReferencesPassed != (references > 0 && referenceFailures == 0) {
				return schedulerEvent{}, failure("SCHEDULER_PROTOCOL_INVALID", true)
			}
		}
		if event.Mature != nil && (control.Mature == nil || event.Outcome != nil || event.Validation != nil || !event.Mature.valid()) {
			return schedulerEvent{}, failure("SCHEDULER_PROTOCOL_INVALID", true)
		}
		if scanner.Scan() || scanner.Err() != nil {
			return schedulerEvent{}, failure("SCHEDULER_PROTOCOL_INVALID", true)
		}
		return event, nil
	}
	return schedulerEvent{}, failure("SCHEDULER_OPERATION_UNCERTAIN", true)
}
