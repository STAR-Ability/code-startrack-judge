package restclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/config"
)

// Options is trusted deployment configuration. RoundTripper is an injection
// seam for mocks only; production leaves it nil for the fixed local transport.
// Every outgoing request is still checked against the fixed endpoint/route set.
type Options struct {
	Token        string            `json:"-"`
	RoundTripper http.RoundTripper `json:"-"`
	Limits       Limits
}

func (Options) String() string     { return "sandbox REST options [credentials redacted]" }
func (o Options) GoString() string { return o.String() }

type Client struct {
	http   *http.Client
	token  string
	limits Limits
}

func (*Client) String() string     { return "sandbox REST client [credentials redacted]" }
func (c *Client) GoString() string { return c.String() }

func New(options Options) (*Client, error) {
	// The supervisor validates independent credential scopes before construction.
	// The runtime client must never receive business/S2S credentials for comparison.
	if !config.ValidServiceToken(options.Token) {
		return nil, &Error{Kind: ConfigurationError}
	}
	limits, err := normalizeLimits(options.Limits)
	if err != nil {
		return nil, err
	}
	transport := options.RoundTripper
	if transport == nil {
		dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
		transport = &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if network != "tcp" || addr != "127.0.0.1:5050" {
					return nil, &Error{Kind: TransportError}
				}
				return dialer.DialContext(ctx, network, addr)
			},
			DisableCompression: true, MaxIdleConns: 8, MaxIdleConnsPerHost: 8,
			IdleConnTimeout: 30 * time.Second, MaxResponseHeaderBytes: 32 << 10,
		}
	}
	return &Client{http: &http.Client{Transport: fixedTransport{next: transport}, Timeout: 5 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, token: options.Token, limits: limits}, nil
}

type fixedTransport struct{ next http.RoundTripper }

func (t fixedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil || req.URL.Scheme != "http" || req.URL.Host != "127.0.0.1:5050" || req.URL.User != nil || req.URL.RawQuery != "" || req.URL.Fragment != "" || req.URL.Opaque != "" || req.URL.RawPath != "" || req.Host != "" && req.Host != "127.0.0.1:5050" {
		return nil, &Error{Kind: TransportError}
	}
	allowed := req.Method == http.MethodPost && (req.URL.Path == "/run" || req.URL.Path == "/file")
	if strings.HasPrefix(req.URL.Path, "/file/") && FileID(strings.TrimPrefix(req.URL.Path, "/file/")).valid() {
		allowed = req.Method == http.MethodGet || req.Method == http.MethodDelete
	}
	if !allowed {
		return nil, &Error{Kind: TransportError}
	}
	return t.next.RoundTrip(req)
}

func (c *Client) request(ctx context.Context, method, route, contentType string, body []byte, maxBytes int64, missingOK bool) ([]byte, error) {
	if ctx == nil {
		return nil, &Error{Kind: RequestError}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, Endpoint+route, bytes.NewReader(body))
	if err != nil {
		return nil, &Error{Kind: RequestError}
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept-Encoding", "identity")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	response, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &Error{Kind: TransportError, Retryable: true}
	}
	if response == nil || response.Body == nil {
		return nil, &Error{Kind: ProtocolError}
	}
	defer response.Body.Close()
	if encoding := response.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		return nil, &Error{Kind: ProtocolError}
	}
	if response.ContentLength > maxBytes {
		return nil, &Error{Kind: BoundsError}
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxBytes+1))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &Error{Kind: TransportError, Retryable: true}
	}
	if int64(len(data)) > maxBytes {
		return nil, &Error{Kind: BoundsError}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	status := response.StatusCode
	if status == http.StatusOK || missingOK && status == http.StatusNotFound {
		return data, nil
	}
	e := &Error{HTTPStatus: status}
	switch {
	case status >= 300 && status < 400:
		e.Kind = RedirectError
	case status == 401 || status == 403:
		e.Kind = AuthenticationError
	case status == 404:
		e.Kind = MissingFileError
	case status == 429 || status >= 500 && status < 600:
		e.Kind, e.Retryable = UnavailableError, true
	default:
		e.Kind = RejectedError
	}
	return nil, e
}

func decodeJSON(data []byte, destination any) error {
	if err := canonical.ValidateJSON(data); err != nil {
		return &Error{Kind: ProtocolError}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return &Error{Kind: ProtocolError}
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return &Error{Kind: ProtocolError}
	}
	return nil
}

// Upload uses one fixed multipart field/filename and preserves arbitrary bytes.
func (c *Client) Upload(ctx context.Context, contents []byte) (FileID, error) {
	if int64(len(contents)) > c.limits.FileBytes {
		return "", &Error{Kind: BoundsError}
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "blob")
	if err != nil {
		return "", &Error{Kind: RequestError}
	}
	if _, err := part.Write(contents); err != nil {
		return "", &Error{Kind: RequestError}
	}
	if err := writer.Close(); err != nil {
		return "", &Error{Kind: RequestError}
	}
	if int64(body.Len()) > c.limits.FileBytes+1024 {
		return "", &Error{Kind: BoundsError}
	}
	data, err := c.request(ctx, http.MethodPost, "/file", writer.FormDataContentType(), body.Bytes(), c.limits.ResponseBytes, false)
	if err != nil {
		return "", err
	}
	var id FileID
	if err := decodeJSON(data, &id); err != nil || !id.valid() {
		return "", &Error{Kind: ProtocolError}
	}
	return id, nil
}

// Run preserves the REST bare-array response and exact nanosecond/byte units.
// copyOut (JSON string contents) is unavailable: all outputs use cached files.
func (c *Client) Run(ctx context.Context, request Request) ([]Result, error) {
	if err := validateRequest(request, c.limits); err != nil {
		return nil, err
	}
	body, err := encodeRequest(request)
	if err != nil {
		return nil, &Error{Kind: RequestError}
	}
	if int64(len(body)) > c.limits.RequestBytes {
		return nil, &Error{Kind: BoundsError}
	}
	data, err := c.request(ctx, http.MethodPost, "/run", "application/json", body, c.limits.ResponseBytes, false)
	if err != nil {
		return nil, err
	}
	var values []wireResult
	var results []Result
	err = decodeJSON(data, &values)
	if err == nil {
		results, err = projectResults(values, request, c.limits)
	}
	if err != nil {
		// A structurally parsed response may allocate cached outputs even when its
		// status/shape is invalid. Reclaim safe acknowledged IDs before returning.
		if !c.cleanupResponseIDs(values, request) {
			if failure, ok := err.(*Error); ok {
				failure.CleanupFailed = true
			}
		}
	}
	return results, err
}

func (c *Client) cleanupResponseIDs(values []wireResult, request Request) bool {
	inputs := make(map[FileID]bool)
	for _, command := range request.Commands {
		for _, file := range command.Files {
			if file.ID != "" {
				inputs[file.ID] = true
			}
		}
		for _, id := range command.CopyIn {
			inputs[id] = true
		}
	}
	ids := make(map[FileID]bool)
	for _, value := range values {
		for _, id := range value.FileIDs {
			if id.valid() && !inputs[id] {
				ids[id] = true
			}
		}
	}
	if len(ids) > c.limits.Files {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ok := true
	for id := range ids {
		if err := c.Delete(ctx, id); err != nil {
			ok = false
		}
	}
	return ok
}

// Download bounds the actual raw response bytes even when Content-Length is
// missing or misleading. MIME type/filename never determines byte decoding.
func (c *Client) Download(ctx context.Context, id FileID, maxBytes int64) ([]byte, error) {
	if !id.valid() || maxBytes < 1 || maxBytes > c.limits.FileBytes {
		return nil, &Error{Kind: RequestError}
	}
	return c.request(ctx, http.MethodGet, "/file/"+string(id), "", nil, maxBytes, false)
}

// Delete is idempotent for an already-expired cache entry (upstream returns404).
func (c *Client) Delete(ctx context.Context, id FileID) error {
	if !id.valid() {
		return &Error{Kind: RequestError}
	}
	_, err := c.request(ctx, http.MethodDelete, "/file/"+string(id), "", nil, c.limits.ResponseBytes, true)
	return err
}
