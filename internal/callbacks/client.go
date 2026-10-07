package callbacks

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/config"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
)

const maxACKBytes = 4096

type Client struct {
	token string
	http  *http.Client
}

// NewClient accepts only the independent outbound credential. Its URL is fixed,
// environment proxies and redirects are disabled, and credentials stay private.
func NewClient(token string) (*Client, error) {
	transport := &http.Transport{
		Proxy:           nil,
		DialContext:     (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxConnsPerHost: 4, MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
	}
	return newClient(token, transport)
}

func newClient(token string, transport http.RoundTripper) (*Client, error) {
	if !config.ValidServiceToken(token) || transport == nil {
		return nil, ErrInvalid
	}
	return &Client{token: token, http: &http.Client{
		Transport: transport, Timeout: RequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func (*Client) String() string     { return "callback client [credentials redacted]" }
func (c *Client) GoString() string { return c.String() }
func (c *Client) Close()           { c.http.CloseIdleConnections() }

func validDelivery(d *Delivery) bool {
	if d == nil || int64(len(d.CanonicalJSON)) > contract.MaxResultBytes || canonical.HashBytes(d.CanonicalJSON) != d.PayloadHash {
		return false
	}
	var event contract.CallbackEvent[contract.JudgeTask]
	if contract.DecodeJSON(d.CanonicalJSON, &event) != nil || event.EventID != d.EventID || event.RequestID != d.RequestID || event.AggregateID != d.TaskID || int64(event.Revision) != d.Revision {
		return false
	}
	encoded, err := canonical.Canonicalize(d.CanonicalJSON)
	return err == nil && bytes.Equal(encoded, d.CanonicalJSON)
}

func (c *Client) Send(ctx context.Context, d *Delivery) Outcome {
	if !validDelivery(d) {
		return Outcome{ErrorCode: IntegrityFailure}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, Destination, bytes.NewReader(d.CanonicalJSON))
	if err != nil {
		return Outcome{ErrorCode: Unavailable}
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", string(d.RequestID))
	response, err := c.http.Do(req)
	if err != nil {
		// Do errors may contain URL/transport details. Only a bounded category escapes.
		return Outcome{ErrorCode: Unavailable}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		// Error bodies can contain internal paths, logs, or an upstream credential.
		// They are never interpreted, retained, or logged.
		return Outcome{ErrorCode: statusCode(response.StatusCode)}
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxACKBytes+1))
	if err != nil || len(raw) > maxACKBytes {
		return Outcome{ErrorCode: InvalidACK}
	}
	var ack contract.ApiResponse[contract.CallbackAck]
	if contract.DecodeJSON(raw, &ack) != nil || ack.RequestID != d.RequestID {
		return Outcome{ErrorCode: InvalidACK}
	}
	if !ack.Data.Accepted {
		return Outcome{ErrorCode: Rejected}
	}
	return Outcome{Accepted: true, Duplicate: ack.Data.Duplicate}
}

func statusCode(status int) Code {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return Unauthorized
	case http.StatusNotFound:
		return UnknownTask
	case http.StatusConflict:
		return Conflict
	case http.StatusBadRequest:
		return InvalidArgument
	case http.StatusTooManyRequests:
		return Unavailable
	}
	if status >= 500 {
		return Unavailable
	}
	return UnexpectedHTTP
}
