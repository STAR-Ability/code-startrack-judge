package restclient

import (
	"context"
	"sort"
	"sync"
	"time"
)

// Session tracks acknowledged input/output cache IDs across compilation and
// execution. Close must be deferred by the role-aware adapter. Lost responses
// cannot reveal allocated IDs; the deployed runtime also needs bounded cache TTL.
// A session serializes operations so Close cannot miss an in-flight allocation.
type Session struct {
	mu     sync.Mutex
	client *Client
	ids    map[FileID]bool
	closed bool
}

func (c *Client) NewSession() *Session { return &Session{client: c, ids: make(map[FileID]bool)} }

func (s *Session) Upload(ctx context.Context, contents []byte) (FileID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(s.ids) >= s.client.limits.Files {
		return "", &Error{Kind: BoundsError}
	}
	id, err := s.client.Upload(ctx, contents)
	if err == nil {
		s.ids[id] = true
	}
	return id, err
}

func (s *Session) Run(ctx context.Context, request Request) ([]Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, &Error{Kind: RequestError}
	}
	possibleOutputs := 0
	for _, command := range request.Commands {
		possibleOutputs += len(command.CopyOutCached)
		for _, file := range command.Files {
			if file.ID != "" && !s.ids[file.ID] {
				return nil, &Error{Kind: RequestError}
			}
		}
		for _, id := range command.CopyIn {
			if !s.ids[id] {
				return nil, &Error{Kind: RequestError}
			}
		}
	}
	if len(s.ids)+possibleOutputs > s.client.limits.Files {
		return nil, &Error{Kind: BoundsError}
	}
	results, err := s.client.Run(ctx, request)
	if err == nil {
		for _, result := range results {
			for _, id := range result.CachedFiles {
				s.ids[id] = true
			}
		}
	}
	return results, err
}

func (s *Session) Download(ctx context.Context, id FileID, maxBytes int64) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || !s.ids[id] {
		return nil, &Error{Kind: RequestError}
	}
	return s.client.Download(ctx, id, maxBytes)
}

// Close cleans acknowledged IDs even after the execution context was cancelled.
// The independent cleanup deadline is bounded; failure is returned, not hidden.
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed && len(s.ids) == 0 {
		return nil
	}
	s.closed = true
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ids := make([]string, 0, len(s.ids))
	for id := range s.ids {
		ids = append(ids, string(id))
	}
	sort.Strings(ids)
	failed := false
	for _, rawID := range ids {
		id := FileID(rawID)
		if err := s.client.Delete(ctx, id); err != nil {
			failed = true
		} else {
			delete(s.ids, id)
		}
	}
	if failed {
		return &Error{Kind: CleanupError, Retryable: true}
	}
	return nil
}
