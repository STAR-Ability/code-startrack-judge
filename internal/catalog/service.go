// Package catalog provides immutable public directory snapshots and signed,
// opaque cursors. Cursor authority is separate from service authentication.
package catalog

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	persistence "github.com/STAR-Ability/code-startrack-judge/internal/persistence/problems"
)

type Error = persistence.WorkflowError
type Service struct {
	repo *persistence.Repository
	key  []byte
}
type cursor struct {
	Version    int           `json:"v"`
	SnapshotID contract.UUID `json:"snapshotId"`
	Offset     int64         `json:"offset"`
	Limit      int64         `json:"limit"`
}

func New(repo *persistence.Repository, key []byte) (*Service, error) {
	if repo == nil || len(key) < 32 || len(key) > 1024 {
		return nil, errors.New("invalid catalog cursor authority")
	}
	return &Service{repo: repo, key: append([]byte{}, key...)}, nil
}

func (s *Service) Page(ctx context.Context, encoded *string, limit contract.SafeInt) (contract.CatalogSnapshotPage, error) {
	var out contract.CatalogSnapshotPage
	if limit < 1 || limit > 1000 {
		return out, contract.Invalid("limit")
	}
	var page persistence.SnapshotPage
	var err error
	var offset int64
	if encoded == nil {
		page, err = s.repo.CreateSnapshot(ctx, int64(limit))
	} else {
		value, e := s.decode(*encoded, int64(limit))
		if e != nil {
			return out, e
		}
		offset = value.Offset
		page, err = s.repo.SnapshotPage(ctx, value.SnapshotID, value.Offset, value.Limit)
	}
	if err != nil {
		var domain *Error
		if errors.As(err, &domain) {
			return out, err
		}
		return out, &Error{Code: "INTERNAL_ERROR"}
	}
	out = contract.CatalogSnapshotPage{SnapshotID: page.ID, CatalogVersion: page.CatalogVersion, Items: page.Items, ExpiresAt: contract.UTC(page.ExpiresAt)}
	if offset+int64(limit) < page.Count {
		next, err := s.encode(cursor{Version: 1, SnapshotID: page.ID, Offset: offset + int64(limit), Limit: int64(limit)})
		if err != nil {
			return out, err
		}
		out.NextCursor = &next
	}
	return out, nil
}
func (s *Service) Cleanup(ctx context.Context, limit int) (int64, error) {
	count, err := s.repo.CleanupSnapshots(ctx, limit)
	if err != nil {
		var domain *Error
		if errors.As(err, &domain) {
			return count, err
		}
		return count, &Error{Code: "INTERNAL_ERROR"}
	}
	return count, nil
}

func (s *Service) mac(payload []byte) []byte {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte("startrack-catalog-cursor-v1\x00"))
	mac.Write(payload)
	return mac.Sum(nil)
}
func (s *Service) encode(value cursor) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", &Error{Code: "INTERNAL_ERROR"}
	}
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(s.mac(payload)), nil
}
func (s *Service) decode(encoded string, limit int64) (cursor, error) {
	var out cursor
	if len(encoded) > 8192 {
		return out, contract.Invalid("cursor")
	}
	parts := strings.Split(encoded, ".")
	if len(parts) != 2 {
		return out, contract.Invalid("cursor")
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil {
		return out, contract.Invalid("cursor")
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || !hmac.Equal(signature, s.mac(payload)) {
		return out, contract.Invalid("cursor")
	}
	if canonical.ValidateJSON(payload) != nil || json.Unmarshal(payload, &out) != nil || out.Version != 1 || out.SnapshotID.Validate() != nil || out.Limit != limit || out.Limit < 1 || out.Limit > 1000 || out.Offset < 1 || out.Offset > contract.MaxSafeInteger || out.Offset%out.Limit != 0 {
		return cursor{}, contract.Invalid("cursor")
	}
	// Only the exact encoder form is accepted, so signed unknown fields or
	// alternate representations cannot become a second cursor protocol.
	canonicalPayload, _ := json.Marshal(out)
	if !hmac.Equal(payload, canonicalPayload) {
		return cursor{}, contract.Invalid("cursor")
	}
	return out, nil
}
