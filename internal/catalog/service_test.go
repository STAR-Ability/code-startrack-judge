package catalog

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	persistence "github.com/STAR-Ability/code-startrack-judge/internal/persistence/problems"
)

func TestCursorIntegrityAndFixedLimit(t *testing.T) {
	s, err := New(persistence.New(nil, nil), []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	value := cursor{Version: 1, SnapshotID: "00000000-0000-0000-0000-000000000001", Offset: 100, Limit: 100}
	encoded, err := s.encode(value)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.decode(encoded, 100)
	if err != nil || got != value {
		t.Fatal("valid cursor failed")
	}
	for _, bad := range []string{"", encoded + "=", strings.Replace(encoded, ".", "..", 1), encoded[:len(encoded)-1] + "!"} {
		if _, err := s.decode(bad, 100); err == nil {
			t.Fatal("malformed/tampered cursor accepted")
		}
	}
	if _, err := s.decode(encoded, 99); err == nil {
		t.Fatal("changed page limit accepted")
	}
	other, _ := New(persistence.New(nil, nil), []byte(strings.Repeat("j", 32)))
	if _, err := other.decode(encoded, 100); err == nil {
		t.Fatal("different authority accepted cursor")
	}
	unknown := []byte(`{"v":1,"snapshotId":"00000000-0000-0000-0000-000000000001","offset":100,"limit":100,"extra":true}`)
	signed := base64.RawURLEncoding.EncodeToString(unknown) + "." + base64.RawURLEncoding.EncodeToString(s.mac(unknown))
	if _, err := s.decode(signed, 100); err == nil {
		t.Fatal("unknown protocol member accepted")
	}
	for _, offset := range []int64{0, -1, 101, contract.MaxSafeInteger + 1} {
		bad, _ := s.encode(cursor{Version: 1, SnapshotID: value.SnapshotID, Offset: offset, Limit: 100})
		if _, err := s.decode(bad, 100); err == nil {
			t.Fatal("invalid cursor offset accepted")
		}
	}
}
