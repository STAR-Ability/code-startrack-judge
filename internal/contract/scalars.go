// Package contract defines the published v0.2 wire boundary. It contains no
// persistence models, execution templates, or private artifact addresses.
package contract

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	Version                    = "0.2.0"
	MaxSafeInteger       int64 = 9007199254740991
	MaxJudgeRequestBytes int64 = 2 * 1048576
	MaxResultBytes       int64 = 32 * 1048576
	MaxSourceBytes             = 262144
	MaxCompileLogBytes         = 16384
)

// ValidationError exposes only a fixed diagnostic code and schema field name.
// Raw input and parser/driver errors never become API diagnostic messages.
type ValidationError struct {
	Code  string
	Field string
}

func (e *ValidationError) Error() string { return "contract validation failed: " + e.Code }
func Invalid(field string) error         { return &ValidationError{Code: "INVALID_ARGUMENT", Field: field} }

type ID string
type UUID string
type Instant string
type SafeInt int64

var idPattern = regexp.MustCompile(`^[1-9][0-9]*$`)
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var instantPattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$`)

func (v ID) Validate() error {
	if !idPattern.MatchString(string(v)) {
		return Invalid("id")
	}
	n, err := strconv.ParseInt(string(v), 10, 64)
	if err != nil || n <= 0 {
		return Invalid("id")
	}
	return nil
}
func (v UUID) Validate() error {
	if !uuidPattern.MatchString(string(v)) {
		return Invalid("uuid")
	}
	return nil
}
func (v Instant) Validate() error {
	if !instantPattern.MatchString(string(v)) {
		return Invalid("instant")
	}
	if _, err := time.Parse(time.RFC3339Nano, string(v)); err != nil {
		return Invalid("instant")
	}
	return nil
}
func (v SafeInt) Validate() error {
	if v < 0 || int64(v) > MaxSafeInteger {
		return Invalid("counter")
	}
	return nil
}

func decodeString(data []byte) (string, error) {
	var s string
	if string(data) == "null" || json.Unmarshal(data, &s) != nil {
		return "", Invalid("string")
	}
	return s, nil
}
func (v *ID) UnmarshalJSON(data []byte) error {
	s, e := decodeString(data)
	if e != nil {
		return e
	}
	n := ID(s)
	if e = n.Validate(); e != nil {
		return e
	}
	*v = n
	return nil
}
func (v *UUID) UnmarshalJSON(data []byte) error {
	s, e := decodeString(data)
	if e != nil {
		return e
	}
	n := UUID(s)
	if e = n.Validate(); e != nil {
		return e
	}
	*v = n
	return nil
}
func (v *Instant) UnmarshalJSON(data []byte) error {
	s, e := decodeString(data)
	if e != nil {
		return e
	}
	n := Instant(s)
	if e = n.Validate(); e != nil {
		return e
	}
	*v = n
	return nil
}
func (v *SafeInt) UnmarshalJSON(data []byte) error {
	n, e := parseSafeInteger(data)
	if e != nil {
		return e
	}
	*v = SafeInt(n)
	return nil
}
func (v ID) MarshalJSON() ([]byte, error) {
	if e := v.Validate(); e != nil {
		return nil, e
	}
	return json.Marshal(string(v))
}
func (v UUID) MarshalJSON() ([]byte, error) {
	if e := v.Validate(); e != nil {
		return nil, e
	}
	return json.Marshal(strings.ToLower(string(v)))
}
func (v Instant) MarshalJSON() ([]byte, error) {
	if e := v.Validate(); e != nil {
		return nil, e
	}
	return json.Marshal(string(v))
}
func (v SafeInt) MarshalJSON() ([]byte, error) {
	if e := v.Validate(); e != nil {
		return nil, e
	}
	return json.Marshal(int64(v))
}

func NewUUID() (UUID, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", errors.New("request identity unavailable")
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	s := hex.EncodeToString(b[:])
	return UUID(s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]), nil
}
func UTC(t time.Time) Instant { return Instant(t.UTC().Format(time.RFC3339Nano)) }

// Array keeps required empty arrays as [] on the wire, even at their zero value.
type Array[T any] []T

func (a Array[T]) MarshalJSON() ([]byte, error) {
	if a == nil {
		return []byte("[]"), nil
	}
	return json.Marshal([]T(a))
}
func (a *Array[T]) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return Invalid("array")
	}
	var v []T
	if e := json.Unmarshal(data, &v); e != nil {
		return Invalid("array")
	}
	*a = v
	return nil
}

// parseSafeInteger checks the exact decimal value without float64 rounding or
// allocating arbitrarily large big integers. Integral exponent/fraction forms
// have the same value under the Q-002/JCS profile and are normalized on output.
func parseSafeInteger(data []byte) (int64, error) {
	s := strings.TrimSpace(string(data))
	if !json.Valid(data) || s == "" || (s[0] != '-' && (s[0] < '0' || s[0] > '9')) {
		return 0, Invalid("counter")
	}
	negative := s[0] == '-'
	if negative {
		s = s[1:]
	}
	exponentText := "0"
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		exponentText = s[i+1:]
		s = s[:i]
	}
	fraction := int64(0)
	if i := strings.IndexByte(s, '.'); i >= 0 {
		fraction = int64(len(s) - i - 1)
		s = s[:i] + s[i+1:]
	}
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return 0, nil
	}
	if negative {
		return 0, Invalid("counter")
	}
	exponent, e := strconv.ParseInt(exponentText, 10, 64)
	if e != nil {
		return 0, Invalid("counter")
	}
	if exponent < -int64(len(data)) || exponent > int64(len(data))+16 {
		return 0, Invalid("counter")
	}
	exponent -= fraction
	for exponent < 0 && strings.HasSuffix(s, "0") {
		s = s[:len(s)-1]
		exponent++
	}
	if exponent < 0 || exponent > 16 || int64(len(s))+exponent > 16 {
		return 0, Invalid("counter")
	}
	s += strings.Repeat("0", int(exponent))
	n, e := strconv.ParseInt(s, 10, 64)
	if e != nil || n > MaxSafeInteger {
		return 0, Invalid("counter")
	}
	return n, nil
}
