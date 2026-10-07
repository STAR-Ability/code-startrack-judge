// Package canonical implements the RFC 8785 JSON Canonicalization Scheme (JCS)
// and the contract's SHA-256 boundaries. Business DTO validation and contract
// normalization happen before hashing; this package never trims or normalizes
// strings, reorders arrays, or changes missing members into null members.
package canonical

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strconv"
	"unicode/utf8"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

var (
	ErrInvalidJSON       = errors.New("invalid canonical JSON")
	ErrInvalidUTF8       = errors.New("invalid UTF-8")
	ErrDuplicateKey      = errors.New("duplicate JSON object member")
	ErrUnpairedSurrogate = errors.New("unpaired UTF-16 surrogate")
	ErrInvalidOperation  = errors.New("invalid hash operation or problem identity")
)

// Canonicalize returns RFC 8785 canonical UTF-8 bytes. The pinned upstream JCS
// implementation owns serialization, numeric formatting, and UTF-16 key order.
// Preflight validation closes permissive-parser gaps without changing its
// serialization behavior. Errors never echo input keys, values, or source.
func Canonicalize(raw []byte) ([]byte, error) {
	if err := ValidateJSON(raw); err != nil {
		return nil, err
	}
	// The upstream API accepts only arrays and objects. A singleton array uses
	// the same JCS rules for scalar roots, which RFC 8785 also permits.
	trimmed := bytes.TrimSpace(raw)
	scalar := trimmed[0] != '{' && trimmed[0] != '['
	input := raw
	if scalar {
		input = make([]byte, 0, len(raw)+2)
		input = append(input, '[')
		input = append(input, raw...)
		input = append(input, ']')
	}
	result, err := jsoncanonicalizer.Transform(input)
	if err != nil {
		// Upstream errors may contain input. Only expose the stable category.
		return nil, ErrInvalidJSON
	}
	if scalar {
		result = result[1 : len(result)-1]
	}
	return result, nil
}

// ValidateJSON rejects malformed grammar, non-UTF-8 input, duplicate decoded
// member names at every nesting level, and unpaired escaped UTF-16 surrogates.
// Unlike encoding/json's ordinary decoder it never repairs invalid strings.
func ValidateJSON(raw []byte) error {
	if !utf8.Valid(raw) {
		return ErrInvalidUTF8
	}
	if !json.Valid(raw) {
		return ErrInvalidJSON
	}
	if !validSurrogates(raw) {
		return ErrUnpairedSurrogate
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := readValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrInvalidJSON
	}
	return nil
}

func readValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return ErrInvalidJSON
	}
	delimiter, structured := token.(json.Delim)
	if !structured {
		if number, ok := token.(json.Number); ok {
			value, err := strconv.ParseFloat(string(number), 64)
			if err != nil || math.IsInf(value, 0) || math.IsNaN(value) {
				return ErrInvalidJSON
			}
		}
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return ErrInvalidJSON
			}
			key, ok := token.(string)
			if !ok {
				return ErrInvalidJSON
			}
			if _, exists := keys[key]; exists {
				return ErrDuplicateKey
			}
			keys[key] = struct{}{}
			if err := readValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := readValue(decoder); err != nil {
				return err
			}
		}
	default:
		return ErrInvalidJSON
	}
	_, err = decoder.Token()
	if err != nil {
		return ErrInvalidJSON
	}
	return nil
}

// validSurrogates runs after json.Valid, so escape lengths and hexadecimal
// digits are known valid. It examines escapes inside JSON strings, never text
// outside them or a literal escaped backslash followed by "u".
func validSurrogates(raw []byte) bool {
	inString := false
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '"':
			inString = !inString
		case '\\':
			if !inString {
				continue
			}
			i++
			if raw[i] != 'u' {
				continue
			}
			first := hexUnit(raw[i+1 : i+5])
			i += 4
			if first >= 0xdc00 && first <= 0xdfff {
				return false
			}
			if first < 0xd800 || first > 0xdbff {
				continue
			}
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			second := hexUnit(raw[i+3 : i+7])
			if second < 0xdc00 || second > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}

func hexUnit(raw []byte) uint16 {
	var value uint16
	for _, digit := range raw {
		value <<= 4
		switch {
		case digit >= '0' && digit <= '9':
			value += uint16(digit - '0')
		case digit >= 'a' && digit <= 'f':
			value += uint16(digit-'a') + 10
		default:
			value += uint16(digit-'A') + 10
		}
	}
	return value
}

// HashJSON returns lowercase hexadecimal SHA-256 of canonical JSON, without a
// BOM, trailing newline, domain prefix, or enclosing HTTP response envelope.
func HashJSON(raw []byte) (string, error) {
	canonical, err := Canonicalize(raw)
	if err != nil {
		return "", err
	}
	return HashBytes(canonical), nil
}

// HashSource returns SHA-256 of the exact source UTF-8 bytes. In particular CRLF,
// whitespace, BOMs, and canonically equivalent Unicode remain distinguishable.
func HashSource(source string) (string, error) {
	if !utf8.ValidString(source) {
		return "", ErrInvalidUTF8
	}
	return HashBytes([]byte(source)), nil
}

// HashBytes hashes exact bytes, including arbitrary binary archive and file
// content. It applies no JSON canonicalization, path rewriting, text decoding,
// or newline normalization. A package archive checksum covers the complete
// stored archive bytes; manifest and metadata projections instead use HashJSON.
func HashBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

// RequestHash hashes {operation,problemId,body}, after excluding only requestId
// from body. Pass a contract-validated and contract-normalized DTO encoding.
// JUDGE and IMPORT require nil problemID; management mutations require the
// canonical positive PostgreSQL bigint path identity. Arrays retain order and
// every other body member, including sourceCode, participates in the hash.
func RequestHash(operation string, problemID *string, rawBody []byte) (string, error) {
	switch operation {
	case "JUDGE", "IMPORT":
		if problemID != nil {
			return "", ErrInvalidOperation
		}
	case "PUBLISH", "WITHDRAW", "METADATA_VERSION":
		if problemID == nil || !validProblemID(*problemID) {
			return "", ErrInvalidOperation
		}
	default:
		return "", ErrInvalidOperation
	}
	if err := ValidateJSON(rawBody); err != nil {
		return "", err
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(rawBody, &body); err != nil || body == nil {
		return "", ErrInvalidJSON
	}
	delete(body, "requestId")
	encoded, err := json.Marshal(struct {
		Operation string                     `json:"operation"`
		ProblemID *string                    `json:"problemId"`
		Body      map[string]json.RawMessage `json:"body"`
	}{operation, problemID, body})
	if err != nil {
		return "", ErrInvalidJSON
	}
	return HashJSON(encoded)
}

func validProblemID(value string) bool {
	const largest = "9223372036854775807"
	if len(value) == 0 || value[0] == '0' || len(value) > len(largest) {
		return false
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return len(value) < len(largest) || value <= largest
}
