package canonical

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

type goldenFixture struct {
	SchemaVersion int `json:"schemaVersion"`
	JSONVectors   []struct {
		Name       string `json:"name"`
		Input      string `json:"input"`
		Canonical  string `json:"canonical"`
		SHA256     string `json:"sha256"`
		IEEE754Hex string `json:"ieee754hex"`
	} `json:"jsonVectors"`
	RequestVectors []struct {
		Name      string  `json:"name"`
		Operation string  `json:"operation"`
		ProblemID *string `json:"problemId"`
		Body      string  `json:"body"`
		Canonical string  `json:"canonical"`
		SHA256    string  `json:"sha256"`
	} `json:"requestVectors"`
	SourceVectors []struct {
		Name   string `json:"name"`
		Source string `json:"source"`
		SHA256 string `json:"sha256"`
	} `json:"sourceVectors"`
	ByteVectors []struct {
		Name        string `json:"name"`
		InputBase64 string `json:"inputBase64"`
		SHA256      string `json:"sha256"`
	} `json:"byteVectors"`
	InvalidVectors []struct {
		Name        string `json:"name"`
		Input       string `json:"input"`
		InputBase64 string `json:"inputBase64"`
		Error       string `json:"error"`
	} `json:"invalidVectors"`
}

func readGolden(t *testing.T) goldenFixture {
	t.Helper()
	encoded, err := os.ReadFile("../../testdata/canonical-golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture goldenFixture
	if err := json.Unmarshal(encoded, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.SchemaVersion != 1 || len(fixture.JSONVectors) < 40 {
		t.Fatal("missing shared canonical golden vectors")
	}
	return fixture
}

func TestCanonicalGoldenVectors(t *testing.T) {
	for _, vector := range readGolden(t).JSONVectors {
		t.Run(vector.Name, func(t *testing.T) {
			if vector.IEEE754Hex != "" {
				expected, err := strconv.ParseUint(vector.IEEE754Hex, 16, 64)
				if err != nil {
					t.Fatal(err)
				}
				value, err := strconv.ParseFloat(vector.Input, 64)
				if err != nil || math.Float64bits(value) != expected {
					t.Fatal("RFC Appendix B input lost its specified IEEE-754 representation")
				}
			}
			actual, err := Canonicalize([]byte(vector.Input))
			if err != nil {
				t.Fatal(err)
			}
			if string(actual) != vector.Canonical {
				t.Errorf("canonical mismatch: got %q want %q", actual, vector.Canonical)
			}
			digest, err := HashJSON([]byte(vector.Input))
			if err != nil || digest != vector.SHA256 {
				t.Errorf("SHA-256 mismatch: got %s want %s (error %v)", digest, vector.SHA256, err)
			}
			second, err := Canonicalize(actual)
			if err != nil || !bytes.Equal(actual, second) {
				t.Fatal("canonical serialization is not idempotent")
			}
		})
	}
}

func TestRequestAndSourceGoldenVectors(t *testing.T) {
	fixture := readGolden(t)
	for _, vector := range fixture.RequestVectors {
		t.Run(vector.Name, func(t *testing.T) {
			actual, err := RequestHash(vector.Operation, vector.ProblemID, []byte(vector.Body))
			if err != nil || actual != vector.SHA256 {
				t.Errorf("request digest mismatch: got %s want %s (error %v)", actual, vector.SHA256, err)
			}
		})
	}
	for _, vector := range fixture.SourceVectors {
		t.Run(vector.Name, func(t *testing.T) {
			actual, err := HashSource(vector.Source)
			if err != nil || actual != vector.SHA256 {
				t.Errorf("source digest mismatch: got %s want %s (error %v)", actual, vector.SHA256, err)
			}
		})
	}
	for _, vector := range fixture.ByteVectors {
		t.Run(vector.Name, func(t *testing.T) {
			input, err := base64.StdEncoding.DecodeString(vector.InputBase64)
			if err != nil {
				t.Fatal(err)
			}
			if actual := HashBytes(input); actual != vector.SHA256 {
				t.Errorf("binary digest mismatch: got %s want %s", actual, vector.SHA256)
			}
		})
	}
}

func TestMalformedGoldenVectors(t *testing.T) {
	errorsByCategory := map[string]error{
		"json": ErrInvalidJSON, "utf8": ErrInvalidUTF8,
		"duplicate": ErrDuplicateKey, "surrogate": ErrUnpairedSurrogate,
	}
	for _, vector := range readGolden(t).InvalidVectors {
		t.Run(vector.Name, func(t *testing.T) {
			input := []byte(vector.Input)
			if vector.InputBase64 != "" {
				var err error
				input, err = base64.StdEncoding.DecodeString(vector.InputBase64)
				if err != nil {
					t.Fatal(err)
				}
			}
			expected := errorsByCategory[vector.Error]
			for _, validate := range []func([]byte) error{
				ValidateJSON,
				func(raw []byte) error { _, err := Canonicalize(raw); return err },
				func(raw []byte) error { _, err := HashJSON(raw); return err },
			} {
				if err := validate(input); !errors.Is(err, expected) {
					t.Errorf("malformed input accepted or wrong category: got %v want %v", err, expected)
				}
			}
		})
	}
}

func TestErrorDoesNotDiscloseInput(t *testing.T) {
	const sensitive = "private-hidden-test-address"
	_, err := Canonicalize([]byte(`{"` + sensitive + `":1,"` + sensitive + `":2}`))
	if !errors.Is(err, ErrDuplicateKey) || strings.Contains(err.Error(), sensitive) {
		t.Fatalf("duplicate-key diagnostic disclosed input: %v", err)
	}
	if _, err := HashSource(string([]byte{0xff})); !errors.Is(err, ErrInvalidUTF8) {
		t.Fatal("source hashing repaired invalid UTF-8")
	}
}

func TestEscapedBackslashAndReplacementCharacterAreValid(t *testing.T) {
	for _, raw := range []string{`"\\ud800"`, `"\ufffd"`, `"\ud800\udc00"`, `{"é":1,"e\u0301":2}`} {
		if _, err := Canonicalize([]byte(raw)); err != nil {
			t.Errorf("valid Unicode or literal backslash rejected: %v", err)
		}
	}
}

func TestRequestIdentityValidation(t *testing.T) {
	body := []byte(`{"requestId":"correlation-id","nested":{"requestId":"immutable-input"}}`)
	for _, id := range []string{"", "0", "01", "-1", "1.0", "9223372036854775808"} {
		if _, err := RequestHash("PUBLISH", &id, body); !errors.Is(err, ErrInvalidOperation) {
			t.Errorf("invalid path identity %q accepted", id)
		}
	}
	id := "42"
	for _, input := range []struct {
		operation string
		problemID *string
	}{
		{"UNREVIEWED_OPERATION", nil}, {"PUBLISH", nil}, {"JUDGE", &id}, {"IMPORT", &id},
	} {
		if _, err := RequestHash(input.operation, input.problemID, body); !errors.Is(err, ErrInvalidOperation) {
			t.Errorf("invalid operation/resource pairing accepted: %s", input.operation)
		}
	}
	for _, raw := range []string{"null", "[]", "1", `{"x":1,"x":2}`, `{"x":"\ud800"}`, `{"x":1e400}`} {
		if _, err := RequestHash("JUDGE", nil, []byte(raw)); err == nil {
			t.Errorf("invalid request body accepted: %s", raw)
		}
	}
	actual, err := RequestHash("JUDGE", nil, body)
	expected, expectedErr := HashJSON([]byte(`{"operation":"JUDGE","problemId":null,"body":{"nested":{"requestId":"immutable-input"}}}`))
	if err != nil || expectedErr != nil || actual != expected {
		t.Fatal("requestId exclusion affected a nested immutable field")
	}
}

func FuzzCanonicalization(f *testing.F) {
	for _, seed := range []string{"{}", "[]", "null", "-0", `{"😀":1,"a":[null,1.0]}`, `{"x":"\ud800"}`, `{"x":1,"x":2}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		encoded, err := Canonicalize(raw)
		if err != nil {
			return
		}
		if !json.Valid(encoded) || !utf8.Valid(encoded) {
			t.Fatal("canonicalization produced invalid UTF-8 JSON")
		}
		second, err := Canonicalize(encoded)
		if err != nil || !bytes.Equal(encoded, second) {
			t.Fatal("canonicalization is not idempotent")
		}
	})
}
