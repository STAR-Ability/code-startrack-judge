package contract

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

// DecodeJSON rejects missing required fields, undeclared nulls, unknown fields,
// duplicate object names, invalid UTF-8, unpaired UTF-16 surrogates and extra
// JSON values. Field matching is case sensitive, unlike encoding/json's default.
// Use optional:"true" only for contract fields explicitly carrying a '?'.
func DecodeJSON(data []byte, dst any) error {
	t := reflect.TypeOf(dst)
	if t == nil || t.Kind() != reflect.Pointer || reflect.ValueOf(dst).IsNil() {
		return Invalid("body")
	}
	if !utf8.Valid(data) || !validEscapedUnicode(data) {
		return Invalid("body")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if e := uniqueValue(d, 0); e != nil {
		return Invalid("body")
	}
	if _, e := d.Token(); e != io.EOF {
		return Invalid("body")
	}
	if e := checkShape(data, t.Elem(), false); e != nil {
		return e
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if e := d.Decode(dst); e != nil {
		return Invalid("body")
	}
	return ValidateValue(dst)
}

func uniqueValue(d *json.Decoder, depth int) error {
	if depth > 64 {
		return Invalid("body")
	}
	t, e := d.Token()
	if e != nil {
		return e
	}
	if x, ok := t.(json.Delim); ok {
		switch x {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := k.(string)
				if !ok || seen[s] {
					return Invalid("body")
				}
				seen[s] = true
				if e := uniqueValue(d, depth+1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return Invalid("body")
			}
		case '[':
			for d.More() {
				if e := uniqueValue(d, depth+1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return Invalid("body")
			}
		default:
			return Invalid("body")
		}
	}
	return nil
}

type fieldShape struct {
	typ                reflect.Type
	nullable, optional bool
}

func structFields(t reflect.Type, fields map[string]fieldShape) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" {
			continue
		}
		if f.Anonymous && f.Tag.Get("json") == "" {
			n := f.Type
			for n.Kind() == reflect.Pointer {
				n = n.Elem()
			}
			if n.Kind() == reflect.Struct {
				structFields(n, fields)
			}
			continue
		}
		name := strings.Split(f.Tag.Get("json"), ",")[0]
		if name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		fields[name] = fieldShape{f.Type, f.Tag.Get("nullable") == "true", f.Tag.Get("optional") == "true"}
	}
}
func checkShape(raw json.RawMessage, t reflect.Type, nullable bool) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		if nullable {
			return nil
		}
		return Invalid("body")
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		var obj map[string]json.RawMessage
		if json.Unmarshal(raw, &obj) != nil || obj == nil {
			return Invalid("body")
		}
		fields := map[string]fieldShape{}
		structFields(t, fields)
		for name := range obj {
			if _, ok := fields[name]; !ok {
				return Invalid("body")
			}
		}
		for name, f := range fields {
			v, ok := obj[name]
			if !ok {
				if f.optional {
					continue
				}
				return Invalid(name)
			}
			if e := checkShape(v, f.typ, f.nullable); e != nil {
				return e
			}
		}
	case reflect.Slice, reflect.Array:
		var arr []json.RawMessage
		if json.Unmarshal(raw, &arr) != nil {
			return Invalid("body")
		}
		for _, v := range arr {
			if e := checkShape(v, t.Elem(), false); e != nil {
				return e
			}
		}
	case reflect.Map:
		var obj map[string]json.RawMessage
		if json.Unmarshal(raw, &obj) != nil {
			return Invalid("body")
		}
		for _, v := range obj {
			if e := checkShape(v, t.Elem(), t.Elem().Kind() == reflect.Interface); e != nil {
				return e
			}
		}
	}
	return nil
}

// ValidateValue validates nested DTOs inside envelopes and arrays, as well as
// programmatically constructed values before serialization.
func ValidateValue(value any) error { return validateValue(reflect.ValueOf(value), 0) }
func validateValue(v reflect.Value, depth int) error {
	if !v.IsValid() {
		return nil
	}
	if depth > 64 {
		return Invalid("body")
	}
	if (v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface) && v.IsNil() {
		return nil
	}
	if v.CanInterface() {
		if x, ok := v.Interface().(interface{ Validate() error }); ok {
			if e := x.Validate(); e != nil {
				return e
			}
		}
	}
	switch v.Kind() {
	case reflect.Interface, reflect.Pointer:
		return validateValue(v.Elem(), depth+1)
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).PkgPath == "" {
				if e := validateValue(v.Field(i), depth+1); e != nil {
					return e
				}
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if e := validateValue(v.Index(i), depth+1); e != nil {
				return e
			}
		}
	case reflect.Map:
		for _, key := range v.MapKeys() {
			if e := validateValue(key, depth+1); e != nil {
				return e
			}
			if e := validateValue(v.MapIndex(key), depth+1); e != nil {
				return e
			}
		}
	case reflect.String:
		if !utf8.ValidString(v.String()) {
			return Invalid("string")
		}
	case reflect.Float32, reflect.Float64:
		if math.IsNaN(v.Float()) || math.IsInf(v.Float(), 0) {
			return Invalid("number")
		}
	}
	return nil
}

// encoding/json replaces invalid Unicode escapes with U+FFFD. Inspect escapes
// first so hashes and admitted source bytes cannot differ across implementations.
func validEscapedUnicode(data []byte) bool {
	quoted := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			quoted = !quoted
			continue
		}
		if !quoted || data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			return false
		}
		if data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			return false
		}
		n, e := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if e != nil {
			return false
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return false
			}
			low, e := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if e != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}
