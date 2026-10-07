// SPDX-License-Identifier: Apache-2.0

package packages

import (
	"bytes"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

const (
	MaxFileBytes    int64 = 64 << 20
	MaxTotalBytes   int64 = 512 << 20
	MaxFiles              = 65536
	MaxTests              = 4096
	MaxArchiveBytes int64 = MaxTotalBytes + MaxFiles*1023 + 1024
)

var (
	ErrInvalidArchive = errors.New("invalid package archive")
	ErrUnsafePath     = errors.New("unsafe package path")
	ErrBounds         = errors.New("package bounds exceeded")
)

// File is an inert source/normalized byte snapshot, never an execution request.
// SourceMode preserves Git provenance; archive headers always use regular0644.
type File struct {
	Path       string
	Data       []byte
	SourceMode uint32
}

func (File) String() string     { return "private package file [bytes and path redacted]" }
func (f File) GoString() string { return f.String() }

func pathParts(value string) (name, prefix string, err error) {
	if value == "" || !utf8.ValidString(value) || strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\\%:") {
		return "", "", ErrUnsafePath
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return "", "", ErrUnsafePath
		}
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return "", "", ErrUnsafePath
		}
	}
	if len(value) <= 100 {
		return value, "", nil
	}
	for i := len(value) - 1; i >= 0; i-- {
		if value[i] == '/' && i <= 155 && len(value)-i-1 <= 100 {
			return value[i+1:], value[:i], nil
		}
	}
	return "", "", ErrUnsafePath
}

func ValidatePath(value string) error { _, _, err := pathParts(value); return err }
func ValidateSourcePath(value string) error {
	if value == ReservedManifestPath {
		return ErrUnsafePath
	}
	return ValidatePath(value)
}

func validSourceMode(mode uint32) bool {
	return mode == 0 || mode == 0o644 || mode == 0o755 || mode == 0o100644 || mode == 0o100755
}

func portablePath(value string) string { return norm.NFC.String(cases.Fold().String(value)) }

func validateFiles(files []File, source bool) (int64, error) {
	if len(files) > MaxFiles {
		return 0, ErrBounds
	}
	seen := make(map[string]bool, len(files))
	portable := make(map[string]bool, len(files))
	var total int64
	for _, file := range files {
		if err := ValidatePath(file.Path); err != nil {
			return 0, err
		}
		if source && (file.Path == ReservedManifestPath || !validSourceMode(file.SourceMode)) {
			return 0, ErrUnsafePath
		}
		key := portablePath(file.Path)
		if seen[file.Path] || portable[key] {
			return 0, ErrInvalidArchive
		}
		seen[file.Path] = true
		portable[key] = true
		if int64(len(file.Data)) > MaxFileBytes {
			return 0, ErrBounds
		}
		total += int64(len(file.Data))
		if total > MaxTotalBytes {
			return 0, ErrBounds
		}
	}
	for path := range seen {
		for offset := strings.LastIndexByte(path, '/'); offset >= 0; offset = strings.LastIndexByte(path[:offset], '/') {
			if seen[path[:offset]] || portable[portablePath(path[:offset])] {
				return 0, ErrInvalidArchive
			}
		}
	}
	return total, nil
}

func octal(destination []byte, value uint64) {
	for i := range destination {
		destination[i] = '0'
	}
	destination[len(destination)-1] = 0
	number := strconv.FormatUint(value, 8)
	copy(destination[len(destination)-1-len(number):], number)
}

func archiveHeader(file File) ([512]byte, error) {
	var header [512]byte
	name, prefix, err := pathParts(file.Path)
	if err != nil {
		return header, err
	}
	copy(header[0:100], name)
	octal(header[100:108], 0o644)
	octal(header[108:116], 0)
	octal(header[116:124], 0)
	octal(header[124:136], uint64(len(file.Data)))
	octal(header[136:148], 0)
	for i := 148; i < 156; i++ {
		header[i] = ' '
	}
	header[156] = '0'
	copy(header[257:263], "ustar\x00")
	copy(header[263:265], "00")
	// Device fields are unused for regular files and remain all-zero bytes,
	// exactly as frozen by the independently generated archive vectors.
	copy(header[345:500], prefix)
	var sum uint64
	for _, b := range header {
		sum += uint64(b)
	}
	octal(header[148:155], sum)
	header[155] = ' '
	return header, nil
}

func orderedArchiveFiles(files []File) ([]File, int64, error) {
	if _, err := validateFiles(files, false); err != nil {
		return nil, 0, err
	}
	ordered := append([]File(nil), files...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Path < ordered[j].Path })
	var size int64 = 1024
	for _, f := range ordered {
		size += 512 + ((int64(len(f.Data))+511)/512)*512
	}
	if size > MaxArchiveBytes {
		return nil, 0, ErrBounds
	}
	return ordered, size, nil
}

func writeCanonicalArchive(output io.Writer, ordered []File) error {
	write := func(raw []byte) error {
		n, err := output.Write(raw)
		if err == nil && n != len(raw) {
			return io.ErrShortWrite
		}
		return err
	}
	var padding [512]byte
	for _, file := range ordered {
		header, err := archiveHeader(file)
		if err != nil {
			return err
		}
		if err := write(header[:]); err != nil {
			return err
		}
		if err := write(file.Data); err != nil {
			return err
		}
		if remainder := len(file.Data) % 512; remainder != 0 {
			if err := write(padding[:512-remainder]); err != nil {
				return err
			}
		}
	}
	if err := write(padding[:]); err != nil {
		return err
	}
	return write(padding[:])
}

// BuildArchive constructs the exact startrack-ustar-v1 bytes. Only the owned
// normalized builder may add ReservedManifestPath; source intake rejects it.
func BuildArchive(files []File) ([]byte, error) {
	ordered, size, err := orderedArchiveFiles(files)
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	output.Grow(int(size))
	if err := writeCanonicalArchive(&output, ordered); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

type archiveComparisonWriter struct{ remaining []byte }

func (w *archiveComparisonWriter) Write(expected []byte) (int, error) {
	if len(expected) > len(w.remaining) || !bytes.Equal(expected, w.remaining[:len(expected)]) {
		return 0, ErrInvalidArchive
	}
	w.remaining = w.remaining[len(expected):]
	return len(expected), nil
}

// VerifyArchive compares sealed bytes with the exact canonical archive of the
// supplied inert snapshots. It borrows their byte slices and streams canonical
// headers/data/padding into a comparison writer, without rebuilding an archive
// buffer or decoding/copying archive member contents.
func VerifyArchive(raw []byte, files []File) error {
	if int64(len(raw)) > MaxArchiveBytes {
		return ErrBounds
	}
	ordered, size, err := orderedArchiveFiles(files)
	if err != nil {
		return err
	}
	if int64(len(raw)) != size {
		return ErrInvalidArchive
	}
	output := &archiveComparisonWriter{remaining: raw}
	if err := writeCanonicalArchive(output, ordered); err != nil {
		return err
	}
	if len(output.remaining) != 0 {
		return ErrInvalidArchive
	}
	return nil
}

func zeroBytes(raw []byte) bool {
	for _, b := range raw {
		if b != 0 {
			return false
		}
	}
	return true
}
func fieldString(raw []byte) (string, error) {
	if i := bytes.IndexByte(raw, 0); i >= 0 {
		if !zeroBytes(raw[i:]) {
			return "", ErrInvalidArchive
		}
		raw = raw[:i]
	}
	if !utf8.Valid(raw) {
		return "", ErrInvalidArchive
	}
	return string(raw), nil
}

// ReadArchive accepts only canonical regular-file archives. It performs no
// filesystem writes, follows no links and returns bounded inert byte slices.
func ReadArchive(reader io.Reader) ([]File, error) {
	if reader == nil {
		return nil, ErrInvalidArchive
	}
	raw, err := io.ReadAll(io.LimitReader(reader, MaxArchiveBytes+1))
	if err != nil {
		return nil, ErrInvalidArchive
	}
	if int64(len(raw)) > MaxArchiveBytes {
		return nil, ErrBounds
	}
	var files []File
	offset := 0
	var total int64
	previous := ""
	for {
		if len(raw)-offset < 1024 {
			return nil, ErrInvalidArchive
		}
		header := raw[offset : offset+512]
		if zeroBytes(header) {
			if len(raw)-offset != 1024 || !zeroBytes(raw[offset:]) {
				return nil, ErrInvalidArchive
			}
			break
		}
		if len(files) == MaxFiles {
			return nil, ErrBounds
		}
		name, e := fieldString(header[:100])
		if e != nil {
			return nil, e
		}
		prefix, e := fieldString(header[345:500])
		if e != nil {
			return nil, e
		}
		if prefix != "" {
			name = prefix + "/" + name
		}
		if ValidatePath(name) != nil || len(files) > 0 && name <= previous {
			return nil, ErrInvalidArchive
		}
		previous = name
		size, e := strconv.ParseUint(strings.TrimRight(string(header[124:136]), "\x00 "), 8, 64)
		if e != nil || size > uint64(MaxFileBytes) {
			return nil, ErrBounds
		}
		total += int64(size)
		if total > MaxTotalBytes {
			return nil, ErrBounds
		}
		offset += 512
		padded := (int(size) + 511) / 512 * 512
		if padded > len(raw)-offset {
			return nil, ErrInvalidArchive
		}
		file := File{Path: name, Data: raw[offset : offset+int(size)], SourceMode: 0o644}
		canonical, e := archiveHeader(file)
		if e != nil || !bytes.Equal(header, canonical[:]) || !zeroBytes(raw[offset+int(size):offset+padded]) {
			return nil, ErrInvalidArchive
		}
		files = append(files, file)
		offset += padded
	}
	if _, err := validateFiles(files, false); err != nil {
		return nil, err
	}
	return files, nil
}
