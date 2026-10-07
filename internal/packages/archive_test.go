// SPDX-License-Identifier: Apache-2.0

package packages

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
)

func TestArchiveIndependentGoldenBytes(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/archive-golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Vectors []struct {
			Name  string `json:"name"`
			Files []struct {
				Path string `json:"path"`
				Data string `json:"bytesBase64"`
			} `json:"inputFiles"`
			Paths   []string `json:"orderedPaths"`
			Archive string   `json:"archiveBytesBase64"`
			Size    int      `json:"archiveSizeBytes"`
			Hash    string   `json:"sha256"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, vector := range fixture.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			var files []File
			for _, value := range vector.Files {
				data, err := base64.StdEncoding.DecodeString(value.Data)
				if err != nil {
					t.Fatal(err)
				}
				files = append(files, File{Path: value.Path, Data: data, SourceMode: 0o100755})
			}
			expected, err := base64.StdEncoding.DecodeString(vector.Archive)
			if err != nil {
				t.Fatal(err)
			}
			archive, err := BuildArchive(files)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(archive, expected) || len(archive) != vector.Size || canonical.HashBytes(archive) != vector.Hash {
				for i := 0; i < len(archive) && i < len(expected); i++ {
					if archive[i] != expected[i] {
						t.Logf("first different byte %d: built %02x vector %02x", i, archive[i], expected[i])
						break
					}
				}
				t.Fatal("archive differs from independent format vector")
			}
			if err := VerifyArchive(expected, files); err != nil {
				t.Fatalf("streaming verification rejected independent golden bytes: %v", err)
			}
			decoded, err := ReadArchive(bytes.NewReader(archive))
			if err != nil {
				t.Fatal(err)
			}
			if len(decoded) != len(vector.Paths) {
				t.Fatal("wrong member count")
			}
			standard := tar.NewReader(bytes.NewReader(archive))
			for i, file := range decoded {
				if file.Path != vector.Paths[i] {
					t.Fatal("incorrect canonical member order")
				}
				header, err := standard.Next()
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(standard)
				if err != nil {
					t.Fatal(err)
				}
				if header.Name != file.Path || !bytes.Equal(data, file.Data) || header.Mode != 0o644 || header.Uid != 0 || header.Gid != 0 || header.Typeflag != tar.TypeReg || header.Format != tar.FormatUSTAR {
					t.Fatal("standard parser content/profile mismatch")
				}
			}
			if _, err := standard.Next(); err != io.EOF {
				t.Fatal("extra archive entries")
			}
		})
	}
}

func refreshChecksum(header []byte) {
	for i := 148; i < 156; i++ {
		header[i] = ' '
	}
	var sum uint64
	for _, value := range header[:512] {
		sum += uint64(value)
	}
	octal(header[148:155], sum)
	header[155] = ' '
}

func TestArchiveRejectsMetadataLinksPaddingAndTruncation(t *testing.T) {
	valid, err := BuildArchive([]File{{Path: "safe.txt", Data: []byte("x")}})
	if err != nil {
		t.Fatal(err)
	}
	mutants := map[string]func([]byte) []byte{
		"symlink":           func(b []byte) []byte { b[156] = '2'; copy(b[157:257], "../escape"); refreshChecksum(b); return b },
		"hardlink":          func(b []byte) []byte { b[156] = '1'; copy(b[157:257], "safe.txt"); refreshChecksum(b); return b },
		"pax":               func(b []byte) []byte { b[156] = 'x'; refreshChecksum(b); return b },
		"sparse":            func(b []byte) []byte { b[156] = 'S'; refreshChecksum(b); return b },
		"device":            func(b []byte) []byte { b[156] = '3'; refreshChecksum(b); return b },
		"mtime":             func(b []byte) []byte { b[146] = '1'; refreshChecksum(b); return b },
		"owner":             func(b []byte) []byte { b[265] = 'x'; refreshChecksum(b); return b },
		"checksum":          func(b []byte) []byte { b[148] = '7'; return b },
		"nul-truncation":    func(b []byte) []byte { b[10] = 'x'; refreshChecksum(b); return b },
		"traversal":         func(b []byte) []byte { clear(b[:100]); copy(b[:100], "../escape"); refreshChecksum(b); return b },
		"absolute":          func(b []byte) []byte { clear(b[:100]); copy(b[:100], "/escape"); refreshChecksum(b); return b },
		"oversize":          func(b []byte) []byte { octal(b[124:136], uint64(MaxFileBytes+1)); refreshChecksum(b); return b },
		"malformed-size":    func(b []byte) []byte { b[124] = '9'; refreshChecksum(b); return b },
		"content-padding":   func(b []byte) []byte { b[513] = 'x'; return b },
		"unused-header":     func(b []byte) []byte { b[511] = 1; refreshChecksum(b); return b },
		"truncated-content": func(b []byte) []byte { return b[:513] },
		"single-end-block":  func(b []byte) []byte { return b[:len(b)-512] },
		"extra-end-block":   func(b []byte) []byte { return append(b, make([]byte, 512)...) },
		"trailing-data":     func(b []byte) []byte { return append(b, 'x') },
		"duplicate-member":  func(b []byte) []byte { return append(append(bytes.Clone(b[:1024]), b[:1024]...), b[1024:]...) },
	}
	for name, mutate := range mutants {
		t.Run(name, func(t *testing.T) {
			mutated := mutate(bytes.Clone(valid))
			if _, err := ReadArchive(bytes.NewReader(mutated)); err == nil {
				t.Fatal("unsafe/noncanonical archive accepted")
			}
			if err := VerifyArchive(mutated, []File{{Path: "safe.txt", Data: []byte("x")}}); err == nil {
				t.Fatal("streaming verification accepted unsafe/noncanonical bytes")
			}
		})
	}
	second, err := BuildArchive([]File{{Path: "z.txt", Data: []byte("z")}})
	if err != nil {
		t.Fatal(err)
	}
	unsorted := append(append(bytes.Clone(second[:1024]), valid[:1024]...), make([]byte, 1024)...)
	if _, err := ReadArchive(bytes.NewReader(unsorted)); err == nil {
		t.Fatal("unsorted members accepted")
	}
	if err := VerifyArchive(unsorted, []File{{Path: "safe.txt", Data: []byte("x")}, {Path: "z.txt", Data: []byte("z")}}); err == nil {
		t.Fatal("streaming verification accepted unsorted members")
	}
}

func TestVerifyArchiveBindsActualSnapshotBytesWithoutCopyingPayload(t *testing.T) {
	files := []File{{Path: "payload.bin", Data: bytes.Repeat([]byte{0, 0xff, 1, 2}, 4<<20)}}
	raw, err := BuildArchive(files)
	if err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	err = VerifyArchive(raw, files)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	// Payload is 16 MiB. Even a single full member/archive copy violates the
	// budget; maps, sorted borrowed File descriptors and headers stay small.
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 1<<20 {
		t.Fatalf("verification allocated payload-sized storage: %d bytes", allocated)
	}
	raw[512+777] ^= 1
	if err := VerifyArchive(raw, files); err == nil {
		t.Fatal("changed archive member bytes accepted against sealed snapshot")
	}
	raw[512+777] ^= 1
	files[0].Data[777] ^= 1
	if err := VerifyArchive(raw, files); err == nil {
		t.Fatal("changed snapshot bytes accepted against sealed archive")
	}
}

func TestArchivePathAndPortableCollisionBounds(t *testing.T) {
	for _, value := range []string{"", "/a", "a/../b", "a//b", "a/./b", "a\\b", "a%2fb", "https://a", "a\x00b", "a\nb", string([]byte{0xff}), strings.Repeat("a", 101)} {
		if ValidatePath(value) == nil {
			t.Errorf("unsafe path accepted: %q", value)
		}
	}
	for name, files := range map[string][]File{
		"duplicate": {{Path: "a"}, {Path: "a"}}, "case": {{Path: "A"}, {Path: "a"}}, "unicode-case-fold": {{Path: "Σ"}, {Path: "ς"}}, "NFC": {{Path: "caf\u00e9"}, {Path: "cafe\u0301"}}, "file-directory": {{Path: "a"}, {Path: "a/b"}}, "portable-file-directory": {{Path: "A"}, {Path: "a/b"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := BuildArchive(files); err == nil {
				t.Fatal("colliding paths accepted")
			}
		})
	}
	if _, err := BuildArchive(make([]File, MaxFiles+1)); err == nil {
		t.Fatal("file count cap not enforced")
	}
	if _, err := BuildArchive([]File{{Path: "big", Data: make([]byte, MaxFileBytes+1)}}); err == nil {
		t.Fatal("file byte cap not enforced")
	}
	if _, err := validateFiles([]File{{Path: "a", SourceMode: 0o120000}}, true); err == nil {
		t.Fatal("source symlink mode accepted")
	}
}
