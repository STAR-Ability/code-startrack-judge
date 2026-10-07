// SPDX-License-Identifier: Apache-2.0
package runtime

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/runtime/restclient"
)

func (a *Adapter) matureCompile(ctx context.Context, id string, p Program) (artifact programArtifact, response MatureResponse, err error) {
	data, e := a.read(ctx, p.File)
	if e != nil {
		return artifact, response, e
	}
	s := a.factory.NewSession()
	defer func() {
		if e := s.Close(); e != nil {
			a.failClosed()
			err = failure("SANDBOX_CLEANUP_FAILED", true)
		}
	}()
	stdin, e := s.Upload(ctx, nil)
	if e != nil {
		return artifact, response, transportFailure(e, false)
	}
	source, e := s.Upload(ctx, data)
	if e != nil {
		return artifact, response, transportFailure(e, false)
	}
	argv, sourceName := CompileTemplate(), "main.cpp"
	if p.LanguageID == "python3" {
		argv = []string{"/usr/local/bin/python3", "-I", "-m", "py_compile", "/w/main.py"}
		sourceName = "main.py"
	}
	cmd := command(argv, stdin, map[string]restclient.FileID{sourceName: source}, compilerLimits())
	if p.LanguageID == LanguageID {
		cmd.CopyOutCached = append(cmd.CopyOutCached, restclient.Output{Name: "main", Optional: true})
		cmd.CopyOutMaxBytes = MaxFileBytes
	}
	r, e := a.runOne(ctx, s, id, cmd)
	if e != nil {
		return artifact, response, e
	}
	verdict, code := compilerVerdict(r)
	if verdict == contract.VerdictIE {
		return artifact, response, failure("MATURE_COMPILE_INFRASTRUCTURE_FAILED", false)
	}
	response = MatureResponse{OK: true, Compiled: verdict == contract.VerdictAC, Code: code, WaitStatus: matureWaitStatus(r), CPUNS: r.CPUTimeNS}
	for name, target := range map[string]*string{"stdout": &response.StdoutBase64, "stderr": &response.StderrBase64} {
		file, exists := r.CachedFiles[name]
		if !exists {
			return artifact, response, failure("MATURE_STDIO_MISSING", false)
		}
		output, e := s.Download(ctx, file, int64(compilerLimits().OutputBytes))
		if e != nil {
			return artifact, response, transportFailure(e, false)
		}
		*target = base64.StdEncoding.EncodeToString(output)
	}
	if !response.Compiled {
		return artifact, response, nil
	}
	artifact.language = p.LanguageID
	if p.LanguageID == "python3" {
		artifact.data = bytes.Clone(data)
		return artifact, response, nil
	}
	file, exists := r.CachedFiles["main"]
	if !exists {
		return artifact, response, failure("MATURE_EXECUTABLE_MISSING", false)
	}
	artifact.data, e = s.Download(ctx, file, MaxFileBytes)
	if e != nil {
		return artifact, response, transportFailure(e, false)
	}
	if len(artifact.data) < 4 || !bytes.Equal(artifact.data[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		return artifact, response, failure("MATURE_EXECUTABLE_INVALID", false)
	}
	return artifact, response, nil
}

// Chunking preserves the full statement view while remaining inside the pinned
// REST file/cache bounds. Only Go-owned tar headers and verified public-role
// bytes enter the statement sandbox; extraction happens there, never on host.
type statementChunkWriter struct {
	chunks map[string][]byte
	number int
	total  int64
}

func (w *statementChunkWriter) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		if w.number == 0 || len(w.chunks[fmt.Sprintf("statement.%06d.tarpart", w.number)]) == MaxFileBytes {
			w.number++
			if w.number > 12 {
				return written, failure("STATEMENT_BUNDLE_BOUNDS", false)
			}
		}
		name := fmt.Sprintf("statement.%06d.tarpart", w.number)
		space := MaxFileBytes - len(w.chunks[name])
		n := len(p)
		if n > space {
			n = space
		}
		w.chunks[name] = append(w.chunks[name], p[:n]...)
		w.total += int64(n)
		written += n
		p = p[n:]
	}
	return written, nil
}
func statementChunks(files map[string][]byte) (map[string][]byte, error) {
	writer := &statementChunkWriter{chunks: map[string][]byte{}}
	archive := tar.NewWriter(writer)
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		data := files[path]
		if e := archive.WriteHeader(&tar.Header{Name: path, Mode: 0644, Size: int64(len(data)), Typeflag: tar.TypeReg, Format: tar.FormatPAX, ModTime: time.Unix(0, 0)}); e != nil {
			return nil, failure("STATEMENT_BUNDLE_INVALID", false)
		}
		if _, e := archive.Write(data); e != nil {
			return nil, e
		}
	}
	if e := archive.Close(); e != nil {
		return nil, e
	}
	return writer.chunks, nil
}
