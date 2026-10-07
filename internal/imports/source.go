// SPDX-License-Identifier: Apache-2.0

package imports

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/packages"
)

var ErrSourceUnavailable = errors.New("fixed import source unavailable")
var ErrSourceUnsupported = errors.New("import source revision is not reviewed")

type SourceSnapshot struct {
	Files              []packages.File
	RepositoryLicenses []packages.File
}

type Source interface {
	Acquire(context.Context, string, string) (SourceSnapshot, error)
}

// GitSource acquires only the reviewed repository/commit. It never checks out
// files, runs hooks/submodules, or inherits API secrets, proxy or Git settings.
// Git is a trusted image-owned executable; callers cannot select its argv.
type GitSource struct {
	root  string
	git   string
	mu    sync.Mutex
	repo  string
	proxy string
}

// proxyURL is an optional trusted operator transport setting, never an API
// field. Ambient proxy variables are not inherited. Proxy credentials are
// forbidden, so the acquisition process receives no additional secret.
func NewGitSource(root, gitExecutable string, proxyURL ...string) (*GitSource, error) {
	if !filepath.IsAbs(root) || !filepath.IsAbs(gitExecutable) {
		return nil, ErrSourceUnavailable
	}
	if len(proxyURL) > 1 {
		return nil, ErrSourceUnavailable
	}
	proxy := ""
	if len(proxyURL) == 1 && proxyURL[0] != "" {
		value := proxyURL[0]
		parsed, err := url.Parse(value)
		if err != nil || len(value) > 2048 || !utf8.ValidString(value) || strings.IndexFunc(value, unicode.IsControl) >= 0 || strings.Contains(value, "#") || parsed.Opaque != "" || parsed.ForceQuery || (parsed.Scheme != "http" && parsed.Scheme != "https" && parsed.Scheme != "socks5") || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") || strings.HasSuffix(parsed.Host, ":") {
			return nil, ErrSourceUnavailable
		}
		if port := parsed.Port(); port != "" {
			parsedPort, err := strconv.ParseUint(port, 10, 16)
			if err != nil || parsedPort == 0 {
				return nil, ErrSourceUnavailable
			}
		}
		proxy = parsed.String()
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, ErrSourceUnavailable
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return nil, ErrSourceUnavailable
	}
	return &GitSource{root: root, git: gitExecutable, proxy: proxy}, nil
}

func (s *GitSource) Ready(ctx context.Context) bool {
	if ctx == nil || ctx.Err() != nil {
		return false
	}
	info, err := os.Stat(s.git)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0
}

func (s *GitSource) command(ctx context.Context, work string, args ...string) *exec.Cmd {
	fixed := []string{"--literal-pathspecs", "-c", "core.hooksPath=/dev/null", "-c", "credential.helper=", "-c", "http.proxy=" + s.proxy, "-c", "http.followRedirects=false", "-c", "protocol.allow=never", "-c", "protocol.https.allow=always"}
	cmd := exec.CommandContext(ctx, s.git, append(fixed, args...)...)
	cmd.Dir = work
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "HOME=" + work, "TMPDIR=" + work, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=/bin/false", "GIT_PROTOCOL_FROM_USER=0"}
	cmd.Stderr = io.Discard
	cmd.WaitDelay = 5 * time.Second
	return cmd
}

type boundedOutput struct {
	bytes.Buffer
	limit int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, ErrSourceUnavailable
	}
	return b.Buffer.Write(p)
}

func (s *GitSource) output(ctx context.Context, repo string, limit int, args ...string) ([]byte, error) {
	cmd := s.command(ctx, repo, append([]string{"--git-dir=" + repo}, args...)...)
	out := &boundedOutput{limit: limit}
	cmd.Stdout = out
	if cmd.Run() != nil {
		return nil, ErrSourceUnavailable
	}
	return out.Bytes(), nil
}

func (s *GitSource) initialize(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.repo != "" {
		return s.repo, nil
	}
	dir, err := os.MkdirTemp(s.root, "pinned-")
	if err != nil {
		return "", ErrSourceUnavailable
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(dir)
		}
	}()
	cmd := s.command(ctx, dir, "init", "--bare", "--template=", dir)
	cmd.Stdout = io.Discard
	if cmd.Run() != nil {
		return "", ErrSourceUnavailable
	}
	cmd = s.command(ctx, dir, "--git-dir="+dir, "fetch", "--depth=1", "--no-tags", "--no-recurse-submodules", packages.RepositoryURL, packages.PinnedRevision)
	cmd.Stdout = io.Discard
	if cmd.Run() != nil {
		return "", ErrSourceUnavailable
	}
	commit, err := s.output(ctx, dir, 128, "rev-parse", "--verify", "FETCH_HEAD^{commit}")
	if err != nil || string(commit) != packages.PinnedRevision+"\n" {
		return "", ErrSourceUnavailable
	}
	s.repo, ok = dir, true
	return dir, nil
}

type gitBlob struct {
	path string
	oid  string
	mode uint32
	size int64
}

func parseTree(raw []byte, prefix string, rootLicenses bool) ([]gitBlob, error) {
	entries := bytes.Split(raw, []byte{0})
	blobs := make([]gitBlob, 0)
	var total int64
	for _, entry := range entries {
		if len(entry) == 0 {
			continue
		}
		parts := bytes.SplitN(entry, []byte{'\t'}, 2)
		if len(parts) != 2 {
			return nil, ErrSourceUnavailable
		}
		name := string(parts[1])
		if rootLicenses {
			upper := strings.ToUpper(name)
			if upper != "LICENSE" && upper != "LICENSE.MD" && upper != "LICENSE.TXT" && upper != "NOTICE" && upper != "COPYING" {
				continue
			}
		} else {
			if !strings.HasPrefix(name, prefix+"/") {
				return nil, packages.ErrUnsafePath
			}
			name = strings.TrimPrefix(name, prefix+"/")
		}
		if packages.ValidateSourcePath(name) != nil {
			return nil, packages.ErrUnsafePath
		}
		header := strings.Fields(string(parts[0]))
		if len(header) != 4 || header[1] != "blob" || len(header[2]) != 40 {
			return nil, packages.ErrUnsafePath
		}
		if _, err := hex.DecodeString(header[2]); err != nil {
			return nil, packages.ErrUnsafePath
		}
		mode, e1 := strconv.ParseUint(header[0], 8, 32)
		size, e2 := strconv.ParseInt(header[3], 10, 64)
		if e1 != nil || e2 != nil || (mode != 0o100644 && mode != 0o100755) || size < 0 || size > packages.MaxFileBytes || rootLicenses && size > 1<<20 {
			return nil, packages.ErrBounds
		}
		total += size
		if total > packages.MaxTotalBytes || len(blobs) >= packages.MaxFiles {
			return nil, packages.ErrBounds
		}
		blobs = append(blobs, gitBlob{name, header[2], uint32(mode), size})
	}
	return blobs, nil
}

// Close removes only the private cache allocated by this instance. Lifecycle
// owners call it after all import work has drained.
func (s *GitSource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.repo == "" {
		return nil
	}
	if err := os.RemoveAll(s.repo); err != nil {
		return ErrSourceUnavailable
	}
	s.repo = ""
	return nil
}

func (s *GitSource) readBlobs(ctx context.Context, repo string, blobs []gitBlob) ([]packages.File, error) {
	if len(blobs) == 0 {
		return []packages.File{}, nil
	}
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := s.command(childCtx, repo, "--git-dir="+repo, "cat-file", "--batch")
	var input strings.Builder
	for _, blob := range blobs {
		fmt.Fprintln(&input, blob.oid)
	}
	cmd.Stdin = strings.NewReader(input.String())
	pipe, err := cmd.StdoutPipe()
	if err != nil || cmd.Start() != nil {
		return nil, ErrSourceUnavailable
	}
	defer func() { cancel(); _ = cmd.Wait() }()
	reader := bufio.NewReaderSize(pipe, 4096)
	files := make([]packages.File, 0, len(blobs))
	for _, blob := range blobs {
		header, err := reader.ReadSlice('\n')
		if err != nil || string(header) != fmt.Sprintf("%s blob %d\n", blob.oid, blob.size) {
			return nil, ErrSourceUnavailable
		}
		data := make([]byte, int(blob.size))
		if _, err := io.ReadFull(reader, data); err != nil {
			return nil, ErrSourceUnavailable
		}
		if next, err := reader.ReadByte(); err != nil || next != '\n' {
			return nil, ErrSourceUnavailable
		}
		files = append(files, packages.File{Path: blob.path, SourceMode: blob.mode, Data: data})
	}
	if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
		return nil, ErrSourceUnavailable
	}
	if cmd.Wait() != nil {
		return nil, ErrSourceUnavailable
	}
	return files, nil
}

func (s *GitSource) Acquire(ctx context.Context, revision, packagePath string) (SourceSnapshot, error) {
	if revision != packages.PinnedRevision {
		return SourceSnapshot{}, ErrSourceUnsupported
	}
	if !contract.ValidPackagePath(packagePath) || packages.ValidatePath(packagePath) != nil {
		return SourceSnapshot{}, packages.ErrUnsafePath
	}
	acquisitionCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	repo, err := s.initialize(acquisitionCtx)
	if err != nil {
		return SourceSnapshot{}, err
	}
	raw, err := s.output(acquisitionCtx, repo, 32<<20, "ls-tree", "-r", "-l", "-z", revision, "--", packagePath+"/")
	if err != nil {
		return SourceSnapshot{}, err
	}
	blobs, err := parseTree(raw, packagePath, false)
	if err != nil {
		return SourceSnapshot{}, err
	}
	if len(blobs) == 0 {
		return SourceSnapshot{}, &packages.AdaptError{Code: "PACKAGE_INVALID", Stage: "INVALID_STRUCTURE", Diagnostic: "PACKAGE_NOT_FOUND"}
	}
	files, err := s.readBlobs(acquisitionCtx, repo, blobs)
	if err != nil {
		return SourceSnapshot{}, err
	}
	rootTree, err := s.output(acquisitionCtx, repo, 1<<20, "ls-tree", "-l", "-z", revision)
	if err != nil {
		return SourceSnapshot{}, err
	}
	licenses, err := parseTree(rootTree, "", true)
	if err != nil {
		return SourceSnapshot{}, err
	}
	texts, err := s.readBlobs(acquisitionCtx, repo, licenses)
	return SourceSnapshot{Files: files, RepositoryLicenses: texts}, err
}
