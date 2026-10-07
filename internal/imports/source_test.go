// SPDX-License-Identifier: Apache-2.0

package imports

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/STAR-Ability/code-startrack-judge/internal/packages"
)

func TestSourceRejectsUnreviewedRevisionWithoutDispatch(t *testing.T) {
	s, err := NewGitSource(filepath.Join(t.TempDir(), "private"), "/does/not/exist")
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Acquire(context.Background(), strings.Repeat("0", 40), "problems/example")
	if !errors.Is(err, ErrSourceUnsupported) {
		t.Fatal("unreviewed revision entered acquisition")
	}
}

func TestAcquisitionChildCannotInheritCredentialsOrGitConfiguration(t *testing.T) {
	t.Setenv("JUDGE_S2S_TOKEN", "PRIVATE_API_CREDENTIAL_CANARY")
	t.Setenv("HTTPS_PROXY", "PRIVATE_PROXY_CANARY")
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "credential.helper")
	t.Setenv("GIT_CONFIG_VALUE_0", "PRIVATE_HELPER_CANARY")
	s := &GitSource{git: "/bin/sh"}
	cmd := s.command(context.Background(), t.TempDir(), "--", "-c", "env")
	// Execute a trusted process with precisely the acquisition environment. The
	// real Git argv above are intentionally replaced only in this test process.
	cmd.Args = []string{"sh", "-c", "env"}
	output, err := cmd.Output()
	if err != nil {
		t.Fatal("trusted environment probe failed")
	}
	for _, canary := range []string{"PRIVATE_API_CREDENTIAL_CANARY", "PRIVATE_PROXY_CANARY", "PRIVATE_HELPER_CANARY", "GIT_CONFIG_COUNT="} {
		if strings.Contains(string(output), canary) {
			t.Fatal("acquisition child inherited forbidden configuration")
		}
	}
}

func TestGitTreeRejectsLinksSubmodulesPathsAndBounds(t *testing.T) {
	sha := strings.Repeat("a", 40)
	for _, entry := range []string{
		"120000 blob " + sha + " 1\tproblems/a/link\x00",
		"160000 commit " + sha + " -\tproblems/a/module\x00",
		"100644 blob " + sha + " 1\tproblems/a/../escape\x00",
		"100644 blob " + sha + " 67108865\tproblems/a/large\x00",
		"100644 blob " + strings.Repeat("z", 40) + " 1\tproblems/a/object\x00",
	} {
		if _, err := parseTree([]byte(entry), "problems/a", false); err == nil {
			t.Fatal("unsafe Git object entered package files")
		}
	}
	blobs, err := parseTree([]byte("100755 blob "+sha+" 3\tproblems/a/validator.py\x00"), "problems/a", false)
	if err != nil || len(blobs) != 1 || blobs[0].mode != 0o100755 || blobs[0].path != "validator.py" {
		t.Fatal("Git provenance was lost")
	}
}

func TestActualPinnedAcquisitionMatchesIndependentCorpus(t *testing.T) {
	if os.Getenv("JUDGE_TEST_ACQUIRE_PINNED") != "1" {
		t.Skip("explicit fixed-source network acquisition check")
	}
	s, err := NewGitSource(filepath.Join(t.TempDir(), "private"), "/usr/bin/git", os.Getenv("JUDGE_TEST_SOURCE_PROXY"))
	if err != nil {
		t.Fatal(err)
	}
	if cache := os.Getenv("JUDGE_TEST_PINNED_GIT_DIR"); cache != "" {
		// Borrow only a prequalified exact-commit Git object cache; this test
		// never deletes it or accepts moving branches/checkout bytes.
		s.repo = cache
		commit, err := s.output(context.Background(), cache, 128, "rev-parse", "--verify", packages.PinnedRevision+"^{commit}")
		if err != nil || string(commit) != packages.PinnedRevision+"\n" {
			t.Fatal("offline Git cache lacks the exact reviewed source")
		}
	} else {
		t.Cleanup(func() {
			if s.Close() != nil {
				t.Error("cannot clean private acquisition cache")
			}
		})
	}
	snapshot, err := s.Acquire(context.Background(), packages.PinnedRevision, "problems/hello-world")
	if err != nil {
		t.Fatal("fixed-source acquisition failed")
	}
	a, err := packages.Adapt(packages.PinnedSource("problems/hello-world"), snapshot.Files)
	if err != nil || a.SourceSHA256 != "3ba09c605d66dc4ff89f65f391dafd2ba4b06e8f941546b38974f47bf17d5dd2" || a.NormalizedSHA256 != "f08a214687ebcb35b86eafd860c5ced2c085667e616882cfa9deeff585b6b6f9" || len(snapshot.RepositoryLicenses) == 0 {
		t.Fatal("acquisition differs from reviewed Git corpus")
	}
}
