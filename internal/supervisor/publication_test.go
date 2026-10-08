package supervisor

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPublicationRevokeSerializesWithFinalRename(t *testing.T) {
	for _, revokeFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "rename_then_revoke", true: "revoke_then_rename"}[revokeFirst], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "measurement")
			temporary := path + ".tmp"
			if err := os.WriteFile(temporary, []byte("fully checked fresh measurement"), 0644); err != nil {
				t.Fatal(err)
			}
			p := newQualificationPublication(path)
			if revokeFirst {
				if err := p.revoke(); err != nil {
					t.Fatal(err)
				}
				if err := p.publish(temporary); err != errQualificationRevoked {
					t.Fatalf("late publication = %v", err)
				}
			} else {
				entered, resume := make(chan struct{}), make(chan struct{})
				p.rename = func(from, to string) error {
					close(entered)
					<-resume
					return os.Rename(from, to)
				}
				published, revoked := make(chan error, 1), make(chan error, 1)
				go func() { published <- p.publish(temporary) }()
				<-entered
				go func() { revoked <- p.revoke() }()
				close(resume)
				if err := <-published; err != nil {
					t.Fatal(err)
				}
				if err := <-revoked; err != nil {
					t.Fatal(err)
				}
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("measurement survived terminal revoke: %v", err)
			}
			if p.admitProbe() {
				t.Fatal("scheduled another probe after revoke")
			}
		})
	}
}

func TestPublicationFatalWinsConcurrentRenameAndCannotRecover(t *testing.T) {
	path := filepath.Join(t.TempDir(), "measurement")
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, []byte("checked measurement"), 0644); err != nil {
		t.Fatal(err)
	}
	p := newQualificationPublication(path)
	entered, resume := make(chan struct{}), make(chan struct{})
	p.rename = func(from, to string) error {
		close(entered)
		<-resume
		return os.Rename(from, to)
	}
	published, rejected := make(chan error, 1), make(chan struct{})
	go func() { published <- p.publish(temporary) }()
	<-entered
	first := fail("runtime_stopped")
	go func() { p.reject(first); close(rejected) }()
	close(resume)
	if err := <-published; err != nil {
		t.Fatal(err)
	}
	<-rejected
	p.reject(fail("later_probe_error"))
	if p.failure() != first || p.publish(temporary) != first {
		t.Fatal("fatal status was replaced or republished")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fatal measurement remains: %v", err)
	}
	select {
	case <-p.failed:
	default:
		t.Fatal("fatal notification missing")
	}
}

func TestRevokedSuccessfulPublicationDoesNotExcuseRealProbeFailure(t *testing.T) {
	p := newQualificationPublication(filepath.Join(t.TempDir(), "measurement"))
	if err := p.revoke(); err != nil || !p.acceptProbeResult(errQualificationRevoked) {
		t.Fatal("successful final publication sentinel rejected")
	}
	readFailure := fail("qualification_cleanup")
	if p.acceptProbeResult(readFailure) || p.failure() != readFailure {
		t.Fatal("real post-revoke failure was suppressed")
	}
	if p.acceptProbeResult(errQualificationRevoked) || p.acceptProbeResult(nil) {
		t.Fatal("fatal state recovered after another successful probe")
	}
	unrevoked := newQualificationPublication(filepath.Join(t.TempDir(), "unrevoked"))
	if unrevoked.acceptProbeResult(errQualificationRevoked) || unrevoked.failure() == nil {
		t.Fatal("sentinel accepted without terminal revocation")
	}
}

func TestPublicationRemovalFailureIsFatal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "measurement")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "unexpected"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	p := newQualificationPublication(path)
	if p.revoke() == nil || p.admitProbe() || p.acceptProbeResult(errQualificationRevoked) {
		t.Fatal("failed withdrawal reported success")
	}
}
