package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
)

// FileLedger durably refuses a second dispatch under a fencing token even after
// the judger process restarts. It contains identities only, never source/tests.
// Its private persistent directory is provisioned by the supervisor and must
// survive component restarts. Removing reservations requires reviewed retention
// after the owning task can no longer have a live lease.
type FileLedger struct{ directory string }

func NewFileLedger(directory string) (*FileLedger, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, failure("DISPATCH_LEDGER_INVALID", false)
	}
	for p := directory; ; p = filepath.Dir(p) {
		info, e := os.Lstat(p)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, failure("DISPATCH_LEDGER_INVALID", false)
		}
		if p == directory && info.Mode().Perm() != 0700 {
			return nil, failure("DISPATCH_LEDGER_INVALID", false)
		}
		if p == directory {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != uint32(os.Geteuid()) {
				return nil, failure("DISPATCH_LEDGER_INVALID", false)
			}
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	return &FileLedger{directory: directory}, nil
}
func (l *FileLedger) Begin(ctx context.Context, taskID, token contract.UUID) error {
	return l.begin(ctx, taskID, token, "judge")
}
func (l *FileLedger) BeginStep(ctx context.Context, taskID, token contract.UUID, step string) error {
	namespace, item, ok := strings.Cut(step, ":")
	if !ok || (namespace != "exact-programs" && namespace != "problemtools") || contract.UUID(item).Validate() != nil {
		return failure("DISPATCH_LEDGER_INVALID", false)
	}
	return l.begin(ctx, taskID, token, namespace+"-"+item)
}
func (l *FileLedger) begin(ctx context.Context, taskID, token contract.UUID, step string) error {
	if ctx == nil || ctx.Err() != nil || taskID.Validate() != nil || token.Validate() != nil {
		return failure("DISPATCH_LEDGER_INVALID", false)
	}
	// UUIDs have no path metacharacters; O_EXCL refuses links and duplicate fences.
	ownerName := filepath.Join(l.directory, string(token)+".owner")
	owner, e := os.OpenFile(ownerName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(e, os.ErrExist) {
		data, e := os.ReadFile(ownerName)
		if e != nil || string(data) != string(taskID)+"\n" {
			return failure("DISPATCH_LEDGER_INVALID", false)
		}
	} else if e != nil {
		return failure("DISPATCH_LEDGER_FAILED", false)
	} else {
		if _, e = owner.WriteString(string(taskID) + "\n"); e != nil {
			owner.Close()
			return failure("DISPATCH_LEDGER_FAILED", false)
		}
		e = owner.Sync()
		closeErr := owner.Close()
		if e != nil || closeErr != nil {
			return failure("DISPATCH_LEDGER_FAILED", false)
		}
	}
	name := filepath.Join(l.directory, string(token)+"-"+step+".dispatch")
	f, e := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return failure("ATTEMPT_ALREADY_DISPATCHED", false)
	}
	defer f.Close()
	if _, e = f.WriteString(string(taskID) + "\n"); e != nil {
		return failure("DISPATCH_LEDGER_FAILED", false)
	}
	if e = f.Sync(); e != nil {
		return failure("DISPATCH_LEDGER_FAILED", false)
	}
	dir, e := os.Open(l.directory)
	if e != nil {
		return failure("DISPATCH_LEDGER_FAILED", false)
	}
	defer dir.Close()
	if e = dir.Sync(); e != nil {
		return failure("DISPATCH_LEDGER_FAILED", false)
	}
	return nil
}
