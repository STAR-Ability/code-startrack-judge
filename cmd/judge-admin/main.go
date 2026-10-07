// judge-admin is a trusted offline operator tool, excluded from API/worker
// authorization. Root-owned configuration fixes the accountable ADMIN identity.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/persistence/migrate"
	persistence "github.com/STAR-Ability/code-startrack-judge/internal/persistence/problems"
	"github.com/STAR-Ability/code-startrack-judge/internal/problems"
	"github.com/STAR-Ability/code-startrack-judge/internal/processguard"
	"github.com/STAR-Ability/code-startrack-judge/internal/storage"
)

type operatorConfig struct {
	DatabaseURL        string `json:"databaseUrl"`
	PrivateStorageRoot string `json:"privateStorageRoot"`
	ReviewerID         string `json:"reviewerId"`
	Authority          string `json:"authority"`
}

var errAuthority = errors.New("license review requires root-owned ADMIN operator files and dedicated database authority")

func main() {
	if processguard.Harden() != nil {
		fmt.Fprintln(os.Stderr, "PROCESS_HARDENING_UNAVAILABLE")
		os.Exit(1)
	}
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 || args[0] != "license-review" {
		return errors.New("usage: judge-admin license-review -config ABSOLUTE_PATH -review ABSOLUTE_PATH")
	}
	if os.Geteuid() != 0 {
		return errAuthority
	}
	flags := flag.NewFlagSet("judge-admin license-review", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "root-owned operator configuration")
	reviewPath := flags.String("review", "", "root-owned approval receipt")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *configPath == "" || *reviewPath == "" {
		return errors.New("invalid license review command flags")
	}
	configRaw, err := readTrusted(*configPath, 65536, 0)
	if err != nil {
		return err
	}
	var config operatorConfig
	if strictDecode(configRaw, &config) != nil || config.Authority != "ADMIN" || config.ReviewerID == "" || config.PrivateStorageRoot == "" {
		return errAuthority
	}
	if err := trustedStoragePath(config.PrivateStorageRoot); err != nil {
		return err
	}
	if err := migrateConfig(config.DatabaseURL); err != nil {
		return err
	}
	reviewRaw, err := readTrusted(*reviewPath, 8<<20, 0)
	if err != nil {
		return err
	}
	var review problems.LicenseApproval
	if strictDecode(reviewRaw, &review) != nil {
		return errors.New("invalid private license review receipt")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	db, err := migrate.Open(ctx, config.DatabaseURL)
	if err != nil {
		return errors.New("license reviewer database connection failed")
	}
	defer db.Close()
	store, err := storage.New(config.PrivateStorageRoot)
	if err != nil {
		return errors.New("private license evidence storage unavailable")
	}
	defer store.Close()
	id, err := problems.ApproveLicense(ctx, persistence.New(db, nil), store, config.ReviewerID, review)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		EvidenceID string `json:"evidenceId"`
		Status     string `json:"status"`
	}{string(id), "VERIFIED"})
}

func strictDecode(raw []byte, out any) error {
	if err := canonical.ValidateJSON(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return errors.New("invalid private operator JSON")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("invalid private operator JSON")
	}
	return nil
}

// Every ancestor must be immutable to untrusted accounts. File-descriptor
// identity checks and O_NOFOLLOW close the final-component replacement gap.
func trustedPath(name string, owner uint32, directory bool) error {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return errAuthority
	}
	for current := name; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errAuthority
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != owner || info.Mode().Perm()&0022 != 0 {
			return errAuthority
		}
		if current == name {
			if directory {
				if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
					return errAuthority
				}
			} else if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
				return errAuthority
			}
		} else if !info.IsDir() {
			return errAuthority
		}
		if current == filepath.Dir(current) {
			break
		}
	}
	return nil
}
func readTrusted(name string, maxBytes int64, owner uint32) ([]byte, error) {
	if err := trustedPath(name, owner, false); err != nil {
		return nil, err
	}
	before, err := os.Lstat(name)
	if err != nil {
		return nil, errAuthority
	}
	file, err := os.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errAuthority
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || after.Size() > maxBytes {
		return nil, errAuthority
	}
	body, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil || int64(len(body)) > maxBytes {
		return nil, errAuthority
	}
	return body, nil
}

func trustedStoragePath(name string) error {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return errAuthority
	}
	info, err := os.Lstat(name)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return errAuthority
	}
	// The leaf belongs to the service's storage account. Its checksum-addressed
	// contents are verified; only root can redirect the configured parent path.
	for parent := filepath.Dir(name); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return errAuthority
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return errAuthority
		}
		if parent == filepath.Dir(parent) {
			break
		}
	}
	return nil
}
