package postgres

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/persistence/migrate"
)

// ReserveLicenseReviewer serializes tests using the fixed offline reviewer
// identity. Advisory locks are database-scoped, so reserve it on the shared
// operator database rather than each test's disposable database.
func ReserveLicenseReviewer(t *testing.T) func() {
	t.Helper()
	dsn := os.Getenv("JUDGE_TEST_ADMIN_DATABASE_URL")
	if filename := os.Getenv("JUDGE_TEST_ADMIN_DSN_FILE"); filename != "" {
		raw, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal("cannot read private reviewer test connection")
		}
		dsn = strings.TrimSpace(string(raw))
	}
	if dsn == "" {
		t.Skip("actual PostgreSQL reviewer tests require a private administrator connection")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	db, err := migrate.Open(ctx, dsn)
	if err != nil {
		t.Fatal("cannot connect to reviewer reservation database")
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		db.Close()
		t.Fatal("cannot reserve reviewer test connection")
	}
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock(721035083)`); err != nil {
		conn.Close()
		db.Close()
		t.Fatal("cannot reserve dedicated reviewer test identity")
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			_, _ = conn.ExecContext(cleanup, `SELECT pg_advisory_unlock(721035083)`)
			conn.Close()
			db.Close()
		})
	}
	t.Cleanup(release)
	return release
}
