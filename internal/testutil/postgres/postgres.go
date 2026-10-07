// Package postgres creates isolated disposable databases for repository tests.
// It never resets the supplied administrator database or prints credentials.
package postgres

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/STAR-Ability/code-startrack-judge/internal/persistence/migrate"
	"github.com/STAR-Ability/code-startrack-judge/migrations"
	"github.com/jackc/pgx/v5"
)

type Database struct {
	Admin        *sql.DB
	Runtime      *sql.DB
	MigrationURL string
	RuntimeURL   string
}

func New(t *testing.T) Database {
	t.Helper()
	dsn := os.Getenv("JUDGE_TEST_ADMIN_DATABASE_URL")
	if path := os.Getenv("JUDGE_TEST_ADMIN_DSN_FILE"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("cannot read private test connection")
		}
		dsn = strings.TrimSpace(string(b))
	}
	if dsn == "" {
		t.Skip("actual PostgreSQL tests require a private administrator connection")
	}
	ctx := context.Background()
	admin, err := migrate.Open(ctx, dsn)
	if err != nil {
		t.Fatal("cannot connect to test PostgreSQL")
	}
	admin.SetMaxOpenConns(1)
	// Role passwords are synthetic; turn off all statement/parameter logging
	// before generating SQL containing them, including error-statement logging.
	if _, err := admin.ExecContext(ctx, `SET log_statement='none';SET log_min_error_statement='panic';SET log_min_duration_statement=-1;SET log_parameter_max_length=0;SET log_parameter_max_length_on_error=0`); err != nil {
		admin.Close()
		t.Fatal("cannot suppress test credential statement logs")
	}
	var entropy [24]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		admin.Close()
		t.Fatal("test identity unavailable")
	}
	suffix := hex.EncodeToString(entropy[:8])
	name, owner, runtime := "judge_repo_"+suffix, "judge_owner_"+suffix, "judge_app_"+suffix
	password := hex.EncodeToString(entropy[8:]) + hex.EncodeToString(entropy[:8])
	isolated := (*sql.DB)(nil)
	app := (*sql.DB)(nil)
	t.Cleanup(func() {
		if app != nil {
			app.Close()
		}
		if isolated != nil {
			isolated.Close()
		}
		_, _ = admin.ExecContext(context.Background(), "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
		_, _ = admin.ExecContext(context.Background(), "DROP ROLE "+pgx.Identifier{runtime}.Sanitize())
		_, _ = admin.ExecContext(context.Background(), "DROP ROLE "+pgx.Identifier{owner}.Sanitize())
		admin.Close()
	})
	for _, role := range []string{owner, runtime} {
		if _, err := admin.ExecContext(ctx, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD '"+password+"'"); err != nil {
			t.Fatal("cannot create isolated test role")
		}
	}
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal("cannot create isolated test database")
	}
	connection, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("invalid private administrator connection")
	}
	connection.Path = "/" + name
	isolated, err = migrate.Open(ctx, connection.String())
	if err != nil {
		t.Fatal("cannot open isolated test database")
	}
	for _, statement := range []string{
		"REVOKE ALL ON DATABASE " + pgx.Identifier{name}.Sanitize() + " FROM PUBLIC",
		"GRANT CONNECT ON DATABASE " + pgx.Identifier{name}.Sanitize() + " TO " + pgx.Identifier{owner}.Sanitize() + "," + pgx.Identifier{runtime}.Sanitize(),
		"REVOKE ALL ON SCHEMA public FROM PUBLIC",
		"CREATE SCHEMA judge AUTHORIZATION " + pgx.Identifier{owner}.Sanitize(),
		"REVOKE ALL ON SCHEMA judge FROM PUBLIC",
	} {
		if _, err := isolated.ExecContext(ctx, statement); err != nil {
			t.Fatal("cannot establish isolated schema boundary")
		}
	}
	connection.User = url.UserPassword(owner, password)
	ownerURL := connection.String()
	migrationDB, err := migrate.Open(ctx, ownerURL)
	if err != nil {
		t.Fatal("cannot open isolated migration identity")
	}
	files, err := migrate.Load(migrations.Files)
	if err != nil {
		migrationDB.Close()
		t.Fatal("shipped migration chain invalid")
	}
	_, err = migrate.Apply(ctx, migrationDB, files, 0)
	migrationDB.Close()
	if err != nil {
		t.Fatal("cannot apply shipped migration chain")
	}
	quotedRole := pgx.Identifier{runtime}.Sanitize()
	for _, statement := range []string{
		"GRANT USAGE ON SCHEMA judge TO " + quotedRole,
		"GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA judge TO " + quotedRole,
		"REVOKE INSERT,UPDATE,DELETE ON judge.schema_migrations,judge.migration_checksums FROM " + quotedRole,
		"GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA judge TO " + quotedRole,
		"GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA judge TO " + quotedRole,
	} {
		if _, err := isolated.ExecContext(ctx, statement); err != nil {
			t.Fatal("cannot grant isolated repository-test role")
		}
	}
	// These generic repository test grants are not deployment ACL evidence;
	// provisioning tests exercise the exact production grant scripts separately.
	connection.User = url.UserPassword(runtime, password)
	app, err = migrate.Open(ctx, connection.String())
	if err != nil {
		t.Fatal("cannot open isolated application role")
	}
	return Database{Admin: isolated, Runtime: app, MigrationURL: ownerURL, RuntimeURL: connection.String()}
}
