package main

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/persistence/migrate"
	persistence "github.com/STAR-Ability/code-startrack-judge/internal/persistence/problems"
	"github.com/STAR-Ability/code-startrack-judge/internal/problems"
	"github.com/STAR-Ability/code-startrack-judge/internal/testutil/postgres"
	"github.com/jackc/pgx/v5"
)

// This is the real offline approval path with a dedicated, narrowly granted
// identity. It does not grant the application's identity approval authority.
func acceptanceApproveLicense(t *testing.T, f *acceptanceFixture, approval problems.LicenseApproval) contract.UUID {
	t.Helper()
	release := postgres.ReserveLicenseReviewer(t)
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	operator, err := f.db.Admin.Conn(ctx)
	if err != nil {
		t.Fatal("cannot reserve acceptance reviewer provisioning connection")
	}
	defer operator.Close()
	settings := []string{
		"log_statement='none'", "log_min_error_statement='panic'",
		"log_min_duration_statement=-1", "log_min_duration_sample=-1",
		"log_duration=off", "log_parameter_max_length=0",
		"log_parameter_max_length_on_error=0", "log_transaction_sample_rate=0",
		"log_error_verbosity='terse'", "log_min_messages='panic'",
	}
	for _, setting := range settings {
		if _, err := operator.ExecContext(ctx, "SET "+setting); err != nil {
			t.Fatal("cannot suppress acceptance reviewer SQL diagnostics")
		}
	}
	for name, value := range map[string]string{"pgaudit.log": "none", "pgaudit.role": ""} {
		var exists bool
		if operator.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_settings WHERE name=$1)`, name).Scan(&exists) != nil {
			t.Fatal("cannot inspect acceptance reviewer audit policy")
		}
		if exists {
			if _, err := operator.ExecContext(ctx, `SELECT set_config($1,$2,false)`, name, value); err != nil {
				t.Fatal("cannot suppress acceptance reviewer audit diagnostics")
			}
			settings = append(settings, name+"='"+value+"'")
		}
	}
	var exists bool
	if operator.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='judge_license_reviewer')`).Scan(&exists) != nil {
		t.Fatal("cannot inspect dedicated acceptance reviewer identity")
	}
	if exists {
		t.Fatal("dedicated reviewer identity belongs to another qualification")
	}
	password := strings.ReplaceAll(string(acceptanceUUID(t)), "-", "")
	if _, err := operator.ExecContext(ctx, `CREATE ROLE judge_license_reviewer LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD '`+password+`'`); err != nil {
		t.Fatal("cannot create dedicated acceptance reviewer identity")
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := operator.ExecContext(cleanup, `DROP OWNED BY judge_license_reviewer;DROP ROLE judge_license_reviewer`); err != nil {
			t.Error("cannot remove dedicated acceptance reviewer identity")
		}
	}()
	var database string
	if operator.QueryRowContext(ctx, `SELECT current_database()`).Scan(&database) != nil {
		t.Fatal("cannot inspect acceptance database identity")
	}
	quotedDatabase := pgx.Identifier{database}.Sanitize()
	for _, statement := range []string{
		"GRANT CONNECT ON DATABASE " + quotedDatabase + " TO judge_license_reviewer",
		"GRANT USAGE ON SCHEMA judge TO judge_license_reviewer",
		"GRANT SELECT ON judge.license_evidence,judge.rejected_package_evidence,judge.private_objects TO judge_license_reviewer",
		"GRANT INSERT ON judge.license_evidence TO judge_license_reviewer",
		"GRANT EXECUTE ON FUNCTION judge.valid_package_path(text) TO judge_license_reviewer",
	} {
		if _, err := operator.ExecContext(ctx, statement); err != nil {
			t.Fatal("cannot grant narrow acceptance reviewer authority")
		}
	}
	settings = append(settings, "search_path=pg_catalog,judge")
	for _, setting := range settings {
		if _, err := operator.ExecContext(ctx, "ALTER ROLE judge_license_reviewer IN DATABASE "+quotedDatabase+" SET "+setting); err != nil {
			t.Fatal("cannot establish private acceptance reviewer session policy")
		}
	}
	connection, err := url.Parse(f.db.MigrationURL)
	if err != nil {
		t.Fatal("invalid private acceptance reviewer connection")
	}
	connection.User = url.UserPassword("judge_license_reviewer", password)
	reviewer, err := migrate.Open(ctx, connection.String())
	if err != nil {
		t.Fatal("cannot connect dedicated acceptance reviewer")
	}
	defer reviewer.Close()
	id, err := problems.ApproveLicense(ctx, persistence.New(reviewer, nil), f.store, "ADMIN:acceptance", approval)
	if err != nil || id != approval.EvidenceID {
		t.Fatal("real offline acceptance license approval failed")
	}
	return id
}
