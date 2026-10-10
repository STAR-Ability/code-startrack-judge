// Package migrate applies only the forward SQL shipped with a service release.
// The pinned golang-migrate engine owns execution, locking and dirty tracking.
// Each atomic SQL file and its checksum ledger row commit in one transaction.
package migrate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strconv"
	"strings"
	"testing/fstest"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/config"
	native "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	pgxdriver "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

var filename = regexp.MustCompile(`^([0-9]{6})_[a-z][a-z0-9_]*\.up\.sql$`)

// Migration is a reviewed, release-owned SQL file. Load derives its checksum.
type Migration struct {
	Version int
	Name    string
	SHA256  string
	SQL     string
}

// Status describes database history separately from available release files.
// Dirty is the native runner's durable in-progress/failure state. Inspect fails
// closed on dirty, unknown versions, or corrupt/missing checksum history.
type Status struct {
	Initialized bool `json:"initialized"`
	Applied     int  `json:"applied"`
	Available   int  `json:"available"`
	Dirty       bool `json:"dirty"`
}

// DatabaseError exposes a bounded operation and SQLSTATE, never driver text,
// connection credentials, SQL text, object data, or server diagnostics.
type DatabaseError struct {
	Operation string
	SQLState  string
}

func (e *DatabaseError) Error() string {
	if e.SQLState != "" {
		return fmt.Sprintf("migration database operation %s failed (SQLSTATE %s)", e.Operation, e.SQLState)
	}
	return "migration database operation " + e.Operation + " failed"
}

func dbError(operation string, err error) error {
	var state interface{ SQLState() string }
	code := ""
	if errors.As(err, &state) {
		code = state.SQLState()
	}
	return &DatabaseError{Operation: operation, SQLState: code}
}

// Open creates a dedicated native-driver pool. Server-side lock timeouts bound
// both golang-migrate's initial tracking-table lock and later migration locks;
// its driver's background contexts otherwise wait without a bound.
func Open(ctx context.Context, dsn string) (*sql.DB, error) {
	if err := config.ValidateDatabaseURL(dsn); err != nil {
		return nil, err
	}
	connection, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, dbError("parse connection configuration", err)
	}
	connection.RuntimeParams["lock_timeout"] = "15s"
	connection.RuntimeParams["statement_timeout"] = "5min"
	connection.RuntimeParams["timezone"] = "UTC"
	db := stdlib.OpenDB(*connection)
	// Native driver reserves one connection; checksum verification uses another.
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(2)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, dbError("connect", err)
	}
	return db, nil
}

// Load accepts the root of the embedded migration directory. Arbitrary callers
// cannot supply SQL to the CLI; its filesystem is embedded at build time.
func Load(source fs.FS) ([]Migration, error) {
	entries, err := fs.ReadDir(source, ".")
	if err != nil {
		return nil, errors.New("cannot read shipped migration files")
	}
	var migrations []Migration
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		match := filename.FindStringSubmatch(name)
		if entry.IsDir() || entry.Type()&fs.ModeSymlink != 0 || match == nil {
			return nil, fmt.Errorf("invalid migration identity: %s", name)
		}
		version, _ := strconv.Atoi(match[1])
		if version != len(migrations)+1 {
			return nil, errors.New("migration identities must be unique, contiguous, and start at 000001")
		}
		body, err := fs.ReadFile(source, name)
		if err != nil || len(strings.TrimSpace(string(body))) == 0 {
			return nil, fmt.Errorf("cannot read nonempty shipped migration: %s", name)
		}
		text := strings.TrimSpace(string(body))
		if !strings.HasPrefix(text, "--") && !strings.HasPrefix(text, "BEGIN;") {
			return nil, fmt.Errorf("migration must begin with reviewed comments or BEGIN: %s", name)
		}
		if !strings.HasSuffix(text, "COMMIT;") || !strings.Contains(text, "BEGIN;") {
			return nil, fmt.Errorf("migration must have an explicit BEGIN/COMMIT transaction: %s", name)
		}
		hash := sha256.Sum256(body)
		migrations = append(migrations, Migration{Version: version, Name: name, SHA256: hex.EncodeToString(hash[:]), SQL: string(body)})
	}
	return migrations, nil
}

// Inspect never initializes schema or tracking objects and requires SELECT only.
func Inspect(ctx context.Context, db *sql.DB, migrations []Migration) (Status, error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return Status{}, dbError("begin status", err)
	}
	defer tx.Rollback()
	status, err := inspect(ctx, tx, migrations)
	if err != nil {
		return Status{}, err
	}
	if err := tx.Commit(); err != nil {
		return Status{}, dbError("commit status", err)
	}
	return status, nil
}

func inspect(ctx context.Context, tx *sql.Tx, migrations []Migration) (Status, error) {
	status := Status{Available: len(migrations)}
	if err := tx.QueryRowContext(ctx, "SELECT to_regclass('judge.schema_migrations') IS NOT NULL").Scan(&status.Initialized); err != nil {
		return status, dbError("inspect ledger", err)
	}
	if !status.Initialized {
		var checksumExists bool
		if err := tx.QueryRowContext(ctx, "SELECT to_regclass('judge.migration_checksums') IS NOT NULL").Scan(&checksumExists); err != nil {
			return status, dbError("inspect retained checksums", err)
		}
		if checksumExists {
			return status, errors.New("immutable checksum history exists without native migration tracking")
		}
		return status, nil
	}
	var nativeRows int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM judge.schema_migrations").Scan(&nativeRows); err != nil {
		return status, dbError("count native version rows", err)
	}
	if nativeRows > 1 {
		return status, errors.New("native migration tracking contains multiple current versions")
	}
	var version int
	err := tx.QueryRowContext(ctx, "SELECT version, dirty FROM judge.schema_migrations").Scan(&version, &status.Dirty)
	if err == sql.ErrNoRows {
		version = 0
	} else if err != nil {
		return status, dbError("read native version", err)
	}
	if status.Dirty {
		return status, fmt.Errorf("database migration version %06d is dirty; manual reviewed recovery required", version)
	}
	if version < 0 || version > len(migrations) || (nativeRows == 1 && version == 0) {
		return status, errors.New("database migration version is outside this release")
	}
	var ledgerExists bool
	if err := tx.QueryRowContext(ctx, "SELECT to_regclass('judge.migration_checksums') IS NOT NULL").Scan(&ledgerExists); err != nil {
		return status, dbError("inspect checksums", err)
	}
	if !ledgerExists {
		if version != 0 {
			return status, errors.New("applied migration history has no immutable checksum ledger")
		}
		return status, nil
	}
	rows, err := tx.QueryContext(ctx, "SELECT version, name, sha256 FROM judge.migration_checksums ORDER BY version")
	if err != nil {
		return status, dbError("read ledger", err)
	}
	defer rows.Close()
	for rows.Next() {
		var version int
		var name, checksum string
		if err := rows.Scan(&version, &name, &checksum); err != nil {
			return status, dbError("decode ledger", err)
		}
		if version != status.Applied+1 || version > len(migrations) {
			return status, errors.New("database migration history is missing, noncontiguous, or newer than this release")
		}
		file := migrations[version-1]
		if file.Version != version || file.Name != name || file.SHA256 != checksum {
			return status, fmt.Errorf("immutable migration history differs at version %06d", version)
		}
		status.Applied = version
	}
	if err := rows.Err(); err != nil {
		return status, dbError("read ledger", err)
	}
	if status.Applied != version {
		return status, errors.New("native migration version differs from immutable checksum history")
	}
	return status, nil
}

// Apply locks, verifies all retained history, then applies through ceiling. Zero
// means this release's highest migration. The migration role must own judge and
// cannot have superuser, CREATE ROLE, or CREATE DATABASE privileges. The supplied
// DB must be dedicated to this command: upstream closes it when releasing its
// reserved connection. Inspect accepts an ordinary shared read connection.
func Apply(ctx context.Context, db *sql.DB, migrations []Migration, ceiling int) (Status, error) {
	if ceiling == 0 {
		ceiling = len(migrations)
	}
	if ceiling < 0 || ceiling > len(migrations) {
		return Status{}, errors.New("migration ceiling is outside this release")
	}
	var allowed bool
	if err := db.QueryRowContext(ctx, `SELECT NOT r.rolsuper AND NOT r.rolcreatedb AND NOT r.rolcreaterole AND n.nspowner = r.oid
		FROM pg_roles r JOIN pg_namespace n ON n.nspname = 'judge' WHERE r.rolname = current_user`).Scan(&allowed); err != nil {
		return Status{}, dbError("verify migration identity", err)
	}
	if !allowed {
		return Status{}, errors.New("migration identity must own judge and lack administrative privileges")
	}
	driver, err := pgxdriver.WithInstance(db, &pgxdriver.Config{SchemaName: "judge", MigrationsTable: "schema_migrations", StatementTimeout: 5 * time.Minute})
	if err != nil {
		return Status{}, dbError("initialize native runner", err)
	}
	defer driver.Close()
	wrapped := &checksumDriver{Driver: driver, ctx: ctx, db: db, migrations: migrations, ceiling: ceiling}
	files := fstest.MapFS{}
	for _, file := range migrations {
		body := strings.TrimSpace(file.SQL)
		// Filename and hash contain only loader-validated ASCII, so these SQL
		// literals cannot introduce caller SQL. This insert joins the file's own
		// transaction; a crash never commits schema without its original hash.
		ledger := fmt.Sprintf("INSERT INTO judge.migration_checksums (version,name,sha256) VALUES (%d,'%s','%s');\n", file.Version, file.Name, file.SHA256)
		body = strings.TrimSuffix(body, "COMMIT;") + ledger + "COMMIT;\n"
		files[file.Name] = &fstest.MapFile{Data: []byte(body)}
	}
	source, err := iofs.New(files, ".")
	if err != nil {
		return Status{}, errors.New("cannot initialize shipped migration source")
	}
	defer source.Close()
	runner, err := native.NewWithInstance("shipped", source, "pgx5", wrapped)
	if err != nil {
		return Status{}, dbError("initialize native engine", err)
	}
	runner.LockTimeout = 15 * time.Second
	err = runner.Migrate(uint(ceiling))
	if err != nil && !errors.Is(err, native.ErrNoChange) {
		return Status{}, dbError("apply forward migrations", err)
	}
	return Inspect(ctx, db, migrations)
}

// Lock verifies checksums while holding the native driver's existing lock. It
// never reacquires that advisory lock on a second connection (which deadlocks).
type checksumDriver struct {
	database.Driver
	ctx        context.Context
	db         *sql.DB
	migrations []Migration
	ceiling    int
	current    int
}

func (d *checksumDriver) Lock() error {
	if err := d.Driver.Lock(); err != nil {
		return err
	}
	status, err := Inspect(d.ctx, d.db, d.migrations)
	if err == nil && d.ceiling < status.Applied {
		err = errors.New("forward-only runner cannot lower the applied migration level")
	}
	if err == nil {
		d.current = status.Applied
		_, err = d.db.ExecContext(d.ctx, `CREATE TABLE IF NOT EXISTS judge.migration_checksums (
			version integer PRIMARY KEY CHECK (version > 0),
			name text NOT NULL UNIQUE CHECK (name ~ '^[0-9]{6}_[a-z][a-z0-9_]*[.]up[.]sql$'),
			sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
			applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
		)`)
	}
	if err != nil {
		_ = d.Driver.Unlock()
		return err
	}
	return nil
}

func (d *checksumDriver) SetVersion(version int, dirty bool) error {
	if version != d.current+1 || version > d.ceiling {
		return errors.New("native engine attempted a non-forward version change")
	}
	if err := d.Driver.SetVersion(version, dirty); err != nil {
		return err
	}
	if !dirty {
		d.current = version
	}
	return nil
}
