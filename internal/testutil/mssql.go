package testutil

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
	"time"

	mssql "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/msdsn"

	"auth-2fa-api/internal/db"
)

// migrationsDir locates ./migrations relative to this source file rather
// than the test's working directory (which is always the package under
// test, not the repo root).
func migrationsDir() string {
	_, thisFile, _, _ := runtime.Caller(0)
	// internal/testutil/mssql.go -> repo root is two levels up.
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "migrations")
}

// dsn returns the SQL Server connection string to test against:
// TEST_MSSQL_DSN if set, else MSSQL_DSN, else the same local default used
// by config.Load.
func dsn() string {
	if v := os.Getenv("TEST_MSSQL_DSN"); v != "" {
		return v
	}
	if v := os.Getenv("MSSQL_DSN"); v != "" {
		return v
	}
	return "sqlserver://sa:@localhost:1433?database=auth2fa"
}

// migrationLockResource is an arbitrary fixed name for sp_getapplock, used
// to serialize migration application across concurrent test binaries — `go
// test` runs different packages as separate processes in parallel by
// default, and some migrations' DDL (ALTER TABLE / CREATE INDEX) deadlocks
// or errors if two of them race to apply it against the same database at
// once.
const migrationLockResource = "auth-2fa-api-migrations"

// MSSQLPool connects to a local SQL Server (see dsn) and applies every
// migration, exactly like cmd/migrate does. If no SQL Server is reachable,
// the test is skipped rather than failed — DB-backed tests are opt-in for
// whoever has SQL Server running locally.
func MSSQLPool(t *testing.T) *sql.DB {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// ProcessQueryText, not a plain sql.Open("sqlserver", ...): the bare
	// "sqlserver" driver name leaves "?" untranslated, and every repository
	// in this project writes queries with "?" — see db.NewMSSQL's doc
	// comment, this mirrors it exactly.
	params, err := msdsn.Parse(dsn())
	if err != nil {
		t.Skipf("skipping: could not parse mssql dsn: %v", err)
	}
	sqlDB := sql.OpenDB(mssql.NewConnectorWithProcessQueryText(params))
	if err := sqlDB.PingContext(ctx); err != nil {
		sqlDB.Close()
		t.Skipf("skipping: no mssql reachable at %s (set TEST_MSSQL_DSN to point elsewhere): %v", dsn(), err)
	}
	t.Cleanup(func() { sqlDB.Close() })

	applyMigrations(t, sqlDB)

	return sqlDB
}

// applyMigrations runs every ./migrations/*.sql file against sqlDB, exactly
// like cmd/migrate does. Serialized across concurrent test binaries via
// sp_getapplock (see migrationLockResource) — its own longer-lived context,
// independent of the connectivity check above, since it may have to wait
// behind another process's migration run.
func applyMigrations(t *testing.T, sqlDB *sql.DB) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		t.Fatalf("acquiring connection for migrations: %v", err)
	}
	defer conn.Close()

	// @LockOwner = 'Session' (not the default 'Transaction') — this
	// connection never opens an explicit transaction, and 'Transaction'
	// mode requires one to already be active.
	if _, err := conn.ExecContext(ctx, "EXEC sp_getapplock @Resource = ?, @LockMode = 'Exclusive', @LockOwner = 'Session', @LockTimeout = 30000", migrationLockResource); err != nil {
		t.Fatalf("acquiring migration applock: %v", err)
	}
	defer conn.ExecContext(context.Background(), "EXEC sp_releaseapplock @Resource = ?, @LockOwner = 'Session'", migrationLockResource)

	files, err := filepath.Glob(filepath.Join(migrationsDir(), "*.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("listing migrations: %v (found %d files)", err, len(files))
	}
	sort.Strings(files)
	for _, f := range files {
		sqlBytes, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("reading migration %s: %v", f, err)
		}
		for i, batch := range db.SplitBatches(string(sqlBytes)) {
			if _, err := conn.ExecContext(ctx, batch); err != nil {
				t.Fatalf("applying migration %s (batch %d): %v", f, i+1, err)
			}
		}
	}
}

// UniqueSuffix returns a short random hex string so tests can build
// collision-free emails/names/device ids without stepping on each other or
// on leftover data from previous runs.
func UniqueSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("generating unique suffix: %v", err)
	}
	return hex.EncodeToString(b)
}
