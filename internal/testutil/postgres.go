package testutil

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// migrationsDir locates ./migrations relative to this source file rather
// than the test's working directory (which is always the package under
// test, not the repo root).
func migrationsDir() string {
	_, thisFile, _, _ := runtime.Caller(0)
	// internal/testutil/postgres.go -> repo root is two levels up.
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "migrations")
}

// dsn returns the Postgres connection string to test against: TEST_POSTGRES_DSN
// if set, else POSTGRES_DSN, else the same local default used by config.Load.
func dsn() string {
	if v := os.Getenv("TEST_POSTGRES_DSN"); v != "" {
		return v
	}
	if v := os.Getenv("POSTGRES_DSN"); v != "" {
		return v
	}
	return "postgres://postgres:postgres@localhost:5432/auth2fa?sslmode=disable"
}

// migrationLockID is an arbitrary fixed key for pg_advisory_lock, used to
// serialize migration application across concurrent test binaries — `go
// test` runs different packages as separate processes in parallel by
// default, and 0004's DDL (ALTER TABLE / DROP CONSTRAINT / CREATE INDEX)
// deadlocks if two of them race to apply it against the same database at
// once.
const migrationLockID = 851972640

// PostgresPool connects to a local Postgres (see dsn) and applies every
// migration, exactly like cmd/migrate does. If no Postgres is reachable, the
// test is skipped rather than failed — DB-backed tests are opt-in for
// whoever has Postgres running locally.
func PostgresPool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn())
	if err != nil {
		t.Skipf("skipping: could not create postgres pool: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("skipping: no postgres reachable at %s (set TEST_POSTGRES_DSN to point elsewhere): %v", dsn(), err)
	}
	t.Cleanup(pool.Close)

	applyMigrations(t, pool)

	return pool
}

// applyMigrations runs every ./migrations/*.sql file against pool, exactly
// like cmd/migrate does. Serialized across concurrent test binaries via a
// Postgres advisory lock (see migrationLockID) — its own longer-lived
// context, independent of the connectivity check above, since it may have
// to wait behind another process's migration run.
func applyMigrations(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquiring connection for migrations: %v", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLockID); err != nil {
		t.Fatalf("acquiring migration advisory lock: %v", err)
	}
	defer conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", migrationLockID)

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
		if _, err := conn.Exec(ctx, string(sqlBytes)); err != nil {
			t.Fatalf("applying migration %s: %v", f, err)
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
