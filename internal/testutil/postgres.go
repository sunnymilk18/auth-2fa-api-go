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
		if _, err := pool.Exec(ctx, string(sqlBytes)); err != nil {
			t.Fatalf("applying migration %s: %v", f, err)
		}
	}

	return pool
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
