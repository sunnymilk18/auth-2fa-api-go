package db

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"
)

// goBatchSeparator matches a line containing only "GO" (T-SQL/sqlcmd batch
// separator convention), optionally surrounded by whitespace. Not real
// T-SQL — SSMS/sqlcmd strip it client-side before sending each batch
// separately — so this project's migration files use it the same way and
// this package does the splitting itself before handing batches to the Go
// driver, which has no notion of "GO" either.
var goBatchSeparator = regexp.MustCompile(`(?im)^\s*GO\s*$`)

// SplitBatches splits a migration file's contents into individual batches
// on "GO" lines, dropping empty batches. Needed because SQL Server doesn't
// allow certain DDL sequences (e.g. ALTER TABLE ADD COLUMN followed by a
// statement that references the new column) inside a single batch — each
// migration file uses "GO" between statements that need to be visible to
// the next one.
func SplitBatches(script string) []string {
	parts := goBatchSeparator.Split(script, -1)
	batches := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.TrimSpace(p) == "" {
			continue
		}
		batches = append(batches, p)
	}
	return batches
}

// ApplyMigration executes every batch in a migration file's contents, in
// order, against db.
func ApplyMigration(ctx context.Context, sqlDB *sql.DB, script string) error {
	for i, batch := range SplitBatches(script) {
		if _, err := sqlDB.ExecContext(ctx, batch); err != nil {
			return fmt.Errorf("batch %d: %w", i+1, err)
		}
	}
	return nil
}
