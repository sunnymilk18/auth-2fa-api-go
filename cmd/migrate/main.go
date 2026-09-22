// Command migrate applies every .sql file in ./migrations, in filename
// order, against MSSQL_DSN. Simple and idempotent as long as migration
// files themselves guard their own DDL (IF NOT EXISTS checks, MERGE) —
// there's no tracking table, this is meant for a small project, not a full
// migration framework.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"

	"auth-2fa-api/internal/config"
	"auth-2fa-api/internal/db"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("fatal: %v", err)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx := context.Background()
	sqlDB, err := db.NewMSSQL(ctx, cfg.MSSQLDSN)
	if err != nil {
		return err
	}
	defer sqlDB.Close()

	files, err := filepath.Glob("migrations/*.sql")
	if err != nil {
		return fmt.Errorf("listing migration files: %w", err)
	}
	sort.Strings(files)

	for _, f := range files {
		sqlBytes, err := os.ReadFile(f)
		if err != nil {
			return fmt.Errorf("reading %s: %w", f, err)
		}

		log.Printf("applying %s ...", f)
		if err := db.ApplyMigration(ctx, sqlDB, string(sqlBytes)); err != nil {
			return fmt.Errorf("applying %s: %w", f, err)
		}
	}

	log.Println("all migrations applied")
	return nil
}
