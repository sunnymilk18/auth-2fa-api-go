// Command migrate applies every .sql file in ./migrations, in filename
// order, against POSTGRES_DSN. Simple and idempotent as long as migration
// files themselves use IF NOT EXISTS / ON CONFLICT — there's no tracking
// table, this is meant for a small project, not a full migration framework.
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
	pool, err := db.NewPostgres(ctx, cfg.PostgresDSN)
	if err != nil {
		return err
	}
	defer pool.Close()

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
		if _, err := pool.Exec(ctx, string(sqlBytes)); err != nil {
			return fmt.Errorf("applying %s: %w", f, err)
		}
	}

	log.Println("all migrations applied")
	return nil
}
