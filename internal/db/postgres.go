package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// NewPostgres opens a connection pool and verifies connectivity, retrying
// with backoff for up to 30s — a cold-started free-tier instance (Neon and
// similar suspend after being idle) can take a few seconds to answer the
// very first connection after a while.
func NewPostgres(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	poolCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(poolCtx, dsn)
	if err != nil {
		return nil, fmt.Errorf("creating postgres pool: %w", err)
	}

	err = retryConnect(ctx, "postgres", 30*time.Second, func(ctx context.Context) error {
		pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		return pool.Ping(pingCtx)
	})
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging postgres: %w", err)
	}

	return pool, nil
}
