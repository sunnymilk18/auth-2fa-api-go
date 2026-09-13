package db

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// NewRedis opens a client from a connection URL and verifies connectivity,
// retrying with backoff for up to 30s — a cold-started free-tier instance
// (Upstash and similar suspend after being idle) can take a few seconds to
// answer the very first connection after a while.
// Supports both redis:// (plain) and rediss:// (TLS) schemes — the latter
// is what hosted providers like Upstash require.
func NewRedis(ctx context.Context, redisURL string) (*redis.Client, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parsing redis url: %w", err)
	}

	client := redis.NewClient(opts)

	err = retryConnect(ctx, "redis", 30*time.Second, func(ctx context.Context) error {
		pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return client.Ping(pingCtx).Err()
	})
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("pinging redis: %w", err)
	}

	return client, nil
}
