package db

import (
	"context"
	"fmt"
	"log"
	"time"
)

// retryConnect calls fn repeatedly with exponential backoff (starting at
// 1s, doubling, capped at 5s between attempts) until it succeeds or maxWait
// elapses. Smooths over a slow-to-start dependency — e.g. Postgres or Redis
// still coming up in the same docker-compose stack (migrate/api can start
// racing them) — instead of failing the whole service on one unlucky ping
// at startup.
func retryConnect(ctx context.Context, name string, maxWait time.Duration, fn func(ctx context.Context) error) error {
	deadline := time.Now().Add(maxWait)
	backoff := time.Second
	const maxBackoff = 5 * time.Second

	for attempt := 1; ; attempt++ {
		err := fn(ctx)
		if err == nil {
			return nil
		}
		if !time.Now().Add(backoff).Before(deadline) {
			return fmt.Errorf("giving up connecting to %s after %d attempts: %w", name, attempt, err)
		}

		log.Printf("%s not reachable yet (attempt %d): %v — retrying in %s", name, attempt, err, backoff)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}

		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}
