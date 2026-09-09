package db

import (
	"context"
	"fmt"
	"log"
	"time"
)

// retryConnect calls fn repeatedly with exponential backoff (starting at
// 1s, doubling, capped at 5s between attempts) until it succeeds or maxWait
// elapses. Smooths over a slow-to-wake dependency — e.g. a Neon Postgres or
// Upstash Redis free-tier instance that suspends itself after being idle
// and takes a few seconds to wake back up on the next connection — instead
// of failing the whole service on one unlucky ping at startup.
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
