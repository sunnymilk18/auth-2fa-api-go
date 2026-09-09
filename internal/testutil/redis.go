// Package testutil provides shared test helpers for spinning up the
// dependencies the rest of the app needs (Redis, Postgres) without requiring
// heavyweight infra like Docker.
package testutil

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// RedisClient starts an in-memory miniredis instance for the duration of the
// test and returns a real *redis.Client pointed at it. No external Redis
// (or Docker) needed — miniredis is a pure-Go dependency.
func RedisClient(t *testing.T) *redis.Client {
	t.Helper()

	client, _ := RedisClientAndServer(t)
	return client
}

// RedisClientAndServer is RedisClient plus the underlying *miniredis.Miniredis,
// needed when a test has to advance time past a TTL — miniredis tracks TTLs
// against a manual clock (see its FastForward), not the real wall clock, so
// time.Sleep alone won't expire anything.
func RedisClientAndServer(t *testing.T) (*redis.Client, *miniredis.Miniredis) {
	t.Helper()

	mr := miniredis.RunT(t) // RunT registers its own t.Cleanup to shut down
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return client, mr
}
