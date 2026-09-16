package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

var ErrTooManyFailedLogins = errors.New("too many failed login attempts, try again later")

// LoginAttemptLimiter tracks failed password attempts per (api client, key)
// in Redis — distinct from the per-IP rate limiter already on /auth/login
// (internal/middleware.RateLimiter): that one bounds total request volume
// from one IP, which doesn't catch someone spreading password guesses
// against a single account across many different IPs.
//
// key is normally the resolved account's user id — see
// auth.Service.LoginStep1, which is the only real caller — falling back
// to the raw login identifier (email/username/rut, whatever was typed)
// only when it doesn't resolve to any account.
//
// Deliberately a temporary throttle (same order of magnitude as the IP
// limiter's own window), not a hard/permanent lockout — an unconditional
// "N wrong passwords locks the account" is itself a denial-of-service tool:
// anyone who knows a victim's email could lock them out on purpose. This
// only slows a distributed guessing attempt down; it never fully closes
// the door on the legitimate owner.
type LoginAttemptLimiter struct {
	rdb      *redis.Client
	maxFails int64
	window   time.Duration
}

func NewLoginAttemptLimiter(rdb *redis.Client, maxFails int, window time.Duration) *LoginAttemptLimiter {
	return &LoginAttemptLimiter{rdb: rdb, maxFails: int64(maxFails), window: window}
}

// IsLocked reports whether apiClientID/lockoutKey currently has too many
// recorded failures to allow another attempt.
func (l *LoginAttemptLimiter) IsLocked(ctx context.Context, apiClientID, lockoutKey string) (bool, error) {
	count, err := l.rdb.Get(ctx, l.redisKey(apiClientID, lockoutKey)).Int64()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("checking login attempts: %w", err)
	}
	return count >= l.maxFails, nil
}

// RecordFailure increments the failure count, starting its TTL on the
// first failure of a new window.
func (l *LoginAttemptLimiter) RecordFailure(ctx context.Context, apiClientID, lockoutKey string) error {
	redisKey := l.redisKey(apiClientID, lockoutKey)
	count, err := l.rdb.Incr(ctx, redisKey).Result()
	if err != nil {
		return fmt.Errorf("recording login failure: %w", err)
	}
	if count == 1 {
		if err := l.rdb.Expire(ctx, redisKey, l.window).Err(); err != nil {
			return fmt.Errorf("setting login attempts ttl: %w", err)
		}
	}
	return nil
}

// Reset clears the failure count — called after a successful login so past
// failures don't linger against a legitimate user's next typo.
func (l *LoginAttemptLimiter) Reset(ctx context.Context, apiClientID, lockoutKey string) error {
	return l.rdb.Del(ctx, l.redisKey(apiClientID, lockoutKey)).Err()
}

func (l *LoginAttemptLimiter) redisKey(apiClientID, lockoutKey string) string {
	// Lowercased/trimmed same as any of the three identifier forms would
	// be before comparison — harmless no-op when lockoutKey is already a
	// user id (UUIDs are lowercase hex to begin with).
	return "login_attempts:" + apiClientID + ":" + strings.ToLower(strings.TrimSpace(lockoutKey))
}
