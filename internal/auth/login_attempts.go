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

// LockedOutError wraps ErrTooManyFailedLogins with how long the account
// actually has left before RecordFailure's window expires — callers that
// only care whether it's ErrTooManyFailedLogins can keep using errors.Is
// (Unwrap makes that still match); callers that want to tell the user a
// real wait time use errors.As to get RetryAfter.
type LockedOutError struct {
	RetryAfter time.Duration
}

func (e *LockedOutError) Error() string { return ErrTooManyFailedLogins.Error() }
func (e *LockedOutError) Unwrap() error { return ErrTooManyFailedLogins }

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
// recorded failures to allow another attempt, and if so, how much longer
// the lockout actually has left (read from the key's real Redis TTL, not
// just the configured window — the window started on the first failure,
// which is usually already some minutes in the past by the time this is
// checked again).
func (l *LoginAttemptLimiter) IsLocked(ctx context.Context, apiClientID, lockoutKey string) (locked bool, retryAfter time.Duration, err error) {
	redisKey := l.redisKey(apiClientID, lockoutKey)

	count, err := l.rdb.Get(ctx, redisKey).Int64()
	if errors.Is(err, redis.Nil) {
		return false, 0, nil
	}
	if err != nil {
		return false, 0, fmt.Errorf("checking login attempts: %w", err)
	}
	if count < l.maxFails {
		return false, 0, nil
	}

	ttl, err := l.rdb.TTL(ctx, redisKey).Result()
	if err != nil || ttl < 0 {
		// Fall back to the full configured window if the real TTL can't be
		// read for some reason — still correct, just less precise than the
		// real remaining time.
		ttl = l.window
	}
	return true, ttl, nil
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
