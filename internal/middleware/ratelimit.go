package middleware

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
)

// RateLimiter implements a fixed-window counter backed by Redis. Simple and
// good enough to blunt brute-force attempts against login/OTP/register
// without adding another moving part to the stack.
type RateLimiter struct {
	rdb    *redis.Client
	prefix string
	limit  int64
	window time.Duration

	// trustProxyHeaders enables reading X-Forwarded-For for the client IP.
	// Only safe when the server sits behind a reverse proxy that overwrites
	// (rather than appends to) that header — otherwise any caller can set
	// it themselves and reset their own counter on every request, making
	// the limit trivial to bypass.
	trustProxyHeaders bool

	// blacklist, when attached, is told about every request this limiter
	// denies — see Blacklist's doc comment for the escalation that feeds.
	// nil is a valid, common state (most limiters don't need it attached
	// more than once — router.go shares a single Blacklist across all of
	// them).
	blacklist *Blacklist
}

func NewRateLimiter(rdb *redis.Client, prefix string, limit int64, window time.Duration, trustProxyHeaders bool) *RateLimiter {
	return &RateLimiter{rdb: rdb, prefix: prefix, limit: limit, window: window, trustProxyHeaders: trustProxyHeaders}
}

// AttachBlacklist wires bl into this limiter so a denied request also
// counts as a strike toward bl's own escalating ban — returns rl so it can
// be chained onto NewRateLimiter at the call site.
func (rl *RateLimiter) AttachBlacklist(bl *Blacklist) *RateLimiter {
	rl.blacklist = bl
	return rl
}

// Allow increments the counter for key and reports whether the caller is
// still within the limit for the current window.
func (rl *RateLimiter) Allow(ctx context.Context, key string) (bool, error) {
	redisKey := fmt.Sprintf("ratelimit:%s:%s", rl.prefix, key)

	count, err := rl.rdb.Incr(ctx, redisKey).Result()
	if err != nil {
		return false, err
	}
	if count == 1 {
		// First hit in this window: set expiry so the key resets on its own.
		if err := rl.rdb.Expire(ctx, redisKey, rl.window).Err(); err != nil {
			return false, err
		}
	}

	return count <= rl.limit, nil
}

// Middleware rate-limits by client IP.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := rl.clientIP(r)

		allowed, err := rl.Allow(r.Context(), ip)
		if err != nil {
			// Fail open: a Redis hiccup shouldn't take the whole API down.
			next.ServeHTTP(w, r)
			return
		}
		if !allowed {
			if rl.blacklist != nil {
				// Best-effort, same fail-open spirit as everything else on
				// this path — a Redis hiccup here just means one strike
				// goes unrecorded, not a request that should have failed
				// open turning into a 500.
				_ = rl.blacklist.RecordViolation(r.Context(), ip)
			}
			w.Header().Set("Retry-After", fmt.Sprintf("%.0f", rl.window.Seconds()))
			http.Error(w, `{"error":"demasiadas solicitudes, intenta de nuevo más tarde"}`, http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (rl *RateLimiter) clientIP(r *http.Request) string {
	return ClientIP(r, rl.trustProxyHeaders)
}
