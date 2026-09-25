package middleware

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
)

// formatWait renders a retry-after duration as a short Spanish phrase for
// user-facing error messages — rounded up to whole minutes (so 90s reads
// as "2 minutos", never "1 minuto" when there's really some of a second
// one left), with the under-a-minute case worded separately rather than
// as "0 minutos". Mirrors auth.formatWait — kept separate rather than
// shared to avoid a cross-package dependency for five lines.
func formatWait(d time.Duration) string {
	minutes := int(d / time.Minute)
	if d%time.Minute != 0 {
		minutes++
	}
	if minutes < 1 {
		return "menos de un minuto"
	}
	if minutes == 1 {
		return "1 minuto"
	}
	return fmt.Sprintf("%d minutos", minutes)
}

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
// still within the limit for the current window. When denied, retryAfter
// is the real time left on the window (read from Redis's own TTL, not just
// the configured window — the window started on whichever request was the
// first to hit this key, not on this one), for callers that want to tell
// the caller how long to actually wait.
func (rl *RateLimiter) Allow(ctx context.Context, key string) (allowed bool, retryAfter time.Duration, err error) {
	redisKey := fmt.Sprintf("ratelimit:%s:%s", rl.prefix, key)

	count, err := rl.rdb.Incr(ctx, redisKey).Result()
	if err != nil {
		return false, 0, err
	}
	if count == 1 {
		// First hit in this window: set expiry so the key resets on its own.
		if err := rl.rdb.Expire(ctx, redisKey, rl.window).Err(); err != nil {
			return false, 0, err
		}
	}
	if count <= rl.limit {
		return true, 0, nil
	}

	ttl, err := rl.rdb.TTL(ctx, redisKey).Result()
	if err != nil || ttl < 0 {
		// Fall back to the full configured window if the real TTL can't be
		// read for some reason — still correct, just less precise.
		ttl = rl.window
	}
	return false, ttl, nil
}

// Middleware rate-limits by client IP.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := rl.clientIP(r)

		allowed, retryAfter, err := rl.Allow(r.Context(), ip)
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
			w.Header().Set("Retry-After", fmt.Sprintf("%.0f", retryAfter.Seconds()))
			http.Error(w, fmt.Sprintf(`{"error":"demasiadas solicitudes, intenta de nuevo en %s"}`, formatWait(retryAfter)), http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (rl *RateLimiter) clientIP(r *http.Request) string {
	return ClientIP(r, rl.trustProxyHeaders)
}
