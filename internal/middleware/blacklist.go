package middleware

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
)

// Blacklist escalates repeat rate-limit offenders (by IP) from a temporary
// throttle into a standalone ban. Layered on top of RateLimiter, not a
// replacement for it: RateLimiter's own fixed window already blocks a
// single burst; Blacklist tracks how many separate times an IP has been
// denied within strikeWindow and, past strikeThreshold, bans it outright
// for banDurations[0], escalating to banDurations[1], [2]... on further
// repeats (capped at the last entry) — same idea as the escalating bans
// many mail/SSH brute-force guards use.
//
// levelMemory bounds how long a past ban keeps counting toward the next
// escalation: an IP that behaves for that long resets back to the first
// (shortest) tier instead of climbing forever. That matters here more than
// in a generic deployment — this API serves a municipality, where an IP is
// plausibly a shared one (a public library, a community wifi point), so a
// long-departed offender shouldn't leave that whole location on the
// longest ban tier indefinitely.
type Blacklist struct {
	rdb             *redis.Client
	strikeThreshold int64
	strikeWindow    time.Duration
	banDurations    []time.Duration
	levelMemory     time.Duration
}

func NewBlacklist(rdb *redis.Client, strikeThreshold int64, strikeWindow time.Duration, banDurations []time.Duration, levelMemory time.Duration) *Blacklist {
	return &Blacklist{
		rdb:             rdb,
		strikeThreshold: strikeThreshold,
		strikeWindow:    strikeWindow,
		banDurations:    banDurations,
		levelMemory:     levelMemory,
	}
}

func (bl *Blacklist) bannedKey(ip string) string  { return "blacklist:banned:" + ip }
func (bl *Blacklist) strikesKey(ip string) string { return "blacklist:strikes:" + ip }
func (bl *Blacklist) levelKey(ip string) string   { return "blacklist:level:" + ip }

// IsBanned reports whether ip is currently serving a ban, plus how much
// time is left on it (0 if it's not banned, or its TTL couldn't be read).
func (bl *Blacklist) IsBanned(ctx context.Context, ip string) (banned bool, retryAfter time.Duration, err error) {
	ttl, err := bl.rdb.TTL(ctx, bl.bannedKey(ip)).Result()
	if err != nil {
		return false, 0, fmt.Errorf("checking blacklist: %w", err)
	}
	if ttl <= 0 {
		return false, 0, nil
	}
	return true, ttl, nil
}

// RecordViolation is called by RateLimiter.Middleware every time it denies
// a request — each denial is one strike. Once strikeThreshold strikes land
// within strikeWindow, ip gets banned outright, at whatever tier its
// recent ban history puts it on.
func (bl *Blacklist) RecordViolation(ctx context.Context, ip string) error {
	strikes, err := bl.rdb.Incr(ctx, bl.strikesKey(ip)).Result()
	if err != nil {
		return fmt.Errorf("recording blacklist strike: %w", err)
	}
	if strikes == 1 {
		if err := bl.rdb.Expire(ctx, bl.strikesKey(ip), bl.strikeWindow).Err(); err != nil {
			return fmt.Errorf("setting blacklist strike ttl: %w", err)
		}
	}
	if strikes < bl.strikeThreshold {
		return nil
	}

	level, err := bl.rdb.Incr(ctx, bl.levelKey(ip)).Result()
	if err != nil {
		return fmt.Errorf("recording blacklist level: %w", err)
	}
	if level == 1 {
		if err := bl.rdb.Expire(ctx, bl.levelKey(ip), bl.levelMemory).Err(); err != nil {
			return fmt.Errorf("setting blacklist level ttl: %w", err)
		}
	}

	idx := level - 1
	if idx >= int64(len(bl.banDurations)) {
		idx = int64(len(bl.banDurations)) - 1
	}
	if err := bl.rdb.Set(ctx, bl.bannedKey(ip), "1", bl.banDurations[idx]).Err(); err != nil {
		return fmt.Errorf("banning ip: %w", err)
	}
	// Reset strikes so, once the ban itself expires, one leftover strike
	// doesn't immediately re-trigger a fresh ban before any new violation.
	if err := bl.rdb.Del(ctx, bl.strikesKey(ip)).Err(); err != nil {
		return fmt.Errorf("resetting blacklist strikes after ban: %w", err)
	}
	return nil
}

// Unban lifts a ban early and clears its strike/level history — the manual
// override for a false positive, most commonly a shared IP where the
// original offender is long gone but everyone behind that IP is still
// paying for it.
func (bl *Blacklist) Unban(ctx context.Context, ip string) error {
	if err := bl.rdb.Del(ctx, bl.bannedKey(ip), bl.strikesKey(ip), bl.levelKey(ip)).Err(); err != nil {
		return fmt.Errorf("unbanning ip: %w", err)
	}
	return nil
}

// Middleware is the global gate: a banned IP is rejected before it reaches
// any route at all, rate-limited or not.
func (bl *Blacklist) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := ClientIP(r)

		banned, retryAfter, err := bl.IsBanned(r.Context(), ip)
		if err != nil {
			// Fail open — same reasoning as RateLimiter: a Redis outage
			// must not take the whole API down with it.
			next.ServeHTTP(w, r)
			return
		}
		if banned {
			if retryAfter > 0 {
				w.Header().Set("Retry-After", fmt.Sprintf("%.0f", retryAfter.Seconds()))
			}
			http.Error(w, `{"error":"acceso bloqueado temporalmente por actividad sospechosa"}`, http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
