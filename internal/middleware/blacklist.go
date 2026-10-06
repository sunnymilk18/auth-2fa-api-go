package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
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

	// banReferenceSecret derives the short, stable "reference" code a
	// consuming system can show a blocked person without exposing their
	// real IP — see Reference's doc comment. Empty disables it: Reference
	// returns ("", false) and callers omit the field entirely rather than
	// fail. Deliberately a secret of its own (BAN_REFERENCE_SECRET), not
	// reused from JWT_REFRESH_SECRET or anything else already in this
	// project — mixing an HMAC's purpose with an unrelated secret's is the
	// kind of thing that turns into a real problem the day either one
	// needs to rotate independently of the other.
	banReferenceSecret []byte
}

func NewBlacklist(rdb *redis.Client, strikeThreshold int64, strikeWindow time.Duration, banDurations []time.Duration, levelMemory time.Duration, banReferenceSecret []byte) *Blacklist {
	return &Blacklist{
		rdb:                rdb,
		strikeThreshold:    strikeThreshold,
		strikeWindow:       strikeWindow,
		banDurations:       banDurations,
		levelMemory:        levelMemory,
		banReferenceSecret: banReferenceSecret,
	}
}

func (bl *Blacklist) bannedKey(ip string) string  { return "blacklist:banned:" + ip }
func (bl *Blacklist) strikesKey(ip string) string { return "blacklist:strikes:" + ip }
func (bl *Blacklist) levelKey(ip string) string   { return "blacklist:level:" + ip }

// detailsKey holds the extra fields a system-admin listing needs
// (banned_at, banned_until, level, strikes, owner) — separate from
// bannedKey, which only ever needs to answer "is this banned, for how
// long" and predates this. Same TTL as bannedKey itself, set together.
func (bl *Blacklist) detailsKey(ip string) string { return "blacklist:details:" + ip }

// ownedKey is a sorted set of every IP currently banned "because of" one
// api client's traffic (see RecordViolation's doc comment on ownership) —
// score is the ban's Unix expiry, member is the IP. This is what lets
// ListOwned answer "which bans belong to this system" without SCANning the
// whole keyspace: a single ZRANGEBYSCORE against one key.
func (bl *Blacklist) ownedKey(apiClientID string) string { return "blacklist:owned:" + apiClientID }

// allKey is a sorted set of every IP currently banned platform-wide,
// regardless of owner — score is the ban's Unix expiry, member is the IP.
// Backs ListAll (the operator's unscoped /admin/blacklist view); ListOwned
// stays scoped to ownedKey for the per-tenant /system-admin/blacklist view.
func (bl *Blacklist) allKey() string { return "blacklist:all" }

// allowlistOwnerKey's value is the api_client_id that added ip to the
// allowlist (persistent, no TTL — allowlisting isn't time-boxed the way a
// ban is). Existence alone is what RecordViolation checks; the value is
// only read for ownership (AllowlistRemove) and listing.
func (bl *Blacklist) allowlistOwnerKey(ip string) string { return "blacklist:allowlist:owner:" + ip }

// allowlistMembersKey mirrors ownedKey's role for bans: a per-tenant set
// of every IP it has allowlisted, so AllowlistList doesn't need SCAN.
func (bl *Blacklist) allowlistMembersKey(apiClientID string) string {
	return "blacklist:allowlist:members:" + apiClientID
}

// IsAllowlisted reports whether ip is exempt from strikes/bans — see
// RecordViolation and AllowlistAdd's doc comments for what that means and
// why the exemption is global (not scoped to whichever system added it).
func (bl *Blacklist) IsAllowlisted(ctx context.Context, ip string) (bool, error) {
	n, err := bl.rdb.Exists(ctx, bl.allowlistOwnerKey(ip)).Result()
	if err != nil {
		return false, fmt.Errorf("checking blacklist allowlist: %w", err)
	}
	return n > 0, nil
}

// AllowlistAdd exempts ip from ever being struck or banned (see
// RecordViolation) — for an address a system knows is its own legitimate
// traffic that just happens to be shared (a NATed office network, for
// instance), so a burst of real logins shouldn't be able to ban everyone
// behind it. The exemption is global once added: it protects ip against
// every system's strikes, not only apiClientID's own — the same "one IP,
// one shared state" reality that makes a ban affect every system too (see
// RecordViolation's doc comment on ownership, and README.md/DEPLOY.md).
// Also lifts any ban ip is currently serving and clears its strike/level
// history, same as Unban — the point of allowlisting an IP is that it
// should never be blocked, so leaving an existing block in place would
// defeat the purpose of the call that was just made to prevent exactly
// that.
func (bl *Blacklist) AllowlistAdd(ctx context.Context, apiClientID, ip string) error {
	if err := bl.rdb.Set(ctx, bl.allowlistOwnerKey(ip), apiClientID, 0).Err(); err != nil {
		return fmt.Errorf("adding to blacklist allowlist: %w", err)
	}
	if err := bl.rdb.SAdd(ctx, bl.allowlistMembersKey(apiClientID), ip).Err(); err != nil {
		return fmt.Errorf("indexing blacklist allowlist entry: %w", err)
	}
	return bl.Unban(ctx, ip)
}

// AllowlistRemove takes ip off the allowlist, but only if apiClientID is
// the one that added it — same ownership rule as UnbanOwned. found is
// false (no error) when ip isn't allowlisted at all, or belongs to a
// different system.
func (bl *Blacklist) AllowlistRemove(ctx context.Context, apiClientID, ip string) (found bool, err error) {
	owner, err := bl.rdb.Get(ctx, bl.allowlistOwnerKey(ip)).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reading blacklist allowlist owner: %w", err)
	}
	if owner != apiClientID {
		return false, nil
	}
	if err := bl.rdb.Del(ctx, bl.allowlistOwnerKey(ip)).Err(); err != nil {
		return false, fmt.Errorf("removing blacklist allowlist entry: %w", err)
	}
	if err := bl.rdb.SRem(ctx, bl.allowlistMembersKey(apiClientID), ip).Err(); err != nil {
		return false, fmt.Errorf("removing blacklist allowlist index: %w", err)
	}
	return true, nil
}

// AllowlistList returns every IP apiClientID has allowlisted, in no
// particular order.
func (bl *Blacklist) AllowlistList(ctx context.Context, apiClientID string) ([]string, error) {
	ips, err := bl.rdb.SMembers(ctx, bl.allowlistMembersKey(apiClientID)).Result()
	if err != nil {
		return nil, fmt.Errorf("listing blacklist allowlist: %w", err)
	}
	return ips, nil
}

// Reference derives a short, stable, non-reversible code from ip — safe for
// a consuming system's panel to show a blocked person (support ticket,
// error message) without exposing their real IP address. Deterministic
// (the same ip always yields the same reference) but one-way: knowing the
// reference doesn't let anyone recover the IP without the secret. ok is
// false when BAN_REFERENCE_SECRET isn't configured — callers omit the
// field entirely rather than send an empty or fake one.
func (bl *Blacklist) Reference(ip string) (reference string, ok bool) {
	if len(bl.banReferenceSecret) == 0 {
		return "", false
	}
	mac := hmac.New(sha256.New, bl.banReferenceSecret)
	mac.Write([]byte(ip))
	return hex.EncodeToString(mac.Sum(nil))[:8], true
}

// BanInfo is one banned IP as a system-admin listing shows it — see
// ListOwned.
type BanInfo struct {
	IP          string
	Reference   string // "" when BAN_REFERENCE_SECRET isn't configured
	HasRef      bool
	BannedAt    time.Time
	BannedUntil time.Time
	Level       int64
	Strikes     int64
	// OwnerAPIClientID is "" for a ban with no resolvable owner — only
	// ever populated by ListAll; ListOwned never returns such a ban at
	// all (see its own doc comment).
	OwnerAPIClientID string
}

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
//
// Never strikes or bans an IP inside a trusted-proxy network (see
// ClientIP/TRUSTED_PROXY_CIDRS) — that would only ever happen if a trusted
// system's own call reached here without X-Forwarded-For resolving to a
// real end user (a bug on that system's side, or simply no header set),
// making ClientIP fall back to the proxy's own address. Banning that
// address would take down every user behind that proxy at once, which is
// worse than the single bad request this is meant to catch.
//
// ownerAPIClientID records which consuming system's request happened to be
// the one that crossed strikeThreshold and actually created this ban — see
// ListOwned/UnbanOwned. "" (not resolvable, e.g. a hypothetical
// rate-limited route with no X-API-Key context) means the ban belongs to
// the operator only: it still works exactly as before, just invisible to
// every /system-admin/blacklist listing. The strikes counter itself is
// shared by IP alone, not scoped per system — so if one IP's strikes
// happen to come from two different systems before the threshold is
// crossed (a shared IP with abusive traffic hitting both), the resulting
// ban is attributed to whichever one's request was the last straw, not
// split between them. Documented behavior, not a bug — see README.md/
// DEPLOY.md.
func (bl *Blacklist) RecordViolation(ctx context.Context, ip, ownerAPIClientID string) error {
	if isTrustedProxyAddr(ip) {
		return nil
	}
	allowlisted, err := bl.IsAllowlisted(ctx, ip)
	if err != nil {
		return err
	}
	if allowlisted {
		return nil
	}

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
	duration := bl.banDurations[idx]
	if err := bl.rdb.Set(ctx, bl.bannedKey(ip), "1", duration).Err(); err != nil {
		return fmt.Errorf("banning ip: %w", err)
	}
	// Reset strikes so, once the ban itself expires, one leftover strike
	// doesn't immediately re-trigger a fresh ban before any new violation.
	if err := bl.rdb.Del(ctx, bl.strikesKey(ip)).Err(); err != nil {
		return fmt.Errorf("resetting blacklist strikes after ban: %w", err)
	}

	// Details/global index are recorded for every ban, owned or not — see
	// ListAll's doc comment for why this one (unlike ownedKey below) isn't
	// conditional on ownerAPIClientID: the operator's unscoped view needs
	// to see every ban, including ones with no resolvable owner.
	now := time.Now()
	bannedUntil := now.Add(duration)
	if err := bl.rdb.HSet(ctx, bl.detailsKey(ip), map[string]any{
		"ip":           ip,
		"owner":        ownerAPIClientID,
		"banned_at":    now.Unix(),
		"banned_until": bannedUntil.Unix(),
		"level":        level,
		"strikes":      strikes,
	}).Err(); err != nil {
		return fmt.Errorf("recording blacklist ban details: %w", err)
	}
	if err := bl.rdb.Expire(ctx, bl.detailsKey(ip), duration).Err(); err != nil {
		return fmt.Errorf("setting blacklist details ttl: %w", err)
	}
	if err := bl.rdb.ZAdd(ctx, bl.allKey(), redis.Z{
		Score:  float64(bannedUntil.Unix()),
		Member: ip,
	}).Err(); err != nil {
		return fmt.Errorf("indexing blacklist ban globally: %w", err)
	}
	if ownerAPIClientID != "" {
		if err := bl.rdb.ZAdd(ctx, bl.ownedKey(ownerAPIClientID), redis.Z{
			Score:  float64(bannedUntil.Unix()),
			Member: ip,
		}).Err(); err != nil {
			return fmt.Errorf("indexing blacklist ban by owner: %w", err)
		}
	}
	return nil
}

// ListOwned returns apiClientID's currently-banned IPs, soonest-to-expire
// first (ZRANGEBYSCORE's natural ascending order over banned_until), up to
// limit. Opportunistically prunes any already-expired entries from the
// owner's index first (a sorted set has no native per-member TTL, so an
// expired ban's IP would otherwise linger in the index — harmless since
// ListOwned always re-checks against "now" anyway, but cleaning it up keeps
// the index from growing forever for a system that gets banned often). Bans
// created before this feature existed (no owner recorded) never appear
// here — see RecordViolation.
func (bl *Blacklist) ListOwned(ctx context.Context, apiClientID string, limit int64) ([]BanInfo, error) {
	key := bl.ownedKey(apiClientID)
	now := time.Now().Unix()

	if err := bl.rdb.ZRemRangeByScore(ctx, key, "-inf", strconv.FormatInt(now-1, 10)).Err(); err != nil {
		return nil, fmt.Errorf("pruning expired blacklist entries: %w", err)
	}

	ips, err := bl.rdb.ZRangeByScore(ctx, key, &redis.ZRangeBy{
		Min:   strconv.FormatInt(now, 10),
		Max:   "+inf",
		Count: limit,
	}).Result()
	if err != nil {
		return nil, fmt.Errorf("listing blacklist entries: %w", err)
	}

	out := make([]BanInfo, 0, len(ips))
	for _, ip := range ips {
		fields, err := bl.rdb.HGetAll(ctx, bl.detailsKey(ip)).Result()
		if err != nil {
			return nil, fmt.Errorf("reading blacklist ban details for %s: %w", ip, err)
		}
		if len(fields) == 0 {
			// Details hash already expired (its own TTL is tighter than
			// or equal to the ban, but clock skew between the two Redis
			// writes above could in principle let this happen) — skip
			// rather than return a half-empty entry.
			continue
		}
		info := BanInfo{IP: ip}
		info.BannedAt = parseUnixField(fields["banned_at"])
		info.BannedUntil = parseUnixField(fields["banned_until"])
		info.Level, _ = strconv.ParseInt(fields["level"], 10, 64)
		info.Strikes, _ = strconv.ParseInt(fields["strikes"], 10, 64)
		if ref, ok := bl.Reference(ip); ok {
			info.Reference, info.HasRef = ref, true
		}
		out = append(out, info)
	}
	return out, nil
}

// ListAll returns every currently-banned IP platform-wide, soonest-to-
// expire first, up to limit — the operator's unscoped /admin/blacklist
// view across every tenant at once (ListOwned is the per-tenant
// equivalent). Unlike ListOwned, a ban with no resolvable owner DOES
// appear here, with OwnerAPIClientID == "".
//
// A ban recorded before this global index existed never appears here
// either, same limitation ListOwned already had for ownedKey — it still
// enforces its deny (bannedKey has its own TTL, untouched by this), it
// just won't show up in this listing until it naturally expires.
func (bl *Blacklist) ListAll(ctx context.Context, limit int64) ([]BanInfo, error) {
	key := bl.allKey()
	now := time.Now().Unix()

	if err := bl.rdb.ZRemRangeByScore(ctx, key, "-inf", strconv.FormatInt(now-1, 10)).Err(); err != nil {
		return nil, fmt.Errorf("pruning expired blacklist entries: %w", err)
	}

	ips, err := bl.rdb.ZRangeByScore(ctx, key, &redis.ZRangeBy{
		Min:   strconv.FormatInt(now, 10),
		Max:   "+inf",
		Count: limit,
	}).Result()
	if err != nil {
		return nil, fmt.Errorf("listing blacklist entries: %w", err)
	}

	out := make([]BanInfo, 0, len(ips))
	for _, ip := range ips {
		fields, err := bl.rdb.HGetAll(ctx, bl.detailsKey(ip)).Result()
		if err != nil {
			return nil, fmt.Errorf("reading blacklist ban details for %s: %w", ip, err)
		}
		if len(fields) == 0 {
			continue
		}
		info := BanInfo{IP: ip, OwnerAPIClientID: fields["owner"]}
		info.BannedAt = parseUnixField(fields["banned_at"])
		info.BannedUntil = parseUnixField(fields["banned_until"])
		info.Level, _ = strconv.ParseInt(fields["level"], 10, 64)
		info.Strikes, _ = strconv.ParseInt(fields["strikes"], 10, 64)
		if ref, ok := bl.Reference(ip); ok {
			info.Reference, info.HasRef = ref, true
		}
		out = append(out, info)
	}
	return out, nil
}

func parseUnixField(v string) time.Time {
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(n, 0)
}

// UnbanOwned lifts ip's ban, but only if it's currently owned by
// apiClientID — see RecordViolation's doc comment on ownership. found is
// false (no error) when ip isn't banned at all, belongs to a different
// system, or was banned before ownership tracking existed — the caller
// turns that into a 404, same "never reveal whether it exists elsewhere"
// rule every other /system-admin/* route already follows.
func (bl *Blacklist) UnbanOwned(ctx context.Context, apiClientID, ip string) (found bool, err error) {
	owner, err := bl.rdb.HGet(ctx, bl.detailsKey(ip), "owner").Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reading blacklist ban owner: %w", err)
	}
	if owner != apiClientID {
		return false, nil
	}
	if err := bl.Unban(ctx, ip); err != nil {
		return false, err
	}
	return true, nil
}

// Unban lifts a ban early and clears its strike/level history — the manual
// override for a false positive, most commonly a shared IP where the
// original offender is long gone but everyone behind that IP is still
// paying for it. Also clears detailsKey and removes ip from its owner's
// ownedKey index when the ban had one, so a lifted ban stops appearing in
// that system's /system-admin/blacklist listing right away instead of
// lingering until detailsKey's own TTL catches up — both the operator's
// /admin/blacklist/{ip} route and AllowlistAdd call this directly and rely
// on that full cleanup; UnbanOwned does too, after confirming ownership.
func (bl *Blacklist) Unban(ctx context.Context, ip string) error {
	owner, err := bl.rdb.HGet(ctx, bl.detailsKey(ip), "owner").Result()
	if err != nil && err != redis.Nil {
		return fmt.Errorf("reading blacklist ban owner: %w", err)
	}

	if err := bl.rdb.Del(ctx, bl.bannedKey(ip), bl.strikesKey(ip), bl.levelKey(ip), bl.detailsKey(ip)).Err(); err != nil {
		return fmt.Errorf("unbanning ip: %w", err)
	}

	if err := bl.rdb.ZRem(ctx, bl.allKey(), ip).Err(); err != nil {
		return fmt.Errorf("removing blacklist ban from global index: %w", err)
	}

	if owner != "" {
		if err := bl.rdb.ZRem(ctx, bl.ownedKey(owner), ip).Err(); err != nil {
			return fmt.Errorf("removing blacklist ban from owner index: %w", err)
		}
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
			writeBannedResponse(w, bl, ip, retryAfter)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func writeBannedResponse(w http.ResponseWriter, bl *Blacklist, ip string, retryAfter time.Duration) {
	body := map[string]any{
		"error":               "acceso bloqueado temporalmente por actividad sospechosa",
		"code":                "ip_banned",
		"retry_after_seconds": int64(retryAfter.Seconds()),
	}
	if ref, ok := bl.Reference(ip); ok {
		body["reference"] = ref
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(body)
}
