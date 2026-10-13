package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	chimw "github.com/go-chi/chi/v5/middleware"

	"auth-2fa-api/internal/testutil"
)

func TestRateLimiter_Allow(t *testing.T) {
	rdb := testutil.RedisClient(t)
	rl := NewRateLimiter(rdb, "test", 3, time.Minute)
	ctx := t.Context()

	for i := 1; i <= 3; i++ {
		allowed, _, err := rl.Allow(ctx, "key")
		if err != nil {
			t.Fatalf("Allow() error: %v", err)
		}
		if !allowed {
			t.Fatalf("Allow() call %d: want allowed, got denied", i)
		}
	}

	allowed, _, err := rl.Allow(ctx, "key")
	if err != nil {
		t.Fatalf("Allow() error: %v", err)
	}
	if allowed {
		t.Fatal("Allow() call 4: want denied (over limit), got allowed")
	}

	// A different key has its own independent counter.
	allowed, _, err = rl.Allow(ctx, "other-key")
	if err != nil {
		t.Fatalf("Allow() error: %v", err)
	}
	if !allowed {
		t.Fatal("Allow() for a different key: want allowed, got denied")
	}
}

func TestRateLimiter_Middleware_BlocksOverLimit(t *testing.T) {
	rdb := testutil.RedisClient(t)
	rl := NewRateLimiter(rdb, "test", 2, time.Minute)

	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	do := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.RemoteAddr = "203.0.113.5:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	if rec := do(); rec.Code != http.StatusOK {
		t.Fatalf("request 1: want 200, got %d", rec.Code)
	}
	if rec := do(); rec.Code != http.StatusOK {
		t.Fatalf("request 2: want 200, got %d", rec.Code)
	}
	rec := do()
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("request 3: want 429, got %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("request 3 (blocked): missing Retry-After header")
	}
	if !strings.Contains(rec.Body.String(), "minuto") {
		t.Fatalf("request 3 (blocked): error message %q doesn't tell the caller how long to wait", rec.Body.String())
	}
}

// With no TRUSTED_PROXY_CIDRS configured (the default — see ClientIP's own
// doc comment), X-Forwarded-For is never consulted — a forged one must
// have zero effect on which counter a request hits, always the real
// connection's address.
func TestRateLimiter_IgnoresXForwardedFor(t *testing.T) {
	rdb := testutil.RedisClient(t)
	rl := NewRateLimiter(rdb, "test", 1, time.Minute)

	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	do := func(forwardedFor string) int {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.RemoteAddr = "203.0.113.5:12345" // same real connection every time
		req.Header.Set("X-Forwarded-For", forwardedFor)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := do("1.1.1.1"); code != http.StatusOK {
		t.Fatalf("request 1: want 200, got %d", code)
	}
	// A different forged IP each time must not reset the limit, since the
	// real RemoteAddr is what's actually used.
	if code := do("2.2.2.2"); code != http.StatusTooManyRequests {
		t.Fatalf("request 2 (forged X-Forwarded-For): want 429, got %d", code)
	}
	if code := do("3.3.3.3"); code != http.StatusTooManyRequests {
		t.Fatalf("request 3 (forged X-Forwarded-For): want 429, got %d", code)
	}
}

// With TRUSTED_PROXY_CIDRS covering the connecting RemoteAddr (e.g. the
// internal Docker network a proxying backend like empresa-backend sits on),
// the limiter must count by the real client IP that proxy reports via
// X-Forwarded-For — not by the proxy's own address, which would otherwise
// make every user behind it share one budget (the exact bug TRUSTED_PROXY_
// CIDRS exists to fix). Mirrors how router.go wires chi's ClientIPFromXFF
// ahead of this middleware in production.
func TestRateLimiter_TrustedProxy_CountsByRealClientIP(t *testing.T) {
	t.Cleanup(func() { ValidateTrustedProxyCIDRs("") })
	ValidateTrustedProxyCIDRs("10.0.1.0/24")

	rdb := testutil.RedisClient(t)
	rl := NewRateLimiter(rdb, "test-trusted", 1, time.Minute)

	handler := chimw.ClientIPFromXFF("10.0.1.0/24")(rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	do := func(realClientIP string) int {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.RemoteAddr = "10.0.1.249:12345" // the proxy's own connection, trusted
		req.Header.Set("X-Forwarded-For", realClientIP)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	// Two different real clients behind the same trusted proxy each get
	// their own budget.
	if code := do("152.172.68.141"); code != http.StatusOK {
		t.Fatalf("client A request 1: want 200, got %d", code)
	}
	if code := do("203.0.113.9"); code != http.StatusOK {
		t.Fatalf("client B request 1: want 200, got %d (must not share client A's budget)", code)
	}
	// The same real client hitting the limit (1/min configured above) gets
	// throttled on their second request.
	if code := do("152.172.68.141"); code != http.StatusTooManyRequests {
		t.Fatalf("client A request 2: want 429 (limit is 1/min), got %d", code)
	}
	// Client B is unaffected by client A's own limit.
	if code := do("203.0.113.9"); code != http.StatusTooManyRequests {
		t.Fatalf("client B request 2: want 429 (its own limit, not borrowed from client A), got %d", code)
	}
}

// Allow's retryAfter must reflect how much of the window is actually left,
// not always the full configured window — see the analogous
// auth.TestLoginAttemptLimiter_IsLocked_ReturnsRealRemainingTime.
func TestRateLimiter_Allow_ReturnsRealRemainingTime(t *testing.T) {
	rdb, mr := testutil.RedisClientAndServer(t)
	rl := NewRateLimiter(rdb, "test", 1, 10*time.Minute)
	ctx := t.Context()

	if _, _, err := rl.Allow(ctx, "key"); err != nil {
		t.Fatalf("Allow (first, under limit): %v", err)
	}

	// 6 of the 10 minutes have already passed — at most 4 should remain.
	mr.FastForward(6 * time.Minute)

	allowed, retryAfter, err := rl.Allow(ctx, "key")
	if err != nil || allowed {
		t.Fatalf("Allow (over limit): allowed=%v err=%v, want false, nil", allowed, err)
	}
	if retryAfter <= 0 || retryAfter > 4*time.Minute {
		t.Fatalf("retryAfter = %v, want something in (0, 4m] (real remaining time, not the full 10m window)", retryAfter)
	}
}

func TestRateLimiter_WindowResets(t *testing.T) {
	rdb, mr := testutil.RedisClientAndServer(t)
	rl := NewRateLimiter(rdb, "test", 1, time.Minute)
	ctx := t.Context()

	allowed, _, err := rl.Allow(ctx, "key")
	if err != nil || !allowed {
		t.Fatalf("first call: allowed=%v err=%v, want true, nil", allowed, err)
	}
	allowed, _, err = rl.Allow(ctx, "key")
	if err != nil || allowed {
		t.Fatalf("second call within window: allowed=%v err=%v, want false, nil", allowed, err)
	}

	// miniredis tracks TTLs against a manual clock — advance it past the
	// window instead of sleeping in real time.
	mr.FastForward(time.Minute + time.Second)

	allowed, _, err = rl.Allow(ctx, "key")
	if err != nil || !allowed {
		t.Fatalf("call after window reset: allowed=%v err=%v, want true, nil", allowed, err)
	}
}

// If Redis itself is unreachable, Allow must report the error (callers that
// care can decide what to do) but Middleware must fail OPEN — a Redis
// outage taking down rate limiting is an acceptable tradeoff next to it
// taking down the whole API (register/login/etc. would otherwise 500 for
// everyone the moment Redis has a hiccup).
func TestRateLimiter_FailsOpenWhenRedisIsDown(t *testing.T) {
	_, mr := testutil.RedisClientAndServer(t)
	addr := mr.Addr()
	mr.Close() // simulate Redis being unreachable

	// MaxRetries: -1 disables go-redis's own dial retries — irrelevant to
	// what this test checks (Allow/Middleware's behavior on failure) and
	// would otherwise make it take several seconds for no benefit.
	rdb := redis.NewClient(&redis.Options{Addr: addr, MaxRetries: -1})
	t.Cleanup(func() { _ = rdb.Close() })
	rl := NewRateLimiter(rdb, "test", 1, time.Minute)

	allowed, _, err := rl.Allow(t.Context(), "key")
	if err == nil {
		t.Fatal("Allow() with Redis down: want an error, got nil")
	}
	if allowed {
		t.Fatal("Allow() with Redis down: want allowed=false alongside the error (Middleware, not Allow, decides to fail open)")
	}

	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "203.0.113.5:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Middleware with Redis down: status = %d, want %d (fail open)", rec.Code, http.StatusOK)
	}
}

// TestRateLimiter_MiddlewareByKey_CountsByCustomKeyNotIP is the case
// /auth/login/push-status needs: two requests from the *same* IP but with
// different keys (e.g. different login_token query params) must each get
// their own independent budget, exactly like two different IPs would
// under the ordinary IP-keyed Middleware.
func TestRateLimiter_MiddlewareByKey_CountsByCustomKeyNotIP(t *testing.T) {
	rdb := testutil.RedisClient(t)
	rl := NewRateLimiter(rdb, "test-by-key", 2, time.Minute)

	handler := rl.MiddlewareByKey(func(r *http.Request) string {
		return r.URL.Query().Get("login_token")
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	do := func(loginToken string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/?login_token="+loginToken, nil)
		req.RemoteAddr = "203.0.113.5:12345" // same IP for every call below
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// Token A: exhaust its budget (limit 2).
	for i := 1; i <= 2; i++ {
		if rec := do("token-a"); rec.Code != http.StatusOK {
			t.Fatalf("token-a call %d: status = %d, want %d", i, rec.Code, http.StatusOK)
		}
	}
	if rec := do("token-a"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("token-a call 3 (over its own limit): status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}

	// Token B, same IP, untouched budget — must still work.
	if rec := do("token-b"); rec.Code != http.StatusOK {
		t.Fatalf("token-b (different key, same IP): status = %d, want %d — a different key must not share token-a's exhausted budget", rec.Code, http.StatusOK)
	}
}

// TestRateLimiter_MiddlewareByKey_StrikesRecordedAgainstIP confirms the
// blacklist strike (when attached) is still keyed by IP even though the
// rate-limit count itself uses a different key — the strike escalation is
// about that IP's behavior across everything it does, not tied to
// whichever identifier a particular limiter happens to count requests by.
func TestRateLimiter_MiddlewareByKey_StrikesRecordedAgainstIP(t *testing.T) {
	rdb := testutil.RedisClient(t)
	bl := NewBlacklist(rdb, 1, time.Hour, []time.Duration{time.Hour}, 24*time.Hour, nil, nil)
	rl := NewRateLimiter(rdb, "test-by-key-strikes", 1, time.Minute).AttachBlacklist(bl)

	handler := rl.MiddlewareByKey(func(r *http.Request) string {
		return r.URL.Query().Get("login_token")
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	do := func(loginToken string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/?login_token="+loginToken, nil)
		req.RemoteAddr = "203.0.113.9:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	do("token-a")                                                     // within limit
	if rec := do("token-a"); rec.Code != http.StatusTooManyRequests { // trips it, 1 strike
		t.Fatalf("token-a call 2: status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}

	banned, _, err := bl.IsBanned(t.Context(), "203.0.113.9")
	if err != nil {
		t.Fatalf("IsBanned: %v", err)
	}
	if !banned {
		t.Fatal("the IP should be banned after 1 strike (strikeThreshold=1), even though the rate limit itself was keyed by login_token")
	}
}
