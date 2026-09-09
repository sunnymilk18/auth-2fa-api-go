package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"auth-2fa-api/internal/testutil"
)

func TestRateLimiter_Allow(t *testing.T) {
	rdb := testutil.RedisClient(t)
	rl := NewRateLimiter(rdb, "test", 3, time.Minute, false)
	ctx := t.Context()

	for i := 1; i <= 3; i++ {
		allowed, err := rl.Allow(ctx, "key")
		if err != nil {
			t.Fatalf("Allow() error: %v", err)
		}
		if !allowed {
			t.Fatalf("Allow() call %d: want allowed, got denied", i)
		}
	}

	allowed, err := rl.Allow(ctx, "key")
	if err != nil {
		t.Fatalf("Allow() error: %v", err)
	}
	if allowed {
		t.Fatal("Allow() call 4: want denied (over limit), got allowed")
	}

	// A different key has its own independent counter.
	allowed, err = rl.Allow(ctx, "other-key")
	if err != nil {
		t.Fatalf("Allow() error: %v", err)
	}
	if !allowed {
		t.Fatal("Allow() for a different key: want allowed, got denied")
	}
}

func TestRateLimiter_Middleware_BlocksOverLimit(t *testing.T) {
	rdb := testutil.RedisClient(t)
	rl := NewRateLimiter(rdb, "test", 2, time.Minute, false)

	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	do := func() int {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.RemoteAddr = "203.0.113.5:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := do(); code != http.StatusOK {
		t.Fatalf("request 1: want 200, got %d", code)
	}
	if code := do(); code != http.StatusOK {
		t.Fatalf("request 2: want 200, got %d", code)
	}
	if code := do(); code != http.StatusTooManyRequests {
		t.Fatalf("request 3: want 429, got %d", code)
	}
}

// This is the regression test for the X-Forwarded-For bypass: with
// trustProxyHeaders off (the default), spoofing a different IP on every
// request must NOT reset the counter.
func TestRateLimiter_IgnoresForgedXForwardedForByDefault(t *testing.T) {
	rdb := testutil.RedisClient(t)
	rl := NewRateLimiter(rdb, "test", 1, time.Minute, false)

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

// When TRUST_PROXY_HEADERS is explicitly enabled (only correct behind a
// proxy that overwrites the header itself), X-Forwarded-For is honored.
func TestRateLimiter_UsesXForwardedForWhenTrusted(t *testing.T) {
	rdb := testutil.RedisClient(t)
	rl := NewRateLimiter(rdb, "test", 1, time.Minute, true)

	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	do := func(forwardedFor string) int {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.RemoteAddr = "203.0.113.5:12345" // same proxy hop every time
		req.Header.Set("X-Forwarded-For", forwardedFor)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := do("1.1.1.1"); code != http.StatusOK {
		t.Fatalf("client 1.1.1.1, request 1: want 200, got %d", code)
	}
	if code := do("1.1.1.1"); code != http.StatusTooManyRequests {
		t.Fatalf("client 1.1.1.1, request 2: want 429, got %d", code)
	}
	// A genuinely different client (different first hop) gets its own limit.
	if code := do("9.9.9.9, 203.0.113.5"); code != http.StatusOK {
		t.Fatalf("client 9.9.9.9, request 1: want 200, got %d", code)
	}
}

func TestRateLimiter_WindowResets(t *testing.T) {
	rdb, mr := testutil.RedisClientAndServer(t)
	rl := NewRateLimiter(rdb, "test", 1, time.Minute, false)
	ctx := t.Context()

	allowed, err := rl.Allow(ctx, "key")
	if err != nil || !allowed {
		t.Fatalf("first call: allowed=%v err=%v, want true, nil", allowed, err)
	}
	allowed, err = rl.Allow(ctx, "key")
	if err != nil || allowed {
		t.Fatalf("second call within window: allowed=%v err=%v, want false, nil", allowed, err)
	}

	// miniredis tracks TTLs against a manual clock — advance it past the
	// window instead of sleeping in real time.
	mr.FastForward(time.Minute + time.Second)

	allowed, err = rl.Allow(ctx, "key")
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
	rl := NewRateLimiter(rdb, "test", 1, time.Minute, false)

	allowed, err := rl.Allow(t.Context(), "key")
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
