package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"auth-2fa-api/internal/middleware"
	"auth-2fa-api/internal/testutil"
)

func TestBlacklist_BansAfterStrikeThreshold(t *testing.T) {
	rdb := testutil.RedisClient(t)
	bl := middleware.NewBlacklist(rdb, 3, 24*time.Hour,
		[]time.Duration{time.Hour, 2 * time.Hour, 3 * time.Hour}, 30*24*time.Hour)
	ctx := t.Context()

	for i := 1; i < 3; i++ {
		if err := bl.RecordViolation(ctx, "1.2.3.4"); err != nil {
			t.Fatalf("RecordViolation #%d: %v", i, err)
		}
		banned, _, err := bl.IsBanned(ctx, "1.2.3.4")
		if err != nil {
			t.Fatalf("IsBanned: %v", err)
		}
		if banned {
			t.Fatalf("banned after only %d strikes, want not yet (threshold is 3)", i)
		}
	}

	// 3rd strike crosses the threshold.
	if err := bl.RecordViolation(ctx, "1.2.3.4"); err != nil {
		t.Fatalf("RecordViolation #3: %v", err)
	}
	banned, retryAfter, err := bl.IsBanned(ctx, "1.2.3.4")
	if err != nil {
		t.Fatalf("IsBanned: %v", err)
	}
	if !banned {
		t.Fatal("want banned after 3 strikes, got not banned")
	}
	if retryAfter <= 0 || retryAfter > time.Hour {
		t.Fatalf("retryAfter = %v, want a positive duration capped at the 1st-tier ban (1h)", retryAfter)
	}

	// A different IP is unaffected.
	if banned, _, err := bl.IsBanned(ctx, "9.9.9.9"); err != nil || banned {
		t.Fatalf("unrelated IP: banned=%v err=%v, want false, nil", banned, err)
	}
}

func TestBlacklist_EscalatesBanDurationOnRepeatOffense(t *testing.T) {
	rdb, mr := testutil.RedisClientAndServer(t)
	banDurations := []time.Duration{time.Hour, 2 * time.Hour, 3 * time.Hour}
	bl := middleware.NewBlacklist(rdb, 1, time.Hour, banDurations, 30*24*time.Hour)
	ctx := t.Context()

	// 1st ban: threshold is 1, so a single violation bans immediately.
	if err := bl.RecordViolation(ctx, "5.5.5.5"); err != nil {
		t.Fatalf("RecordViolation (1st ban): %v", err)
	}
	if _, retryAfter, _ := bl.IsBanned(ctx, "5.5.5.5"); retryAfter > time.Hour || retryAfter <= 0 {
		t.Fatalf("1st ban retryAfter = %v, want <= 1h (tier 1)", retryAfter)
	}

	// Expire the ban itself, then trigger a 2nd one — must escalate to tier 2.
	mr.FastForward(time.Hour + time.Second)
	if err := bl.RecordViolation(ctx, "5.5.5.5"); err != nil {
		t.Fatalf("RecordViolation (2nd ban): %v", err)
	}
	_, retryAfter, err := bl.IsBanned(ctx, "5.5.5.5")
	if err != nil {
		t.Fatalf("IsBanned: %v", err)
	}
	if retryAfter <= time.Hour || retryAfter > 2*time.Hour {
		t.Fatalf("2nd ban retryAfter = %v, want in (1h, 2h] (tier 2, escalated)", retryAfter)
	}

	// A 3rd and 4th ban must cap at the last tier (3h), not grow unbounded.
	mr.FastForward(2*time.Hour + time.Second)
	if err := bl.RecordViolation(ctx, "5.5.5.5"); err != nil {
		t.Fatalf("RecordViolation (3rd ban): %v", err)
	}
	mr.FastForward(3*time.Hour + time.Second)
	if err := bl.RecordViolation(ctx, "5.5.5.5"); err != nil {
		t.Fatalf("RecordViolation (4th ban): %v", err)
	}
	_, retryAfter, err = bl.IsBanned(ctx, "5.5.5.5")
	if err != nil {
		t.Fatalf("IsBanned: %v", err)
	}
	if retryAfter > 3*time.Hour {
		t.Fatalf("4th ban retryAfter = %v, want capped at the last tier (3h)", retryAfter)
	}
}

func TestBlacklist_Unban_ClearsBanAndHistory(t *testing.T) {
	rdb := testutil.RedisClient(t)
	bl := middleware.NewBlacklist(rdb, 1, time.Hour,
		[]time.Duration{time.Hour, 2 * time.Hour}, 30*24*time.Hour)
	ctx := t.Context()

	if err := bl.RecordViolation(ctx, "8.8.8.8"); err != nil {
		t.Fatalf("RecordViolation: %v", err)
	}
	if banned, _, _ := bl.IsBanned(ctx, "8.8.8.8"); !banned {
		t.Fatal("want banned before Unban")
	}

	if err := bl.Unban(ctx, "8.8.8.8"); err != nil {
		t.Fatalf("Unban: %v", err)
	}
	if banned, _, _ := bl.IsBanned(ctx, "8.8.8.8"); banned {
		t.Fatal("want not banned after Unban")
	}

	// History cleared too: a fresh single violation goes back to tier 1
	// (1h), not straight to tier 2, proving Unban reset the escalation
	// level as well as the ban itself.
	if err := bl.RecordViolation(ctx, "8.8.8.8"); err != nil {
		t.Fatalf("RecordViolation after Unban: %v", err)
	}
	_, retryAfter, err := bl.IsBanned(ctx, "8.8.8.8")
	if err != nil {
		t.Fatalf("IsBanned: %v", err)
	}
	if retryAfter > time.Hour {
		t.Fatalf("retryAfter after Unban+fresh violation = %v, want back at tier 1 (<= 1h)", retryAfter)
	}
}

func TestBlacklist_Middleware_RejectsBannedIP(t *testing.T) {
	rdb := testutil.RedisClient(t)
	bl := middleware.NewBlacklist(rdb, 1, time.Hour, []time.Duration{time.Hour}, 30*24*time.Hour)
	ctx := t.Context()

	if err := bl.RecordViolation(ctx, "203.0.113.9"); err != nil {
		t.Fatalf("RecordViolation: %v", err)
	}

	handler := bl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "203.0.113.9:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("banned IP: status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("banned IP response missing Retry-After header")
	}

	// A different IP is unaffected.
	req2 := httptest.NewRequest(http.MethodPost, "/", nil)
	req2.RemoteAddr = "203.0.113.10:12345"
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("unrelated IP: status = %d, want %d", rec2.Code, http.StatusOK)
	}
}

// RateLimiter denials must feed Blacklist's strike counter when attached —
// this is the integration point router.go relies on.
func TestRateLimiter_DenialFeedsAttachedBlacklist(t *testing.T) {
	rdb := testutil.RedisClient(t)
	bl := middleware.NewBlacklist(rdb, 1, time.Hour, []time.Duration{time.Hour}, 30*24*time.Hour)
	rl := middleware.NewRateLimiter(rdb, "test", 1, time.Minute).AttachBlacklist(bl)

	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	do := func() int {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.RemoteAddr = "198.51.100.7:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := do(); code != http.StatusOK {
		t.Fatalf("request 1: want 200, got %d", code)
	}
	if code := do(); code != http.StatusTooManyRequests {
		t.Fatalf("request 2 (over the limit): want 429, got %d", code)
	}

	// That single denial should already have been enough to ban the IP,
	// since strikeThreshold is 1 above.
	banned, _, err := bl.IsBanned(t.Context(), "198.51.100.7")
	if err != nil {
		t.Fatalf("IsBanned: %v", err)
	}
	if !banned {
		t.Fatal("want the IP banned after a rate-limit denial fed the attached blacklist, got not banned")
	}
}
