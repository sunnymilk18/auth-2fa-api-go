package middleware_test

import (
	"encoding/json"
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
		[]time.Duration{time.Hour, 2 * time.Hour, 3 * time.Hour}, 30*24*time.Hour, nil)
	ctx := t.Context()

	for i := 1; i < 3; i++ {
		if err := bl.RecordViolation(ctx, "1.2.3.4", "test-client"); err != nil {
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
	if err := bl.RecordViolation(ctx, "1.2.3.4", "test-client"); err != nil {
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
	bl := middleware.NewBlacklist(rdb, 1, time.Hour, banDurations, 30*24*time.Hour, nil)
	ctx := t.Context()

	// 1st ban: threshold is 1, so a single violation bans immediately.
	if err := bl.RecordViolation(ctx, "5.5.5.5", "test-client"); err != nil {
		t.Fatalf("RecordViolation (1st ban): %v", err)
	}
	if _, retryAfter, _ := bl.IsBanned(ctx, "5.5.5.5"); retryAfter > time.Hour || retryAfter <= 0 {
		t.Fatalf("1st ban retryAfter = %v, want <= 1h (tier 1)", retryAfter)
	}

	// Expire the ban itself, then trigger a 2nd one — must escalate to tier 2.
	mr.FastForward(time.Hour + time.Second)
	if err := bl.RecordViolation(ctx, "5.5.5.5", "test-client"); err != nil {
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
	if err := bl.RecordViolation(ctx, "5.5.5.5", "test-client"); err != nil {
		t.Fatalf("RecordViolation (3rd ban): %v", err)
	}
	mr.FastForward(3*time.Hour + time.Second)
	if err := bl.RecordViolation(ctx, "5.5.5.5", "test-client"); err != nil {
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
		[]time.Duration{time.Hour, 2 * time.Hour}, 30*24*time.Hour, nil)
	ctx := t.Context()

	if err := bl.RecordViolation(ctx, "8.8.8.8", "test-client"); err != nil {
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
	if err := bl.RecordViolation(ctx, "8.8.8.8", "test-client"); err != nil {
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

// The 403 a banned IP gets must be real JSON (Content-Type included) with
// code/retry_after_seconds always present and reference only when a
// BAN_REFERENCE_SECRET is actually configured.
func TestBlacklist_Middleware_BannedResponseShape(t *testing.T) {
	rdb := testutil.RedisClient(t)

	doRequest := func(bl *middleware.Blacklist, ip string) *httptest.ResponseRecorder {
		handler := bl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.RemoteAddr = ip + ":12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	t.Run("without a reference secret", func(t *testing.T) {
		bl := middleware.NewBlacklist(rdb, 1, time.Hour, []time.Duration{time.Hour}, 30*24*time.Hour, nil)
		if err := bl.RecordViolation(t.Context(), "198.51.100.20", "tenant-a"); err != nil {
			t.Fatalf("RecordViolation: %v", err)
		}
		rec := doRequest(bl, "198.51.100.20")

		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Fatalf("Content-Type = %q, want application/json", ct)
		}
		var body map[string]any
		if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
			t.Fatalf("response body isn't valid JSON: %v", err)
		}
		if body["code"] != "ip_banned" {
			t.Fatalf(`body["code"] = %v, want "ip_banned"`, body["code"])
		}
		if _, ok := body["retry_after_seconds"]; !ok {
			t.Fatal("body missing retry_after_seconds")
		}
		if _, ok := body["reference"]; ok {
			t.Fatal("body has a reference field despite no secret being configured")
		}
	})

	t.Run("with a reference secret", func(t *testing.T) {
		bl := middleware.NewBlacklist(rdb, 1, time.Hour, []time.Duration{time.Hour}, 30*24*time.Hour, []byte("test-secret"))
		if err := bl.RecordViolation(t.Context(), "198.51.100.21", "tenant-a"); err != nil {
			t.Fatalf("RecordViolation: %v", err)
		}
		rec := doRequest(bl, "198.51.100.21")

		var body map[string]any
		if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
			t.Fatalf("response body isn't valid JSON: %v", err)
		}
		ref, _ := body["reference"].(string)
		if ref == "" {
			t.Fatal("body missing reference despite a secret being configured")
		}
	})
}

func TestBlacklist_Middleware_RejectsBannedIP(t *testing.T) {
	rdb := testutil.RedisClient(t)
	bl := middleware.NewBlacklist(rdb, 1, time.Hour, []time.Duration{time.Hour}, 30*24*time.Hour, nil)
	ctx := t.Context()

	if err := bl.RecordViolation(ctx, "203.0.113.9", "test-client"); err != nil {
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

// RecordViolation must never strike or ban an IP that falls inside a
// trusted-proxy network — banning empresa-backend's (or any other trusted
// system's) own address would take the whole integration down over a
// single bug, like a call that forgot to set X-Forwarded-For.
func TestBlacklist_RecordViolation_NeverBansTrustedProxyAddr(t *testing.T) {
	middleware.ValidateTrustedProxyCIDRs("10.0.1.0/24")
	t.Cleanup(func() { middleware.ValidateTrustedProxyCIDRs("") })

	rdb := testutil.RedisClient(t)
	bl := middleware.NewBlacklist(rdb, 1, time.Hour, []time.Duration{time.Hour}, 30*24*time.Hour, nil)
	ctx := t.Context()

	for i := 0; i < 5; i++ {
		if err := bl.RecordViolation(ctx, "10.0.1.249", "some-client"); err != nil {
			t.Fatalf("RecordViolation #%d: %v", i, err)
		}
	}
	if banned, _, _ := bl.IsBanned(ctx, "10.0.1.249"); banned {
		t.Fatal("trusted-proxy address got banned, want it never counted at all")
	}

	// An address outside the trusted network is unaffected by the
	// safeguard and still bans normally.
	if err := bl.RecordViolation(ctx, "203.0.113.50", "some-client"); err != nil {
		t.Fatalf("RecordViolation (untrusted ip): %v", err)
	}
	if banned, _, _ := bl.IsBanned(ctx, "203.0.113.50"); !banned {
		t.Fatal("untrusted IP should still ban normally")
	}
}

// Reference is deterministic for the same IP, differs across IPs, and is
// disabled (ok=false) with no secret configured.
func TestBlacklist_Reference(t *testing.T) {
	rdb := testutil.RedisClient(t)

	withoutSecret := middleware.NewBlacklist(rdb, 1, time.Hour, []time.Duration{time.Hour}, 30*24*time.Hour, nil)
	if _, ok := withoutSecret.Reference("1.2.3.4"); ok {
		t.Fatal("Reference should be disabled with no BAN_REFERENCE_SECRET configured")
	}

	withSecret := middleware.NewBlacklist(rdb, 1, time.Hour, []time.Duration{time.Hour}, 30*24*time.Hour, []byte("test-secret"))
	ref1, ok := withSecret.Reference("1.2.3.4")
	if !ok || ref1 == "" {
		t.Fatal("Reference should be enabled with a secret configured")
	}
	ref1Again, _ := withSecret.Reference("1.2.3.4")
	if ref1Again != ref1 {
		t.Fatalf("Reference(%q) not stable: %q then %q", "1.2.3.4", ref1, ref1Again)
	}
	ref2, _ := withSecret.Reference("5.6.7.8")
	if ref2 == ref1 {
		t.Fatal("different IPs must not collide to the same reference")
	}
}

// ListOwned/UnbanOwned only ever see/affect bans this specific api client
// actually triggered — a different tenant's own bans (even ones that exist
// at the same time) must be completely invisible and un-liftable.
func TestBlacklist_ListOwnedAndUnbanOwned_ScopedToOwner(t *testing.T) {
	rdb := testutil.RedisClient(t)
	bl := middleware.NewBlacklist(rdb, 1, time.Hour, []time.Duration{time.Hour}, 30*24*time.Hour, []byte("test-secret"))
	ctx := t.Context()

	if err := bl.RecordViolation(ctx, "198.51.100.1", "tenant-a"); err != nil {
		t.Fatalf("RecordViolation (tenant-a): %v", err)
	}
	if err := bl.RecordViolation(ctx, "198.51.100.2", "tenant-b"); err != nil {
		t.Fatalf("RecordViolation (tenant-b): %v", err)
	}

	bansA, err := bl.ListOwned(ctx, "tenant-a", 200)
	if err != nil {
		t.Fatalf("ListOwned(tenant-a): %v", err)
	}
	if len(bansA) != 1 || bansA[0].IP != "198.51.100.1" {
		t.Fatalf("ListOwned(tenant-a) = %+v, want exactly the one ban it owns", bansA)
	}
	if !bansA[0].HasRef || bansA[0].Reference == "" {
		t.Fatalf("ListOwned(tenant-a) ban missing reference despite a secret being configured: %+v", bansA[0])
	}
	if bansA[0].Strikes != 1 || bansA[0].Level != 1 {
		t.Fatalf("ListOwned(tenant-a) strikes/level = %d/%d, want 1/1", bansA[0].Strikes, bansA[0].Level)
	}

	bansB, err := bl.ListOwned(ctx, "tenant-b", 200)
	if err != nil {
		t.Fatalf("ListOwned(tenant-b): %v", err)
	}
	if len(bansB) != 1 || bansB[0].IP != "198.51.100.2" {
		t.Fatalf("ListOwned(tenant-b) = %+v, want exactly the one ban it owns", bansB)
	}

	// tenant-b can't lift tenant-a's ban.
	found, err := bl.UnbanOwned(ctx, "tenant-b", "198.51.100.1")
	if err != nil {
		t.Fatalf("UnbanOwned(tenant-b, tenant-a's ip): %v", err)
	}
	if found {
		t.Fatal("tenant-b must not be able to lift tenant-a's ban")
	}
	if banned, _, _ := bl.IsBanned(ctx, "198.51.100.1"); !banned {
		t.Fatal("tenant-a's ban must still be in place after tenant-b's failed attempt")
	}

	// tenant-a can lift its own ban.
	found, err = bl.UnbanOwned(ctx, "tenant-a", "198.51.100.1")
	if err != nil {
		t.Fatalf("UnbanOwned(tenant-a, own ip): %v", err)
	}
	if !found {
		t.Fatal("tenant-a should be able to lift its own ban")
	}
	if banned, _, _ := bl.IsBanned(ctx, "198.51.100.1"); banned {
		t.Fatal("ban should be lifted after UnbanOwned")
	}
	bansA, err = bl.ListOwned(ctx, "tenant-a", 200)
	if err != nil {
		t.Fatalf("ListOwned(tenant-a) after unban: %v", err)
	}
	if len(bansA) != 0 {
		t.Fatalf("ListOwned(tenant-a) after unban = %+v, want empty", bansA)
	}
}

// A ban whose triggering request couldn't resolve an owner (empty
// ownerAPIClientID — the operator-only case) must never show up in any
// tenant's own listing, and no tenant can lift it via UnbanOwned.
func TestBlacklist_OwnerlessBan_InvisibleToSystemAdmins(t *testing.T) {
	rdb := testutil.RedisClient(t)
	bl := middleware.NewBlacklist(rdb, 1, time.Hour, []time.Duration{time.Hour}, 30*24*time.Hour, nil)
	ctx := t.Context()

	if err := bl.RecordViolation(ctx, "203.0.113.77", ""); err != nil {
		t.Fatalf("RecordViolation (no owner): %v", err)
	}
	if banned, _, _ := bl.IsBanned(ctx, "203.0.113.77"); !banned {
		t.Fatal("the ban itself must still take effect even with no owner")
	}

	bans, err := bl.ListOwned(ctx, "any-tenant", 200)
	if err != nil {
		t.Fatalf("ListOwned: %v", err)
	}
	if len(bans) != 0 {
		t.Fatalf("ListOwned(any-tenant) = %+v, want empty — the ban has no owner", bans)
	}

	found, err := bl.UnbanOwned(ctx, "any-tenant", "203.0.113.77")
	if err != nil {
		t.Fatalf("UnbanOwned: %v", err)
	}
	if found {
		t.Fatal("no tenant should be able to lift an ownerless ban via UnbanOwned")
	}
}

// AllowlistAdd exempts an IP from future strikes/bans, and also lifts
// whatever ban it's currently serving right away — allowlisting an IP
// precisely because it's wrongly blocked shouldn't leave it blocked until
// a separate Unban call.
func TestBlacklist_AllowlistAdd_ExemptsFromStrikesAndLiftsExistingBan(t *testing.T) {
	rdb := testutil.RedisClient(t)
	bl := middleware.NewBlacklist(rdb, 1, time.Hour, []time.Duration{time.Hour}, 30*24*time.Hour, nil)
	ctx := t.Context()

	if err := bl.RecordViolation(ctx, "192.0.2.50", "tenant-a"); err != nil {
		t.Fatalf("RecordViolation: %v", err)
	}
	if banned, _, _ := bl.IsBanned(ctx, "192.0.2.50"); !banned {
		t.Fatal("expected banned before allowlisting")
	}

	if err := bl.AllowlistAdd(ctx, "tenant-a", "192.0.2.50"); err != nil {
		t.Fatalf("AllowlistAdd: %v", err)
	}
	if banned, _, _ := bl.IsBanned(ctx, "192.0.2.50"); banned {
		t.Fatal("AllowlistAdd must lift any ban the IP is currently serving")
	}

	// Further violations never strike or ban it again.
	for i := 0; i < 5; i++ {
		if err := bl.RecordViolation(ctx, "192.0.2.50", "tenant-a"); err != nil {
			t.Fatalf("RecordViolation #%d after allowlisting: %v", i, err)
		}
	}
	if banned, _, _ := bl.IsBanned(ctx, "192.0.2.50"); banned {
		t.Fatal("allowlisted IP got banned despite the exemption")
	}
}

// The exemption is global once added — it protects the IP against every
// system's strikes, not only the one that added it. Same "one IP, one
// shared state" reality as a ban itself.
func TestBlacklist_AllowlistAdd_IsGlobalAcrossTenants(t *testing.T) {
	rdb := testutil.RedisClient(t)
	bl := middleware.NewBlacklist(rdb, 1, time.Hour, []time.Duration{time.Hour}, 30*24*time.Hour, nil)
	ctx := t.Context()

	if err := bl.AllowlistAdd(ctx, "tenant-a", "192.0.2.60"); err != nil {
		t.Fatalf("AllowlistAdd: %v", err)
	}

	// tenant-b's own strikes against this IP are exempted too.
	if err := bl.RecordViolation(ctx, "192.0.2.60", "tenant-b"); err != nil {
		t.Fatalf("RecordViolation (tenant-b): %v", err)
	}
	if banned, _, _ := bl.IsBanned(ctx, "192.0.2.60"); banned {
		t.Fatal("allowlisting by tenant-a should also protect the IP against tenant-b's strikes")
	}
}

// AllowlistRemove/AllowlistList only ever affect/see entries the calling
// system itself added — same isolation rule as bans.
func TestBlacklist_AllowlistRemoveAndList_ScopedToOwner(t *testing.T) {
	rdb := testutil.RedisClient(t)
	bl := middleware.NewBlacklist(rdb, 1, time.Hour, []time.Duration{time.Hour}, 30*24*time.Hour, nil)
	ctx := t.Context()

	if err := bl.AllowlistAdd(ctx, "tenant-a", "192.0.2.70"); err != nil {
		t.Fatalf("AllowlistAdd: %v", err)
	}

	listA, err := bl.AllowlistList(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("AllowlistList(tenant-a): %v", err)
	}
	if len(listA) != 1 || listA[0] != "192.0.2.70" {
		t.Fatalf("AllowlistList(tenant-a) = %v, want exactly [192.0.2.70]", listA)
	}

	listB, err := bl.AllowlistList(ctx, "tenant-b")
	if err != nil {
		t.Fatalf("AllowlistList(tenant-b): %v", err)
	}
	if len(listB) != 0 {
		t.Fatalf("AllowlistList(tenant-b) = %v, want empty", listB)
	}

	// tenant-b can't remove tenant-a's entry.
	found, err := bl.AllowlistRemove(ctx, "tenant-b", "192.0.2.70")
	if err != nil {
		t.Fatalf("AllowlistRemove(tenant-b): %v", err)
	}
	if found {
		t.Fatal("tenant-b must not be able to remove tenant-a's allowlist entry")
	}
	// The exemption therefore still holds.
	if err := bl.RecordViolation(ctx, "192.0.2.70", "tenant-a"); err != nil {
		t.Fatalf("RecordViolation: %v", err)
	}
	if banned, _, _ := bl.IsBanned(ctx, "192.0.2.70"); banned {
		t.Fatal("entry should still be allowlisted after tenant-b's failed removal")
	}

	// tenant-a can remove its own entry.
	found, err = bl.AllowlistRemove(ctx, "tenant-a", "192.0.2.70")
	if err != nil {
		t.Fatalf("AllowlistRemove(tenant-a): %v", err)
	}
	if !found {
		t.Fatal("tenant-a should be able to remove its own allowlist entry")
	}
	listA, err = bl.AllowlistList(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("AllowlistList(tenant-a) after removal: %v", err)
	}
	if len(listA) != 0 {
		t.Fatalf("AllowlistList(tenant-a) after removal = %v, want empty", listA)
	}
}

// RateLimiter denials must feed Blacklist's strike counter when attached —
// this is the integration point router.go relies on.
func TestRateLimiter_DenialFeedsAttachedBlacklist(t *testing.T) {
	rdb := testutil.RedisClient(t)
	bl := middleware.NewBlacklist(rdb, 1, time.Hour, []time.Duration{time.Hour}, 30*24*time.Hour, nil)
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
