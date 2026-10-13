package authevents_test

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel/metric/noop"

	"auth-2fa-api/internal/authevents"
	"auth-2fa-api/internal/testutil"
)

func newTestService(t *testing.T, secret []byte) *authevents.Service {
	t.Helper()
	pool := testutil.PostgresPool(t)
	return authevents.NewService(authevents.NewRepository(pool), 90*24*time.Hour, secret, noop.NewMeterProvider().Meter("test"), nil)
}

// TestHashEmail_NoSecret_ReturnsNotOK covers the "degrade, don't fail"
// contract: an unconfigured secret must never silently fall back to a
// weaker (e.g. plain SHA-256) hash — see HashEmail's own doc comment.
func TestHashEmail_NoSecret_ReturnsNotOK(t *testing.T) {
	svc := newTestService(t, nil)
	hash, ok := svc.HashEmail("someone@example.com")
	if ok {
		t.Fatal("HashEmail with no secret configured: ok = true, want false")
	}
	if hash != "" {
		t.Fatalf("HashEmail with no secret configured: hash = %q, want empty", hash)
	}
	if svc.HasEmailHashSecret() {
		t.Fatal("HasEmailHashSecret = true, want false")
	}
}

// TestHashEmail_Deterministic_NormalizesCase confirms the hash is stable
// across case/whitespace variants of the same email (same normalization
// as user.NormalizeEmail) and non-reversible-looking (not the plain email
// itself, and not a bare SHA-256 of it — distinguishing HMAC from plain
// hashing isn't directly testable without the secret, but we can at least
// confirm it never equals the raw address).
func TestHashEmail_Deterministic_NormalizesCase(t *testing.T) {
	svc := newTestService(t, []byte("test-secret"))
	h1, ok1 := svc.HashEmail("Someone@Example.com")
	h2, ok2 := svc.HashEmail("  someone@example.com  ")
	if !ok1 || !ok2 {
		t.Fatalf("HashEmail: ok1=%v ok2=%v, want true,true", ok1, ok2)
	}
	if h1 != h2 {
		t.Fatalf("HashEmail not normalized: %q != %q for case/whitespace variants of the same email", h1, h2)
	}
	if h1 == "someone@example.com" {
		t.Fatal("HashEmail returned the raw email unchanged")
	}
	if svc.HasEmailHashSecret() == false {
		t.Fatal("HasEmailHashSecret = false, want true")
	}
}

// TestHashEmail_DifferentSecrets_ProduceDifferentHashes confirms the
// secret actually participates in the digest (HMAC, not a keyless hash
// that would produce the same output for anyone).
func TestHashEmail_DifferentSecrets_ProduceDifferentHashes(t *testing.T) {
	svcA := newTestService(t, []byte("secret-a"))
	svcB := newTestService(t, []byte("secret-b"))
	hA, _ := svcA.HashEmail("someone@example.com")
	hB, _ := svcB.HashEmail("someone@example.com")
	if hA == hB {
		t.Fatal("HashEmail with two different secrets produced the same hash — not actually keyed")
	}
}

// TestLog_NilService_IsNoop confirms the nil-safety every caller in
// internal/auth/internal/middleware relies on — a *Service built nowhere
// (e.g. a deployment or test that never wires one) must never panic.
func TestLog_NilService_IsNoop(t *testing.T) {
	var svc *authevents.Service
	svc.Log(context.Background(), authevents.Entry{Kind: authevents.KindLogin, Result: authevents.ResultSuccess})
	if svc.HasEmailHashSecret() {
		t.Fatal("HasEmailHashSecret on a nil *Service = true, want false")
	}
	if _, ok := svc.HashEmail("x@example.com"); ok {
		t.Fatal("HashEmail on a nil *Service: ok = true, want false")
	}
}

// TestLog_NullableFieldsStoredAsNULL confirms Entry's zero-value string
// fields (APIClientID/UserID/Method/EmailHash/BanOrigin/ActorEmail/IP)
// become real SQL NULL, not empty strings — see Repository.nullIfEmpty's
// own doc comment for why this matters (an empty string in a UUID/INET
// column would fail outright; in a nullable TEXT column it would defeat
// the "NULL means not applicable to this kind" contract).
func TestLog_NullableFieldsStoredAsNULL(t *testing.T) {
	pool := testutil.PostgresPool(t)
	svc := newTestService(t, nil)
	apiClientID, _ := testutil.NewAPIClient(t, pool)

	svc.Log(context.Background(), authevents.Entry{
		APIClientID: apiClientID.ID,
		Kind:        authevents.KindRegister,
		Result:      authevents.ResultSuccess,
		UserAgent:   "test-agent",
		// Method, UserID, EmailHash, BanOrigin, ActorEmail, IP all left
		// at "" — register has no method, and this row has no user_id
		// resolved yet in this test.
	})
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM auth_events WHERE api_client_id = $1`, apiClientID.ID)
	})

	var methodNull, userIDNull, emailHashNull, banOriginNull, actorEmailNull, ipNull bool
	err := pool.QueryRow(context.Background(), `
		SELECT method IS NULL, user_id IS NULL, email_hash IS NULL, ban_origin IS NULL, actor_email IS NULL, ip IS NULL
		FROM auth_events WHERE api_client_id = $1 ORDER BY id DESC LIMIT 1`, apiClientID.ID).
		Scan(&methodNull, &userIDNull, &emailHashNull, &banOriginNull, &actorEmailNull, &ipNull)
	if err != nil {
		t.Fatalf("querying inserted row: %v", err)
	}
	for name, isNull := range map[string]bool{
		"method": methodNull, "user_id": userIDNull, "email_hash": emailHashNull,
		"ban_origin": banOriginNull, "actor_email": actorEmailNull, "ip": ipNull,
	} {
		if !isNull {
			t.Errorf("%s IS NULL = false, want true for an empty Entry field", name)
		}
	}
}

func TestTruncateUserAgent_CutsAtMaxLength(t *testing.T) {
	long := make([]rune, authevents.MaxUserAgentLength+50)
	for i := range long {
		long[i] = 'a'
	}
	got := authevents.TruncateUserAgent(string(long))
	if len([]rune(got)) != authevents.MaxUserAgentLength {
		t.Fatalf("TruncateUserAgent length = %d, want %d", len([]rune(got)), authevents.MaxUserAgentLength)
	}

	short := "Mozilla/5.0"
	if got := authevents.TruncateUserAgent(short); got != short {
		t.Fatalf("TruncateUserAgent(%q) = %q, want unchanged", short, got)
	}
}

// TestResolveEventRange covers GET /admin/security/events' from/to rules in
// isolation from the HTTP layer — see ResolveEventRange's own doc comment
// for the rules themselves; internal/httpserver's own security_events_test.go
// covers the same cases end-to-end through the real endpoint.
func TestResolveEventRange(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	t.Run("neither given defaults to the last 7 days ending now", func(t *testing.T) {
		from, to, err := authevents.ResolveEventRange(nil, nil, now)
		if err != nil {
			t.Fatalf("ResolveEventRange: %v", err)
		}
		if !to.Equal(now) {
			t.Fatalf("to = %v, want %v", to, now)
		}
		if want := now.Add(-authevents.DefaultEventRangeWindow); !from.Equal(want) {
			t.Fatalf("from = %v, want %v", from, want)
		}
	})

	t.Run("to without from defaults to 7 days ending at to, not at now", func(t *testing.T) {
		to := now.Add(-30 * 24 * time.Hour)
		from, resolvedTo, err := authevents.ResolveEventRange(nil, &to, now)
		if err != nil {
			t.Fatalf("ResolveEventRange: %v", err)
		}
		if !resolvedTo.Equal(to) {
			t.Fatalf("to = %v, want %v", resolvedTo, to)
		}
		if want := to.Add(-authevents.DefaultEventRangeWindow); !from.Equal(want) {
			t.Fatalf("from = %v, want %v (relative to to, not to now)", from, want)
		}
	})

	t.Run("from without to defaults to now", func(t *testing.T) {
		from := now.Add(-time.Hour)
		resolvedFrom, to, err := authevents.ResolveEventRange(&from, nil, now)
		if err != nil {
			t.Fatalf("ResolveEventRange: %v", err)
		}
		if !to.Equal(now) {
			t.Fatalf("to = %v, want %v (defaults to now)", to, now)
		}
		if !resolvedFrom.Equal(from) {
			t.Fatalf("from = %v, want %v (unchanged)", resolvedFrom, from)
		}
	})

	t.Run("a span over 90 days is rejected, not clamped", func(t *testing.T) {
		from := now.Add(-91 * 24 * time.Hour)
		if _, _, err := authevents.ResolveEventRange(&from, &now, now); err == nil {
			t.Fatal("ResolveEventRange with a 91-day span: err = nil, want an error")
		}
	})

	t.Run("exactly 90 days is accepted", func(t *testing.T) {
		from := now.Add(-authevents.MaxEventRangeWindow)
		if _, _, err := authevents.ResolveEventRange(&from, &now, now); err != nil {
			t.Fatalf("ResolveEventRange with exactly a 90-day span: %v, want accepted", err)
		}
	})

	t.Run("from after to is rejected", func(t *testing.T) {
		from := now
		to := now.Add(-time.Hour)
		if _, _, err := authevents.ResolveEventRange(&from, &to, now); err == nil {
			t.Fatal("ResolveEventRange with from after to: err = nil, want an error")
		}
	})

	t.Run("a to in the future is accepted", func(t *testing.T) {
		future := now.Add(24 * time.Hour)
		_, to, err := authevents.ResolveEventRange(nil, &future, now)
		if err != nil {
			t.Fatalf("ResolveEventRange with a future to: %v, want accepted", err)
		}
		if !to.Equal(future) {
			t.Fatalf("to = %v, want %v", to, future)
		}
	})
}

func TestParseIP_RejectsGarbageKeepsValid(t *testing.T) {
	if got := authevents.ParseIP(""); got != "" {
		t.Fatalf("ParseIP(\"\") = %q, want empty", got)
	}
	if got := authevents.ParseIP("not-an-ip"); got != "" {
		t.Fatalf("ParseIP(garbage) = %q, want empty", got)
	}
	if got := authevents.ParseIP("203.0.113.5"); got != "203.0.113.5" {
		t.Fatalf("ParseIP(valid) = %q, want unchanged", got)
	}
}
