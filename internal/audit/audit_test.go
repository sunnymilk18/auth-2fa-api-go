package audit_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/metric/noop"

	"auth-2fa-api/internal/audit"
	"auth-2fa-api/internal/middleware"
	"auth-2fa-api/internal/testutil"
)

func newTestService(t *testing.T) (*audit.Service, *pgxpool.Pool) {
	t.Helper()
	pool := testutil.PostgresPool(t)
	repo := audit.NewRepository(pool)
	svc := audit.NewService(repo, 365*24*time.Hour, noop.NewMeterProvider().Meter("test"), nil)
	return svc, pool
}

// cleanupActor deletes every row Log wrote for actorEmail — admin_audit_log
// has no foreign key to clean up via cascade, so tests clean up by actor
// instead, same idea as testutil.NewAPIClient's own cleanup.
func cleanupActor(t *testing.T, pool *pgxpool.Pool, actorEmail string) {
	t.Helper()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM admin_audit_log WHERE actor_email = $1`, actorEmail)
	})
}

// resolveRemoteIP mirrors middleware's own resolveClientIP test helper
// (clientip_test.go) but drives audit.RemoteIP instead of
// middleware.ClientIP directly — this is the external audit_test package,
// so it can import internal/middleware to wire the real resolver without
// creating any cycle in the production build (see audit.
// SetClientIPResolver's own doc comment for why audit.go itself never
// imports internal/middleware). Resets both pieces of shared package state
// afterward so nothing leaks into an unrelated test.
func resolveRemoteIP(t *testing.T, cidrs []string, remoteAddr, xForwardedFor string) string {
	t.Helper()
	middleware.ValidateTrustedProxyCIDRs(strings.Join(cidrs, ","))
	audit.SetClientIPResolver(middleware.ClientIP)
	t.Cleanup(func() {
		middleware.ValidateTrustedProxyCIDRs("")
		audit.SetClientIPResolver(nil)
	})

	var got string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = audit.RemoteIP(r)
	})

	var wrapped http.Handler = handler
	if len(cidrs) > 0 {
		wrapped = chimw.ClientIPFromXFF(cidrs...)(handler)
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remoteAddr
	if xForwardedFor != "" {
		r.Header.Set("X-Forwarded-For", xForwardedFor)
	}
	wrapped.ServeHTTP(httptest.NewRecorder(), r)
	return got
}

// Without a resolver configured (the zero value — no test or production
// caller ever called SetClientIPResolver), RemoteIP must keep behaving the
// way it always has: the bare RemoteAddr, no header ever consulted.
func TestRemoteIP_NoResolverConfigured_FallsBackToRemoteAddr(t *testing.T) {
	t.Cleanup(func() { audit.SetClientIPResolver(nil) })

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.5:12345"
	r.Header.Set("X-Forwarded-For", "198.51.100.9")
	if got := audit.RemoteIP(r); got != "203.0.113.5" {
		t.Fatalf("RemoteIP() = %q, want %q (no resolver configured, header must be ignored)", got, "203.0.113.5")
	}
}

// The scenario this whole change exists for: a request that really did
// arrive through Traefik (RemoteAddr inside TRUSTED_PROXY_CIDRS) must log
// the operator's real IP from X-Forwarded-For, not Traefik's own address.
func TestRemoteIP_TrustedProxyResolverConfigured_UsesForwardedFor(t *testing.T) {
	got := resolveRemoteIP(t, []string{"10.0.1.0/24"}, "10.0.1.4:54321", "152.172.68.141")
	if got != "152.172.68.141" {
		t.Fatalf("RemoteIP() = %q, want %q (RemoteAddr is inside TRUSTED_PROXY_CIDRS)", got, "152.172.68.141")
	}
}

// A connection that doesn't genuinely originate from a trusted network
// must never have its logged IP overridden by a header the caller could
// have forged — RemoteAddr wins regardless of what X-Forwarded-For says.
func TestRemoteIP_UntrustedRemoteAddr_IgnoresForgedForwardedFor(t *testing.T) {
	got := resolveRemoteIP(t, []string{"10.0.1.0/24"}, "198.51.100.9:12345", "1.2.3.4")
	if got != "198.51.100.9" {
		t.Fatalf("RemoteIP() = %q, want %q (RemoteAddr isn't a trusted proxy, header must be ignored)", got, "198.51.100.9")
	}
}

func TestService_LogAndList_RoundTrip(t *testing.T) {
	svc, pool := newTestService(t)
	ctx := t.Context()

	actor := "auditor-" + testutil.UniqueSuffix(t) + "@example.com"
	cleanupActor(t, pool, actor)

	svc.Log(ctx, audit.Entry{
		ActorEmail: actor, ActorRole: "admin", Action: audit.ActionUserBan,
		TargetType: audit.TargetTypeUser, TargetID: "user-123", TargetLabel: "someone@example.com",
		ActorIP: "203.0.113.5",
	})

	entries, total, page, pageSize, err := svc.List(ctx, audit.Filter{Actor: actor}, 0, 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 1 || len(entries) != 1 {
		t.Fatalf("List = %d entries (total=%d), want exactly 1", len(entries), total)
	}
	if page != 1 || pageSize != 50 {
		t.Fatalf("List page/pageSize = %d/%d, want 1/50 (defaults)", page, pageSize)
	}
	e := entries[0]
	if e.ActorEmail != actor || e.ActorRole != "admin" || e.Action != audit.ActionUserBan ||
		e.TargetType != audit.TargetTypeUser || e.TargetID != "user-123" || e.TargetLabel != "someone@example.com" ||
		e.ActorIP != "203.0.113.5" || e.ID == "" || e.CreatedAt.IsZero() {
		t.Fatalf("logged entry round-tripped as %+v, fields don't match what was logged", e)
	}
}

func TestService_List_FiltersByActorAndAction(t *testing.T) {
	svc, pool := newTestService(t)
	ctx := t.Context()

	actorA := "actor-a-" + testutil.UniqueSuffix(t) + "@example.com"
	actorB := "actor-b-" + testutil.UniqueSuffix(t) + "@example.com"
	cleanupActor(t, pool, actorA)
	cleanupActor(t, pool, actorB)

	svc.Log(ctx, audit.Entry{ActorEmail: actorA, Action: audit.ActionUserBan, TargetID: "u1"})
	svc.Log(ctx, audit.Entry{ActorEmail: actorA, Action: audit.ActionUserUnban, TargetID: "u1"})
	svc.Log(ctx, audit.Entry{ActorEmail: actorB, Action: audit.ActionUserBan, TargetID: "u2"})

	// By actor alone: both of actorA's entries, none of actorB's.
	entries, total, _, _, err := svc.List(ctx, audit.Filter{Actor: actorA}, 1, 50)
	if err != nil {
		t.Fatalf("List(actor=A): %v", err)
	}
	if total != 2 {
		t.Fatalf("List(actor=A) total = %d, want 2", total)
	}
	for _, e := range entries {
		if e.ActorEmail != actorA {
			t.Fatalf("List(actor=A) returned an entry from %q", e.ActorEmail)
		}
	}

	// By actor + action together.
	entries, total, _, _, err = svc.List(ctx, audit.Filter{Actor: actorA, Action: audit.ActionUserBan}, 1, 50)
	if err != nil {
		t.Fatalf("List(actor=A, action=ban): %v", err)
	}
	if total != 1 || entries[0].Action != audit.ActionUserBan {
		t.Fatalf("List(actor=A, action=ban) = %+v, want exactly one ban entry", entries)
	}
}

func TestService_List_FiltersByDateRange(t *testing.T) {
	svc, pool := newTestService(t)
	ctx := t.Context()

	actor := "daterange-" + testutil.UniqueSuffix(t) + "@example.com"
	cleanupActor(t, pool, actor)

	svc.Log(ctx, audit.Entry{ActorEmail: actor, Action: audit.ActionUserBan})

	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour)

	// A window that starts after the entry: excluded.
	_, total, _, _, err := svc.List(ctx, audit.Filter{Actor: actor, From: &future}, 1, 50)
	if err != nil {
		t.Fatalf("List(from=future): %v", err)
	}
	if total != 0 {
		t.Fatalf("List(from=future) total = %d, want 0", total)
	}

	// A window that already covers it: included.
	_, total, _, _, err = svc.List(ctx, audit.Filter{Actor: actor, From: &past}, 1, 50)
	if err != nil {
		t.Fatalf("List(from=past): %v", err)
	}
	if total != 1 {
		t.Fatalf("List(from=past) total = %d, want 1", total)
	}
}

func TestService_List_MostRecentFirst(t *testing.T) {
	svc, pool := newTestService(t)
	ctx := t.Context()

	actor := "ordering-" + testutil.UniqueSuffix(t) + "@example.com"
	cleanupActor(t, pool, actor)

	svc.Log(ctx, audit.Entry{ActorEmail: actor, Action: "first"})
	time.Sleep(10 * time.Millisecond)
	svc.Log(ctx, audit.Entry{ActorEmail: actor, Action: "second"})

	entries, _, _, _, err := svc.List(ctx, audit.Filter{Actor: actor}, 1, 50)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 2 || entries[0].Action != "second" || entries[1].Action != "first" {
		t.Fatalf("List order = %+v, want [second, first] (most recent first)", entries)
	}
}

func TestService_DeleteExpired_RemovesOnlyEntriesPastRetention(t *testing.T) {
	pool := testutil.PostgresPool(t)
	repo := audit.NewRepository(pool)
	svc := audit.NewService(repo, time.Hour, noop.NewMeterProvider().Meter("test"), nil)
	ctx := t.Context()

	recentActor := "recent-" + testutil.UniqueSuffix(t) + "@example.com"
	oldActor := "old-" + testutil.UniqueSuffix(t) + "@example.com"
	cleanupActor(t, pool, recentActor)
	cleanupActor(t, pool, oldActor)

	svc.Log(ctx, audit.Entry{ActorEmail: recentActor, Action: "recent"})
	svc.Log(ctx, audit.Entry{ActorEmail: oldActor, Action: "old"})
	// Backdate the "old" entry past the 1h retention window directly —
	// there's no public API to log with an arbitrary created_at, and that's
	// the point (every real entry is stamped "now" by Postgres itself).
	if _, err := pool.Exec(ctx, `UPDATE admin_audit_log SET created_at = now() - interval '2 hours' WHERE actor_email = $1`, oldActor); err != nil {
		t.Fatalf("backdating old entry: %v", err)
	}

	n, err := svc.DeleteExpired(ctx)
	if err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}
	if n < 1 {
		t.Fatalf("DeleteExpired deleted %d rows, want at least 1", n)
	}

	_, total, _, _, err := svc.List(ctx, audit.Filter{Actor: oldActor}, 1, 50)
	if err != nil {
		t.Fatalf("List(oldActor) after cleanup: %v", err)
	}
	if total != 0 {
		t.Fatal("the old entry survived DeleteExpired, want it gone")
	}

	_, total, _, _, err = svc.List(ctx, audit.Filter{Actor: recentActor}, 1, 50)
	if err != nil {
		t.Fatalf("List(recentActor) after cleanup: %v", err)
	}
	if total != 1 {
		t.Fatal("the recent entry was deleted too, want it to survive")
	}
}

// Log must never panic when called on a nil *Service — see its own doc
// comment: this lets a caller built once at startup (possibly nil in a
// test that doesn't care about auditing) be passed through everywhere
// without every call site needing a nil check of its own.
func TestService_Log_NilSafe(t *testing.T) {
	var svc *audit.Service
	svc.Log(t.Context(), audit.Entry{ActorEmail: "whoever", Action: "whatever"})
}
