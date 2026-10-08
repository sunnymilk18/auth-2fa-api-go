package httpserver_test

// Covers the operator panel's own login (/admin/auth/*, /admin/accounts/*):
// the credentialed CORS carve-out only applying to the configured panel
// origin, the session cookie's shape, and RequireAdminAccess rejecting a
// valid cookie with no X-Admin-Panel header (the CSRF mitigation — see
// middleware.AdminPanelHeader's doc comment).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/metric/noop"

	"auth-2fa-api/internal/adminauth"
	"auth-2fa-api/internal/apiclient"
	"auth-2fa-api/internal/audit"
	"auth-2fa-api/internal/auth"
	"auth-2fa-api/internal/device"
	"auth-2fa-api/internal/httpserver"
	"auth-2fa-api/internal/middleware"
	"auth-2fa-api/internal/testutil"
	"auth-2fa-api/internal/user"
)

const testAdminPanelOrigin = "https://panel.example.com"

var testAdminTOTPKey = []byte("0123456789abcdef0123456789abcdef")

func newTestRouterWithAdminPanel(t *testing.T) (http.Handler, *adminauth.Service, *pgxpool.Pool, *redis.Client) {
	t.Helper()

	pool := testutil.PostgresPool(t)
	rdb := testutil.RedisClient(t)

	users := user.NewService(user.NewRepository(pool), 5, 15*time.Minute)
	tokens := auth.NewTokenManager(testutil.RSAKey(t), "test-key-1", "test-refresh-secret", 15*time.Minute, 7*24*time.Hour)
	apiClients := apiclient.NewService(apiclient.NewRepository(pool))
	accessRevocation := auth.NewAccessRevocationStore(rdb, 15*time.Minute)
	svc := auth.NewService(
		users, auth.NewOTPStore(rdb, 5*time.Minute, 3, 6), tokens, auth.NewRefreshRepository(pool),
		device.NewService(device.NewRepository(pool), 30*24*time.Hour), auth.NewPasswordResetStore(rdb, time.Hour, 3, 6),
		auth.NewEmailVerificationStore(rdb, 24*time.Hour, 3, 6),
		nil,
		auth.NewLoginAttemptLimiter(rdb, 3, 15*time.Minute),
		testutil.NewFakeMailer(), 5*time.Minute, 7*24*time.Hour, time.Hour, 24*time.Hour, time.Hour, nil, nil, nil, nil, nil, nil, testLogger(), accessRevocation, apiClients, "", nil,
	)
	handlers := auth.NewHandlers(svc)

	totpManager, err := auth.NewTOTPManager("test-issuer", testAdminTOTPKey)
	if err != nil {
		t.Fatalf("NewTOTPManager: %v", err)
	}
	adminAccounts := adminauth.NewService(
		adminauth.NewAccountRepository(pool),
		adminauth.NewSessionRepository(pool),
		adminauth.NewTOTPRotationStore(rdb),
		totpManager,
		auth.NewLoginAttemptLimiter(rdb, 3, time.Hour),
		time.Hour,
	)

	// A real audit.Service, backed by the same pool — not nil — so tests
	// that care (TestAdminAudit_*) can inspect what every action here
	// actually wrote, by constructing their own audit.Service against this
	// same pool and reading the same admin_audit_log table.
	auditSvc := audit.NewService(audit.NewRepository(pool), 365*24*time.Hour, noop.NewMeterProvider().Meter("test"), testLogger())

	r := httpserver.NewRouter(handlers, svc, tokens, accessRevocation, users, pool, rdb, apiClients,
		noop.NewMeterProvider().Meter("test"), testAdminToken, false, false, nil, nil,
		adminAccounts, testAdminPanelOrigin, true, time.Hour, auditSvc, testLogger())

	return r, adminAccounts, pool, rdb
}

func TestAdminPanel_CORS_OnlyAllowsConfiguredOrigin(t *testing.T) {
	r, _, _, _ := newTestRouterWithAdminPanel(t)

	// Preflight from the configured panel origin: allowed, credentialed.
	req := httptest.NewRequest(http.MethodOptions, "/admin/auth/login", nil)
	req.Header.Set("Origin", testAdminPanelOrigin)
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != testAdminPanelOrigin {
		t.Fatalf("Access-Control-Allow-Origin = %q, want %q", got, testAdminPanelOrigin)
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("Access-Control-Allow-Credentials = %q, want %q", got, "true")
	}

	// Preflight from any other origin: must not be reflected back.
	req2 := httptest.NewRequest(http.MethodOptions, "/admin/auth/login", nil)
	req2.Header.Set("Origin", "https://evil.example.com")
	req2.Header.Set("Access-Control-Request-Method", http.MethodPost)
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)

	if got := rec2.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Access-Control-Allow-Origin for an untrusted origin = %q, want empty", got)
	}
}

// TestAdminPanel_CORS_AllowsAdminPinHeader guards against the exact bug a
// second review caught: the panel's credentialed CORS branch listing every
// custom header the panel sends EXCEPT X-Admin-Pin — invisible to every
// other test here because they all call the router directly, never going
// through an actual browser preflight the way the panel's own JS fetch()
// would. A real browser refuses to even send a PIN-gated request if this
// preflight doesn't allow the header, which httptest can't otherwise catch.
func TestAdminPanel_CORS_AllowsAdminPinHeader(t *testing.T) {
	r, _, _, _ := newTestRouterWithAdminPanel(t)

	req := httptest.NewRequest(http.MethodOptions, "/admin/users/some-id/ban", nil)
	req.Header.Set("Origin", testAdminPanelOrigin)
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	req.Header.Set("Access-Control-Request-Headers", "x-admin-pin")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	allowed := rec.Header().Get("Access-Control-Allow-Headers")
	if !strings.Contains(strings.ToLower(allowed), "x-admin-pin") {
		t.Fatalf("Access-Control-Allow-Headers = %q, want it to include x-admin-pin", allowed)
	}
}

func TestAdminPanel_CORS_RestOfAPIStaysWildcardNoCredentials(t *testing.T) {
	r, _, _, _ := newTestRouterWithAdminPanel(t)

	// /health (outside /admin) must keep the original wildcard,
	// non-credentialed CORS regardless of the panel's own carve-out.
	req := httptest.NewRequest(http.MethodOptions, "/health", nil)
	req.Header.Set("Origin", "https://anything.example.com")
	req.Header.Set("Access-Control-Request-Method", http.MethodGet)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("Access-Control-Allow-Origin for /health = %q, want \"*\"", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Fatalf("Access-Control-Allow-Credentials for /health = %q, want empty", got)
	}
}

func TestAdminPanel_LoginSetsCookie_AndAccountsRouteRequiresPanelHeader(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)

	email := "panel-admin-" + testutil.UniqueSuffix(t) + "@example.com"
	account, otpauthURL, err := adminAccounts.CreateAccount(t.Context(), email, "correct-horse-battery", adminauth.RoleSuperAdmin)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM admin_accounts WHERE id = $1`, account.ID)
	})
	key, err := otp.NewKeyFromURL(otpauthURL)
	if err != nil {
		t.Fatalf("parsing otpauth url: %v", err)
	}
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("generating totp code: %v", err)
	}

	body, _ := json.Marshal(map[string]string{"email": email, "password": "correct-horse-battery", "totp_code": code})
	req := httptest.NewRequest(http.MethodPost, "/admin/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("login status = %d, body = %s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "admin_session" {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatal("login response did not set an admin_session cookie")
	}
	if !sessionCookie.HttpOnly || !sessionCookie.Secure {
		t.Fatalf("admin_session cookie = %+v, want HttpOnly+Secure", sessionCookie)
	}

	// With the cookie but WITHOUT the anti-CSRF header: rejected.
	req2 := httptest.NewRequest(http.MethodGet, "/admin/accounts", nil)
	req2.AddCookie(sessionCookie)
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("GET /admin/accounts with cookie but no X-Admin-Panel header: status = %d, want 401", rec2.Code)
	}

	// With the cookie AND the header: succeeds and lists the account just
	// created.
	req3 := httptest.NewRequest(http.MethodGet, "/admin/accounts", nil)
	req3.AddCookie(sessionCookie)
	req3.Header.Set("X-Admin-Panel", "1")
	rec3 := httptest.NewRecorder()
	r.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("GET /admin/accounts with cookie + header: status = %d, body = %s", rec3.Code, rec3.Body.String())
	}
	var listResp struct {
		Accounts []struct {
			ID string `json:"id"`
		} `json:"accounts"`
	}
	if err := json.Unmarshal(rec3.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decoding list response: %v", err)
	}
	found := false
	for _, a := range listResp.Accounts {
		if a.ID == account.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("ListAccounts did not include the created account %s: %+v", account.ID, listResp.Accounts)
	}
}

// loginAsAdmin logs in via the real HTTP endpoint and returns the
// resulting session cookie — shared by tests that need a cookie for a
// specific role rather than asserting on the login response itself.
func loginAsAdmin(t *testing.T, r http.Handler, email, password, totpSecret string) *http.Cookie {
	t.Helper()

	code, err := totp.GenerateCode(totpSecret, time.Now())
	if err != nil {
		t.Fatalf("generating totp code: %v", err)
	}
	body, _ := json.Marshal(map[string]string{"email": email, "password": password, "totp_code": code})
	req := httptest.NewRequest(http.MethodPost, "/admin/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login status = %d, body = %s", rec.Code, rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "admin_session" {
			return c
		}
	}
	t.Fatal("login response did not set an admin_session cookie")
	return nil
}

func adminPanelRequest(r http.Handler, method, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	return adminPanelRequestWithBody(r, method, path, cookie, nil)
}

func adminPanelRequestWithBody(r http.Handler, method, path string, cookie *http.Cookie, body any) *httptest.ResponseRecorder {
	return adminPanelRequestWithBodyAndPin(r, method, path, cookie, body, "")
}

// adminPanelRequestWithBodyAndPin is adminPanelRequestWithBody plus an
// X-Admin-Pin header — needed by any test exercising a PIN-gated route
// (see router.go's requireAdminPin wiring) for anything past the gate
// itself; pin == "" omits the header entirely, same as
// adminPanelRequestWithBody.
func adminPanelRequestWithBodyAndPin(r http.Handler, method, path string, cookie *http.Cookie, body any, pin string) *httptest.ResponseRecorder {
	var reader *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	req.Header.Set("X-Admin-Panel", "1")
	if pin != "" {
		req.Header.Set(httpserver.AdminPinHeader, pin)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// mustSetPin creates email's PIN via the real self-service endpoint (not
// a direct DB write) — proves the whole SetPin flow, not just that the
// column got written. t.Fatal on any non-204.
func mustSetPin(t *testing.T, r http.Handler, cookie *http.Cookie, password, pin string) {
	t.Helper()
	rec := adminPanelRequestWithBody(r, http.MethodPut, "/admin/auth/pin", cookie, map[string]string{"password": password, "pin": pin})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("setting pin: status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

// A regular ("admin") role can use the day-to-day moderation routes but
// gets 403 on every superadmin-only one — see adminauth.Role's doc
// comment for the full split.
func TestAdminPanel_RegularAdminCannotReachSuperAdminRoutes(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)

	email := "regular-admin-" + testutil.UniqueSuffix(t) + "@example.com"
	account, otpauthURL, err := adminAccounts.CreateAccount(t.Context(), email, "correct-horse-battery", adminauth.RoleAdmin)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM admin_accounts WHERE id = $1`, account.ID)
	})
	key, err := otp.NewKeyFromURL(otpauthURL)
	if err != nil {
		t.Fatalf("parsing otpauth url: %v", err)
	}

	cookie := loginAsAdmin(t, r, email, "correct-horse-battery", key.Secret())

	for _, path := range []string{"/admin/accounts", "/admin/clients", "/admin/blacklist/allowlist"} {
		if rec := adminPanelRequest(r, http.MethodGet, path, cookie); rec.Code != http.StatusForbidden {
			t.Fatalf("GET %s as regular admin: status = %d, want 403", path, rec.Code)
		}
	}

	// But the day-to-day moderation routes stay reachable.
	if rec := adminPanelRequest(r, http.MethodGet, "/admin/users", cookie); rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/users as regular admin: status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

// GET /admin/auth/me is what the panel calls on load to restore "who am I,
// what role" — reachable by any valid session (not superadmin-only), and
// reports the actual role so the UI can hide superadmin-only controls for
// a regular admin.
func TestAdminPanel_Me_ReportsActorAndRole(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)

	email := "me-admin-" + testutil.UniqueSuffix(t) + "@example.com"
	account, otpauthURL, err := adminAccounts.CreateAccount(t.Context(), email, "correct-horse-battery", adminauth.RoleAdmin)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM admin_accounts WHERE id = $1`, account.ID)
	})
	key, err := otp.NewKeyFromURL(otpauthURL)
	if err != nil {
		t.Fatalf("parsing otpauth url: %v", err)
	}

	cookie := loginAsAdmin(t, r, email, "correct-horse-battery", key.Secret())

	rec := adminPanelRequest(r, http.MethodGet, "/admin/auth/me", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/auth/me: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Actor string `json:"actor"`
		Role  string `json:"role"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding /admin/auth/me response: %v", err)
	}
	if resp.Actor != email || resp.Role != string(adminauth.RoleAdmin) {
		t.Fatalf("GET /admin/auth/me = %+v, want actor=%q role=%q", resp, email, adminauth.RoleAdmin)
	}
}

// GET /admin/blacklist is the operator's unscoped view across every
// tenant — unlike /admin/blacklist/allowlist, reachable by a regular
// admin too, not just superadmin (see adminauth.Role's doc comment on
// which actions are superadmin-only).
func TestAdminPanel_Blacklist_ListsAcrossTenants(t *testing.T) {
	r, adminAccounts, pool, rdb := newTestRouterWithAdminPanel(t)

	// Real api_clients rows, so api_client_name can actually resolve —
	// unlike a made-up literal owner id, which FindByIDs would correctly
	// find nothing for.
	clientA, _ := testutil.NewAPIClient(t, pool)
	clientB, _ := testutil.NewAPIClient(t, pool)

	// A single strike is enough to ban, so each RecordViolation call below
	// produces one ban directly — no need to drive it through the rate
	// limiter.
	bl := middleware.NewBlacklist(rdb, 1, time.Hour, []time.Duration{time.Hour}, 30*24*time.Hour, nil)
	ipA, ipB, ipNoOwner := "203.0.113.10", "203.0.113.20", "203.0.113.30"
	if err := bl.RecordViolation(t.Context(), ipA, clientA.ID); err != nil {
		t.Fatalf("RecordViolation(clientA): %v", err)
	}
	if err := bl.RecordViolation(t.Context(), ipB, clientB.ID); err != nil {
		t.Fatalf("RecordViolation(clientB): %v", err)
	}
	// No resolvable owner at all (e.g. the triggering request had no
	// api_client_id in context) — api_client_name must come back "", not
	// error the whole listing out.
	if err := bl.RecordViolation(t.Context(), ipNoOwner, ""); err != nil {
		t.Fatalf("RecordViolation(no owner): %v", err)
	}

	email := "blacklist-admin-" + testutil.UniqueSuffix(t) + "@example.com"
	account, otpauthURL, err := adminAccounts.CreateAccount(t.Context(), email, "correct-horse-battery", adminauth.RoleAdmin)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM admin_accounts WHERE id = $1`, account.ID)
	})
	key, err := otp.NewKeyFromURL(otpauthURL)
	if err != nil {
		t.Fatalf("parsing otpauth url: %v", err)
	}
	cookie := loginAsAdmin(t, r, email, "correct-horse-battery", key.Secret())

	// A regular admin can see it — this isn't superadmin-only.
	rec := adminPanelRequest(r, http.MethodGet, "/admin/blacklist", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/blacklist as regular admin: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Bans []struct {
			IP            string `json:"ip"`
			APIClientID   string `json:"api_client_id"`
			APIClientName string `json:"api_client_name"`
		} `json:"bans"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding /admin/blacklist response: %v", err)
	}
	byIP := map[string]struct {
		id, name string
	}{}
	for _, b := range resp.Bans {
		byIP[b.IP] = struct{ id, name string }{b.APIClientID, b.APIClientName}
	}
	if byIP[ipA].id != clientA.ID || byIP[ipA].name != clientA.Name {
		t.Fatalf("ban for %s = (id=%q, name=%q), want (id=%q, name=%q) (full list: %+v)",
			ipA, byIP[ipA].id, byIP[ipA].name, clientA.ID, clientA.Name, resp.Bans)
	}
	if byIP[ipB].id != clientB.ID || byIP[ipB].name != clientB.Name {
		t.Fatalf("ban for %s = (id=%q, name=%q), want (id=%q, name=%q) (full list: %+v)",
			ipB, byIP[ipB].id, byIP[ipB].name, clientB.ID, clientB.Name, resp.Bans)
	}
	if byIP[ipNoOwner].id != "" || byIP[ipNoOwner].name != "" {
		t.Fatalf("ban for %s (no owner) = (id=%q, name=%q), want both empty (full list: %+v)",
			ipNoOwner, byIP[ipNoOwner].id, byIP[ipNoOwner].name, resp.Bans)
	}

	// No session at all: rejected.
	req := httptest.NewRequest(http.MethodGet, "/admin/blacklist", nil)
	req.Header.Set("X-Admin-Panel", "1")
	recNoAuth := httptest.NewRecorder()
	r.ServeHTTP(recNoAuth, req)
	if recNoAuth.Code != http.StatusUnauthorized {
		t.Fatalf("GET /admin/blacklist with no session: status = %d, want 401", recNoAuth.Code)
	}
}

// POST /admin/accounts/{id}/reactivate brings a revoked account back with
// a fresh password (and, server-side, a fresh TOTP secret the response's
// otpauth_url carries) — superadmin-only, same tier as CreateAccount and
// RevokeAccount. The credential-level guarantees (new creds work, old
// ones don't) are covered by TestService_ReactivateAccount_* in
// adminauth's own test file; this one is about the HTTP wiring: who can
// call it and what each failure mode returns.
func TestAdminPanel_Reactivate(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)
	cleanupAccount := func(id string) {
		t.Cleanup(func() {
			_, _ = pool.Exec(context.Background(), `DELETE FROM admin_accounts WHERE id = $1`, id)
		})
	}

	superEmail := "reactivate-super-" + testutil.UniqueSuffix(t) + "@example.com"
	superAccount, superURL, err := adminAccounts.CreateAccount(t.Context(), superEmail, "correct-horse-battery", adminauth.RoleSuperAdmin)
	if err != nil {
		t.Fatalf("CreateAccount(superadmin): %v", err)
	}
	cleanupAccount(superAccount.ID)
	superKey, err := otp.NewKeyFromURL(superURL)
	if err != nil {
		t.Fatalf("parsing otpauth url: %v", err)
	}
	superCookie := loginAsAdmin(t, r, superEmail, "correct-horse-battery", superKey.Secret())
	mustSetPin(t, r, superCookie, "correct-horse-battery", "123456")
	const superPin = "123456"

	regularEmail := "reactivate-regular-" + testutil.UniqueSuffix(t) + "@example.com"
	regularAccount, regularURL, err := adminAccounts.CreateAccount(t.Context(), regularEmail, "correct-horse-battery", adminauth.RoleAdmin)
	if err != nil {
		t.Fatalf("CreateAccount(regular): %v", err)
	}
	cleanupAccount(regularAccount.ID)
	regularKey, err := otp.NewKeyFromURL(regularURL)
	if err != nil {
		t.Fatalf("parsing otpauth url: %v", err)
	}
	regularCookie := loginAsAdmin(t, r, regularEmail, "correct-horse-battery", regularKey.Secret())

	targetEmail := "reactivate-target-" + testutil.UniqueSuffix(t) + "@example.com"
	target, _, err := adminAccounts.CreateAccount(t.Context(), targetEmail, "old-password-1", adminauth.RoleAdmin)
	if err != nil {
		t.Fatalf("CreateAccount(target): %v", err)
	}
	cleanupAccount(target.ID)
	if err := adminAccounts.RevokeAccount(t.Context(), "", target.ID); err != nil {
		t.Fatalf("RevokeAccount(target): %v", err)
	}

	path := "/admin/accounts/" + target.ID + "/reactivate"

	// A regular admin (not superadmin) is forbidden — doesn't touch the
	// account.
	if rec := adminPanelRequestWithBody(r, http.MethodPost, path, regularCookie, map[string]string{"password": "new-password-1"}); rec.Code != http.StatusForbidden {
		t.Fatalf("reactivate as regular admin: status = %d, want 403", rec.Code)
	}

	// No session at all.
	if rec := adminPanelRequestWithBody(r, http.MethodPost, path, nil, map[string]string{"password": "new-password-1"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("reactivate with no session: status = %d, want 401", rec.Code)
	}

	// No PIN header at all — blocked before the handler even sees the
	// body, see requireAdminPin.
	if rec := adminPanelRequestWithBody(r, http.MethodPost, path, superCookie, map[string]string{"password": "new-password-1"}); rec.Code != http.StatusForbidden {
		t.Fatalf("reactivate with no X-Admin-Pin: status = %d, want 403", rec.Code)
	}

	// Too-short password.
	if rec := adminPanelRequestWithBodyAndPin(r, http.MethodPost, path, superCookie, map[string]string{"password": "short"}, superPin); rec.Code != http.StatusBadRequest {
		t.Fatalf("reactivate with short password: status = %d, want 400", rec.Code)
	}

	// Unknown account id.
	unknownPath := "/admin/accounts/00000000-0000-0000-0000-000000000000/reactivate"
	if rec := adminPanelRequestWithBodyAndPin(r, http.MethodPost, unknownPath, superCookie, map[string]string{"password": "new-password-1"}, superPin); rec.Code != http.StatusNotFound {
		t.Fatalf("reactivate unknown account: status = %d, want 404", rec.Code)
	}

	// The real reactivation, as superadmin.
	rec := adminPanelRequestWithBodyAndPin(r, http.MethodPost, path, superCookie, map[string]string{"password": "new-password-1"}, superPin)
	if rec.Code != http.StatusOK {
		t.Fatalf("reactivate as superadmin: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		ID         string `json:"id"`
		Email      string `json:"email"`
		Role       string `json:"role"`
		OTPAuthURL string `json:"otpauth_url"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding reactivate response: %v", err)
	}
	if resp.ID != target.ID || resp.Email != targetEmail || resp.Role != string(adminauth.RoleAdmin) || resp.OTPAuthURL == "" {
		t.Fatalf("reactivate response = %+v, want id=%q email=%q role=%q with a non-empty otpauth_url", resp, target.ID, targetEmail, adminauth.RoleAdmin)
	}

	// Reactivating an already-active account is refused.
	if rec := adminPanelRequestWithBodyAndPin(r, http.MethodPost, path, superCookie, map[string]string{"password": "another-password-1"}, superPin); rec.Code != http.StatusConflict {
		t.Fatalf("reactivate already-active account: status = %d, want 409", rec.Code)
	}
}

// POST /admin/auth/password — the key contract point is the status code
// for a wrong current password: the panel treats 401 as "the session
// ended" and redirects to login, so a wrong password here must NOT be
// 401 (see adminauth.ErrCurrentPasswordIncorrect's doc comment).
func TestAdminPanel_ChangePassword(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)

	email := "selfservice-pw-" + testutil.UniqueSuffix(t) + "@example.com"
	account, otpauthURL, err := adminAccounts.CreateAccount(t.Context(), email, "old-password-1", adminauth.RoleAdmin)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM admin_accounts WHERE id = $1`, account.ID)
	})
	key, err := otp.NewKeyFromURL(otpauthURL)
	if err != nil {
		t.Fatalf("parsing otpauth url: %v", err)
	}

	currentCookie := loginAsAdmin(t, r, email, "old-password-1", key.Secret())
	otherCookie := loginAsAdmin(t, r, email, "old-password-1", key.Secret())
	mustSetPin(t, r, currentCookie, "old-password-1", "123456")
	const pin = "123456"

	// No session at all (the shared X-Admin-Token path) — refused, there's
	// no "own account" to act on.
	noSessionReq := httptest.NewRequest(http.MethodPost, "/admin/auth/password", bytes.NewReader(nil))
	noSessionReq.Header.Set("X-Admin-Token", testAdminToken)
	noSessionReq.Header.Set("Content-Type", "application/json")
	noSessionRec := httptest.NewRecorder()
	r.ServeHTTP(noSessionRec, noSessionReq)
	if noSessionRec.Code != http.StatusBadRequest {
		t.Fatalf("change password with the shared token, no session: status = %d, want 400", noSessionRec.Code)
	}

	// No X-Admin-Pin at all — blocked before the handler even sees the
	// body.
	if rec := adminPanelRequestWithBody(r, http.MethodPost, "/admin/auth/password", currentCookie,
		map[string]string{"current_password": "old-password-1", "new_password": "new-password-1"}); rec.Code != http.StatusForbidden {
		t.Fatalf("change password with no X-Admin-Pin: status = %d, want 403", rec.Code)
	}

	// Wrong current password — 403, not 401 (see this test's doc comment).
	wrongRec := adminPanelRequestWithBodyAndPin(r, http.MethodPost, "/admin/auth/password", currentCookie,
		map[string]string{"current_password": "not-the-password", "new_password": "new-password-1"}, pin)
	if wrongRec.Code != http.StatusForbidden {
		t.Fatalf("change password with wrong current password: status = %d, want 403", wrongRec.Code)
	}
	var errBody struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(wrongRec.Body.Bytes(), &errBody); err != nil || errBody.Error == "" {
		t.Fatalf("decoding error body: %v, body = %s", err, wrongRec.Body.String())
	}

	// Too-short new password.
	if rec := adminPanelRequestWithBodyAndPin(r, http.MethodPost, "/admin/auth/password", currentCookie,
		map[string]string{"current_password": "old-password-1", "new_password": "short"}, pin); rec.Code != http.StatusBadRequest {
		t.Fatalf("change password with a too-short new password: status = %d, want 400", rec.Code)
	}

	// The real change.
	okRec := adminPanelRequestWithBodyAndPin(r, http.MethodPost, "/admin/auth/password", currentCookie,
		map[string]string{"current_password": "old-password-1", "new_password": "new-password-1"}, pin)
	if okRec.Code != http.StatusNoContent {
		t.Fatalf("change password: status = %d, body = %s, want 204", okRec.Code, okRec.Body.String())
	}

	// The calling session still works; the other one doesn't.
	if rec := adminPanelRequest(r, http.MethodGet, "/admin/auth/me", currentCookie); rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/auth/me with the current session after password change: status = %d, want 200", rec.Code)
	}
	if rec := adminPanelRequest(r, http.MethodGet, "/admin/auth/me", otherCookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /admin/auth/me with the OTHER session after password change: status = %d, want 401 (revoked)", rec.Code)
	}
}

// POST /admin/auth/totp/rotate + /confirm — the two-step flow, plus the
// same 403-not-401 contract point as ChangePassword for a wrong password
// or a wrong confirmation code, and 404 for confirming with nothing
// pending.
func TestAdminPanel_RotateTOTP(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)

	email := "selfservice-totp-" + testutil.UniqueSuffix(t) + "@example.com"
	account, otpauthURL, err := adminAccounts.CreateAccount(t.Context(), email, "correct-horse-battery", adminauth.RoleAdmin)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM admin_accounts WHERE id = $1`, account.ID)
	})
	oldKey, err := otp.NewKeyFromURL(otpauthURL)
	if err != nil {
		t.Fatalf("parsing otpauth url: %v", err)
	}

	currentCookie := loginAsAdmin(t, r, email, "correct-horse-battery", oldKey.Secret())
	otherCookie := loginAsAdmin(t, r, email, "correct-horse-battery", oldKey.Secret())
	mustSetPin(t, r, currentCookie, "correct-horse-battery", "123456")
	const pin = "123456"

	// No X-Admin-Pin at all — blocked before the handler even looks for a
	// pending rotation.
	if rec := adminPanelRequestWithBody(r, http.MethodPost, "/admin/auth/totp/rotate/confirm", currentCookie,
		map[string]string{"code": "000000"}); rec.Code != http.StatusForbidden {
		t.Fatalf("confirm with no X-Admin-Pin: status = %d, want 403", rec.Code)
	}

	// Confirming before ever starting a rotation: nothing pending.
	if rec := adminPanelRequestWithBodyAndPin(r, http.MethodPost, "/admin/auth/totp/rotate/confirm", currentCookie,
		map[string]string{"code": "000000"}, pin); rec.Code != http.StatusNotFound {
		t.Fatalf("confirm with nothing pending: status = %d, want 404", rec.Code)
	}

	// Wrong password on step one — 403, not 401.
	if rec := adminPanelRequestWithBody(r, http.MethodPost, "/admin/auth/totp/rotate", currentCookie,
		map[string]string{"password": "not-the-password"}); rec.Code != http.StatusForbidden {
		t.Fatalf("rotate with wrong password: status = %d, want 403", rec.Code)
	}

	// Step one, for real: returns a fresh otpauth_url, doesn't touch the
	// active secret yet.
	startRec := adminPanelRequestWithBody(r, http.MethodPost, "/admin/auth/totp/rotate", currentCookie,
		map[string]string{"password": "correct-horse-battery"})
	if startRec.Code != http.StatusOK {
		t.Fatalf("rotate step one: status = %d, body = %s", startRec.Code, startRec.Body.String())
	}
	var startResp struct {
		OTPAuthURL string `json:"otpauth_url"`
	}
	if err := json.Unmarshal(startRec.Body.Bytes(), &startResp); err != nil || startResp.OTPAuthURL == "" {
		t.Fatalf("decoding rotate step-one response: %v, body = %s", err, startRec.Body.String())
	}
	newKey, err := otp.NewKeyFromURL(startResp.OTPAuthURL)
	if err != nil {
		t.Fatalf("parsing new otpauth url: %v", err)
	}
	if newKey.Secret() == oldKey.Secret() {
		t.Fatal("rotate step one returned the account's existing secret, want a freshly generated one")
	}

	// The old secret still logs in — nothing active yet.
	if _, err := loginExpectingOK(t, r, email, "correct-horse-battery", oldKey.Secret()); err != nil {
		t.Fatalf("login with the old (still active) secret before confirming: %v", err)
	}

	// Wrong code on step two — 403, not 401 — and the pending rotation
	// must survive for a retry.
	if rec := adminPanelRequestWithBodyAndPin(r, http.MethodPost, "/admin/auth/totp/rotate/confirm", currentCookie,
		map[string]string{"code": "000000"}, pin); rec.Code != http.StatusForbidden {
		t.Fatalf("confirm with wrong code: status = %d, want 403", rec.Code)
	}

	newCode, err := totp.GenerateCode(newKey.Secret(), time.Now())
	if err != nil {
		t.Fatalf("generating totp code: %v", err)
	}
	confirmRec := adminPanelRequestWithBodyAndPin(r, http.MethodPost, "/admin/auth/totp/rotate/confirm", currentCookie,
		map[string]string{"code": newCode}, pin)
	if confirmRec.Code != http.StatusNoContent {
		t.Fatalf("confirm rotation: status = %d, body = %s, want 204", confirmRec.Code, confirmRec.Body.String())
	}

	// The calling session survives; the other one is revoked.
	if rec := adminPanelRequest(r, http.MethodGet, "/admin/auth/me", currentCookie); rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/auth/me with the current session after confirming rotation: status = %d, want 200", rec.Code)
	}
	if rec := adminPanelRequest(r, http.MethodGet, "/admin/auth/me", otherCookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /admin/auth/me with the OTHER session after confirming rotation: status = %d, want 401 (revoked)", rec.Code)
	}
}

// loginExpectingOK is loginAsAdmin without the t.Fatalf on failure — used
// where the test itself wants to report the failure with its own message.
func loginExpectingOK(t *testing.T, r http.Handler, email, password, totpSecret string) (*http.Cookie, error) {
	t.Helper()
	code, err := totp.GenerateCode(totpSecret, time.Now())
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]string{"email": email, "password": password, "totp_code": code})
	req := httptest.NewRequest(http.MethodPost, "/admin/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		return nil, fmt.Errorf("login status = %d, body = %s", rec.Code, rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "admin_session" {
			return c, nil
		}
	}
	return nil, fmt.Errorf("login response did not set an admin_session cookie")
}
