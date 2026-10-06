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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/metric/noop"

	"auth-2fa-api/internal/adminauth"
	"auth-2fa-api/internal/apiclient"
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
		totpManager,
		auth.NewLoginAttemptLimiter(rdb, 3, time.Hour),
		time.Hour,
	)

	r := httpserver.NewRouter(handlers, svc, tokens, accessRevocation, users, pool, rdb, apiClients,
		noop.NewMeterProvider().Meter("test"), testAdminToken, false, false, nil, nil,
		adminAccounts, testAdminPanelOrigin, true, time.Hour, testLogger())

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
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
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

	// A single strike is enough to ban, so each RecordViolation call below
	// produces one ban directly — no need to drive it through the rate
	// limiter.
	bl := middleware.NewBlacklist(rdb, 1, time.Hour, []time.Duration{time.Hour}, 30*24*time.Hour, nil)
	ipA, ipB := "203.0.113.10", "203.0.113.20"
	if err := bl.RecordViolation(t.Context(), ipA, "tenant-a"); err != nil {
		t.Fatalf("RecordViolation(tenant-a): %v", err)
	}
	if err := bl.RecordViolation(t.Context(), ipB, "tenant-b"); err != nil {
		t.Fatalf("RecordViolation(tenant-b): %v", err)
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
			IP          string `json:"ip"`
			APIClientID string `json:"api_client_id"`
		} `json:"bans"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding /admin/blacklist response: %v", err)
	}
	owners := map[string]string{}
	for _, b := range resp.Bans {
		owners[b.IP] = b.APIClientID
	}
	if owners[ipA] != "tenant-a" {
		t.Fatalf("ban for %s = owner %q, want %q (full list: %+v)", ipA, owners[ipA], "tenant-a", resp.Bans)
	}
	if owners[ipB] != "tenant-b" {
		t.Fatalf("ban for %s = owner %q, want %q (full list: %+v)", ipB, owners[ipB], "tenant-b", resp.Bans)
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

	// Too-short password.
	if rec := adminPanelRequestWithBody(r, http.MethodPost, path, superCookie, map[string]string{"password": "short"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("reactivate with short password: status = %d, want 400", rec.Code)
	}

	// Unknown account id.
	unknownPath := "/admin/accounts/00000000-0000-0000-0000-000000000000/reactivate"
	if rec := adminPanelRequestWithBody(r, http.MethodPost, unknownPath, superCookie, map[string]string{"password": "new-password-1"}); rec.Code != http.StatusNotFound {
		t.Fatalf("reactivate unknown account: status = %d, want 404", rec.Code)
	}

	// The real reactivation, as superadmin.
	rec := adminPanelRequestWithBody(r, http.MethodPost, path, superCookie, map[string]string{"password": "new-password-1"})
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
	if rec := adminPanelRequestWithBody(r, http.MethodPost, path, superCookie, map[string]string{"password": "another-password-1"}); rec.Code != http.StatusConflict {
		t.Fatalf("reactivate already-active account: status = %d, want 409", rec.Code)
	}
}
