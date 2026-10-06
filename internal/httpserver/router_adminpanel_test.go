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
	"go.opentelemetry.io/otel/metric/noop"

	"auth-2fa-api/internal/adminauth"
	"auth-2fa-api/internal/apiclient"
	"auth-2fa-api/internal/auth"
	"auth-2fa-api/internal/device"
	"auth-2fa-api/internal/httpserver"
	"auth-2fa-api/internal/testutil"
	"auth-2fa-api/internal/user"
)

const testAdminPanelOrigin = "https://panel.example.com"

var testAdminTOTPKey = []byte("0123456789abcdef0123456789abcdef")

func newTestRouterWithAdminPanel(t *testing.T) (http.Handler, *adminauth.Service, *pgxpool.Pool) {
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

	return r, adminAccounts, pool
}

func TestAdminPanel_CORS_OnlyAllowsConfiguredOrigin(t *testing.T) {
	r, _, _ := newTestRouterWithAdminPanel(t)

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
	r, _, _ := newTestRouterWithAdminPanel(t)

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
	r, adminAccounts, pool := newTestRouterWithAdminPanel(t)

	email := "panel-admin-" + testutil.UniqueSuffix(t) + "@example.com"
	account, otpauthURL, err := adminAccounts.CreateAccount(t.Context(), email, "correct-horse-battery")
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
