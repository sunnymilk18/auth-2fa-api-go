package httpserver_test

// These tests exercise the fully-wired router (NewRouter) rather than any
// handler or middleware in isolation — the thing they catch is a route
// ending up with the wrong middleware attached (or none at all), which no
// amount of testing the middleware or the handler alone would notice.

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	_ "github.com/microsoft/go-mssqldb"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/metric/noop"

	"auth-2fa-api/internal/apiclient"
	"auth-2fa-api/internal/auth"
	"auth-2fa-api/internal/device"
	"auth-2fa-api/internal/httpserver"
	"auth-2fa-api/internal/testutil"
	"auth-2fa-api/internal/user"
)

// totpCodeFromOTPAuthURL extracts the secret embedded in an otpauth:// URL
// and computes the code currently valid for it — standing in for "the
// user's authenticator app" in these tests. See its twin in
// internal/auth's own tests (service_test.go); kept separate since Go
// doesn't share unexported test helpers across packages.
func totpCodeFromOTPAuthURL(t *testing.T, otpauthURL string) string {
	t.Helper()
	u, err := url.Parse(otpauthURL)
	if err != nil {
		t.Fatalf("parsing otpauth url %q: %v", otpauthURL, err)
	}
	secret := u.Query().Get("secret")
	if secret == "" {
		t.Fatalf("otpauth url %q has no secret param", otpauthURL)
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("computing totp code: %v", err)
	}
	return code
}

// testTOTPKey is a fixed 32-byte AES-256 key used only in tests.
var testTOTPKey = []byte("0123456789abcdef0123456789abcdef")

// testLogger discards output — these tests assert on HTTP behavior, not
// on what gets logged; a real logger would just be test noise.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestRouter wires a full router exactly like cmd/api does, against a
// real (local) Postgres and an in-memory Redis. Returns the router, a
// working API key for the tenant, and a Bearer access token for a
// registered, logged-in user under that same tenant.
func newTestRouter(t *testing.T) (router http.Handler, apiKey, accessToken string) {
	t.Helper()

	pool := testutil.MSSQLPool(t)
	rdb := testutil.RedisClient(t)
	client, plaintextKey := testutil.NewAPIClient(t, pool)

	users := user.NewService(user.NewRepository(pool))
	otpStore := auth.NewOTPStore(rdb, 5*time.Minute, 3, 6)
	tokens := auth.NewTokenManager(testutil.RSAKey(t), "test-key-1", "test-refresh-secret", 15*time.Minute, 7*24*time.Hour)
	refresh := auth.NewRefreshRepository(pool)
	devices := device.NewService(device.NewRepository(pool), 30*24*time.Hour, 3)
	passwordReset := auth.NewPasswordResetStore(rdb, time.Hour, 3, 6)
	emailVerification := auth.NewEmailVerificationStore(rdb, 24*time.Hour, 3, 6)
	loginAttempts := auth.NewLoginAttemptLimiter(rdb, 3, 15*time.Minute)
	apiClients := apiclient.NewService(apiclient.NewRepository(pool))
	totpManager, err := auth.NewTOTPManager("test-issuer", testTOTPKey)
	if err != nil {
		t.Fatalf("NewTOTPManager: %v", err)
	}
	totpLogin := auth.NewTOTPLoginStore(rdb, 5*time.Minute)

	svc := auth.NewService(users, otpStore, tokens, refresh, devices, passwordReset, emailVerification, loginAttempts, testutil.NewFakeMailer(), 5*time.Minute, 7*24*time.Hour, time.Hour, 24*time.Hour, totpManager, totpLogin, nil)
	handlers := auth.NewHandlers(svc)

	r := httpserver.NewRouter(handlers, tokens, users, pool, rdb, apiClients, false, noop.NewMeterProvider().Meter("test"), "", true, testLogger())

	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	u, err := svc.Register(t.Context(), client.ID, email, "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t))
	if err != nil {
		t.Fatalf("seeding test user: %v", err)
	}
	access, err := tokens.IssueAccessToken(u.ID, client.ID, email)
	if err != nil {
		t.Fatalf("issuing access token: %v", err)
	}

	return r, plaintextKey, access
}

// newTestRouterWithChoice is newTestRouter but with the first-login
// "choose your method" flow enabled (twoFactorSetup wired in, non-nil) —
// used only by the tests exercising that flow through the real router
// (middleware chain, rate limiters, OptionalAuth included), since wiring it
// into newTestRouter itself would change what every other test in this
// file gets when it registers a fresh account. Returns the router and a
// working API key — no pre-seeded access token, since these tests each
// drive their own first login through the real endpoints.
func newTestRouterWithChoice(t *testing.T) (router http.Handler, apiKey string, mailer *testutil.FakeMailer) {
	t.Helper()

	pool := testutil.MSSQLPool(t)
	rdb := testutil.RedisClient(t)
	_, plaintextKey := testutil.NewAPIClient(t, pool)

	users := user.NewService(user.NewRepository(pool))
	otpStore := auth.NewOTPStore(rdb, 5*time.Minute, 3, 6)
	tokens := auth.NewTokenManager(testutil.RSAKey(t), "test-key-1", "test-refresh-secret", 15*time.Minute, 7*24*time.Hour)
	refresh := auth.NewRefreshRepository(pool)
	devices := device.NewService(device.NewRepository(pool), 30*24*time.Hour, 3)
	passwordReset := auth.NewPasswordResetStore(rdb, time.Hour, 3, 6)
	emailVerification := auth.NewEmailVerificationStore(rdb, 24*time.Hour, 3, 6)
	loginAttempts := auth.NewLoginAttemptLimiter(rdb, 3, 15*time.Minute)
	apiClients := apiclient.NewService(apiclient.NewRepository(pool))
	totpManager, err := auth.NewTOTPManager("test-issuer", testTOTPKey)
	if err != nil {
		t.Fatalf("NewTOTPManager: %v", err)
	}
	totpLogin := auth.NewTOTPLoginStore(rdb, 5*time.Minute)
	twoFactorSetup := auth.NewTwoFactorSetupStore(rdb, 5*time.Minute)
	mailer = testutil.NewFakeMailer()

	svc := auth.NewService(users, otpStore, tokens, refresh, devices, passwordReset, emailVerification, loginAttempts, mailer, 5*time.Minute, 7*24*time.Hour, time.Hour, 24*time.Hour, totpManager, totpLogin, twoFactorSetup)
	handlers := auth.NewHandlers(svc)

	r := httpserver.NewRouter(handlers, tokens, users, pool, rdb, apiClients, false, noop.NewMeterProvider().Meter("test"), "", true, testLogger())
	return r, plaintextKey, mailer
}

func doRequest(r http.Handler, method, path, apiKey, bearer string, body any) *httptest.ResponseRecorder {
	var buf *bytes.Buffer
	if body != nil {
		b, _ := json.Marshal(body)
		buf = bytes.NewBuffer(b)
	} else {
		buf = bytes.NewBuffer(nil)
	}
	req := httptest.NewRequest(method, path, buf)
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// A browser preflights any cross-origin request that isn't a "simple"
// GET/POST with plain headers — every real consuming system's frontend
// sending X-API-Key hits this. Without CORS wired up, the browser never
// even sends the real request, it just fails the preflight silently.
func TestRouter_CORSPreflightAllowsCrossOriginAPIKeyRequests(t *testing.T) {
	r, _, _ := newTestRouter(t)

	req := httptest.NewRequest(http.MethodOptions, "/auth/register", nil)
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	req.Header.Set("Access-Control-Request-Headers", "X-API-Key,Content-Type")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want 200/204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, "*")
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); got == "" {
		t.Error("Access-Control-Allow-Methods missing from preflight response")
	}
}

func TestRouter_PublicRoutesNeedNoAuth(t *testing.T) {
	r, _, _ := newTestRouter(t)

	for _, path := range []string{"/health", "/.well-known/jwks.json", "/openapi.yaml", "/docs"} {
		rec := doRequest(r, http.MethodGet, path, "", "", nil)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s with no auth: status = %d, want %d", path, rec.Code, http.StatusOK)
		}
	}
}

// /health must actually reflect a broken dependency instead of always
// claiming "ok" — an orchestrator relying on it to detect an outage needs
// this to be true.
func TestRouter_HealthReportsDependencyOutage(t *testing.T) {
	r, _, _ := newTestRouter(t)

	// Healthy case: both SQL Server and Redis are reachable in these tests.
	rec := doRequest(r, http.MethodGet, "/health", "", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthy: status = %d, want %d", rec.Code, http.StatusOK)
	}

	// Broken SQL Server: point a *sql.DB at an address nothing listens on —
	// sql.Open doesn't dial eagerly, so this only fails once /health
	// actually pings it.
	brokenDB, err := sql.Open("sqlserver", "sqlserver://user:pass@127.0.0.1:1?database=nonexistent&dial+timeout=1")
	if err != nil {
		t.Fatalf("constructing a deliberately-unreachable db: %v", err)
	}
	t.Cleanup(func() { brokenDB.Close() })

	rBroken := brokenHealthRouter(t, brokenDB, testutil.RedisClient(t))

	brokenRec := doRequest(rBroken, http.MethodGet, "/health", "", "", nil)
	if brokenRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("broken mssql: status = %d, want %d, body=%s", brokenRec.Code, http.StatusServiceUnavailable, brokenRec.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(brokenRec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp["status"] != "mssql unreachable" {
		t.Fatalf("status field = %q, want %q", resp["status"], "mssql unreachable")
	}
}

// brokenHealthRouter builds just enough of a router to exercise /health
// with a deliberately-broken SQL Server *sql.DB — the other dependencies
// (handlers, tokens, users, apiClients) aren't reachable through /health,
// so they're wired minimally (against a real, working pool) rather than
// duplicating newTestRouter's setup.
func brokenHealthRouter(t *testing.T, brokenDB *sql.DB, rdb *redis.Client) http.Handler {
	t.Helper()
	pool := testutil.MSSQLPool(t)
	users := user.NewService(user.NewRepository(pool))
	tokens := auth.NewTokenManager(testutil.RSAKey(t), "test-key-1", "test-refresh-secret", 15*time.Minute, 7*24*time.Hour)
	apiClients := apiclient.NewService(apiclient.NewRepository(pool))
	handlers := auth.NewHandlers(auth.NewService(
		users, auth.NewOTPStore(rdb, 5*time.Minute, 3, 6), tokens, auth.NewRefreshRepository(pool),
		device.NewService(device.NewRepository(pool), 30*24*time.Hour, 3), auth.NewPasswordResetStore(rdb, time.Hour, 3, 6),
		auth.NewEmailVerificationStore(rdb, 24*time.Hour, 3, 6),
		auth.NewLoginAttemptLimiter(rdb, 3, 15*time.Minute),
		testutil.NewFakeMailer(), 5*time.Minute, 7*24*time.Hour, time.Hour, 24*time.Hour, nil, nil, nil,
	))
	return httpserver.NewRouter(handlers, tokens, users, brokenDB, rdb, apiClients, false, noop.NewMeterProvider().Meter("test"), "", false, testLogger())
}

func TestRouter_JWKSShape(t *testing.T) {
	r, _, _ := newTestRouter(t)
	rec := doRequest(r, http.MethodGet, "/.well-known/jwks.json", "", "", nil)

	var body struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding jwks response: %v", err)
	}
	if len(body.Keys) != 1 {
		t.Fatalf("jwks keys = %v, want exactly 1", body.Keys)
	}
	for _, field := range []string{"kty", "use", "kid", "alg", "n", "e"} {
		if _, ok := body.Keys[0][field]; !ok {
			t.Errorf("jwks key missing field %q: %v", field, body.Keys[0])
		}
	}
}

// Every /auth/* route requires X-API-Key, regardless of what else it needs.
func TestRouter_AuthRoutesRequireAPIKey(t *testing.T) {
	r, _, accessToken := newTestRouter(t)

	cases := []struct {
		method, path string
		bearer       string
	}{
		{http.MethodPost, "/auth/register", ""},
		{http.MethodPost, "/auth/login", ""},
		{http.MethodPost, "/auth/verify-otp", ""},
		{http.MethodPost, "/auth/refresh", ""},
		{http.MethodPost, "/auth/logout", ""},
		{http.MethodPost, "/auth/devices/login", ""},
		{http.MethodPost, "/auth/devices/register", accessToken},
		{http.MethodGet, "/auth/devices", accessToken},
		{http.MethodDelete, "/auth/devices/some-id", accessToken},
		{http.MethodPost, "/auth/password-reset/request", ""},
		{http.MethodPost, "/auth/password-reset/confirm", ""},
		{http.MethodPost, "/auth/verify-email/resend", ""},
		{http.MethodPost, "/auth/verify-email/confirm", ""},
	}
	for _, c := range cases {
		rec := doRequest(r, c.method, c.path, "" /* no api key */, c.bearer, map[string]string{})
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without X-API-Key: status = %d, want %d", c.method, c.path, rec.Code, http.StatusUnauthorized)
		}
	}
}

// The device sub-routes additionally require a Bearer token even with a
// valid API key — /auth/devices/login is the one exception, since that's
// the whole point of the PIN-unlock shortcut (no session yet).
func TestRouter_DeviceManagementRoutesAlsoRequireBearer(t *testing.T) {
	r, apiKey, _ := newTestRouter(t)

	cases := []struct {
		method, path string
	}{
		{http.MethodPost, "/auth/devices/register"},
		{http.MethodGet, "/auth/devices"},
		{http.MethodDelete, "/auth/devices/some-id"},
	}
	for _, c := range cases {
		rec := doRequest(r, c.method, c.path, apiKey, "" /* no bearer */, map[string]string{})
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s with API key but no Bearer: status = %d, want %d", c.method, c.path, rec.Code, http.StatusUnauthorized)
		}
	}

	// /auth/devices/login itself needs no Bearer — confirm it's not
	// rejected for that reason (a wrong device/pin still 401s, but for a
	// different reason: device.ErrDeviceNotTrusted, not a missing auth
	// header).
	rec := doRequest(r, http.MethodPost, "/auth/devices/login", apiKey, "", map[string]string{
		"device_id": "nope", "device_token": "nope", "pin": "000000",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("POST /auth/devices/login: status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	var resp map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["error"] == "falta el header Authorization o tiene un formato inválido" {
		t.Fatalf("/auth/devices/login incorrectly required a Bearer token: %v", resp)
	}
}

// /me sits outside the /auth group entirely: needs a Bearer token but, un-
// like everything under /auth/*, no X-API-Key at all.
func TestRouter_Me_NeedsBearerButNotAPIKey(t *testing.T) {
	r, apiKey, accessToken := newTestRouter(t)

	rec := doRequest(r, http.MethodGet, "/me", "", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /me with no auth at all: status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	// No X-API-Key, only Bearer — must still succeed.
	rec = doRequest(r, http.MethodGet, "/me", "", accessToken, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /me with Bearer but no X-API-Key: status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	// Belt and suspenders: also fine if an (unnecessary) API key is present.
	rec = doRequest(r, http.MethodGet, "/me", apiKey, accessToken, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /me with both headers: status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// /me must surface username and rut too, not just id/email — they're core
// identity fields now, not an afterthought bolted onto email alone.
func TestRouter_Me_IncludesUsernameAndRUT(t *testing.T) {
	r, _, accessToken := newTestRouter(t)

	rec := doRequest(r, http.MethodGet, "/me", "", accessToken, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /me: status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	for _, field := range []string{"id", "email", "username", "rut"} {
		if s, _ := resp[field].(string); s == "" {
			t.Errorf("GET /me response missing non-empty %q: %v", field, resp)
		}
	}
	if _, ok := resp["totp_enabled"].(bool); !ok {
		t.Errorf("GET /me response missing boolean totp_enabled: %v", resp)
	}
}

func TestRouter_Register_WithAPIKey_Succeeds(t *testing.T) {
	r, apiKey, _ := newTestRouter(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"

	rec := doRequest(r, http.MethodPost, "/auth/register", apiKey, "", map[string]string{
		"email": email, "password": "correcthorsebattery",
		"username": "user-" + testutil.UniqueSuffix(t), "rut": testutil.UniqueRUT(t),
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusCreated, rec.Body.String())
	}
}

// Password reset needs no Bearer token — same reasoning as
// /auth/devices/login: there's no session to present one from yet. The API
// key alone must be enough to reach the handler (business-logic errors, not
// "missing Authorization header", if anything goes wrong from there).
func TestRouter_PasswordReset_NoBearerNeeded(t *testing.T) {
	r, apiKey, _ := newTestRouter(t)

	reqRec := doRequest(r, http.MethodPost, "/auth/password-reset/request", apiKey, "", map[string]string{
		"email": "nobody@example.com",
	})
	if reqRec.Code != http.StatusOK {
		t.Fatalf("POST /auth/password-reset/request with API key only: status = %d, want %d, body=%s", reqRec.Code, http.StatusOK, reqRec.Body.String())
	}

	confirmRec := doRequest(r, http.MethodPost, "/auth/password-reset/confirm", apiKey, "", map[string]string{
		"email": "nobody@example.com", "code": "does-not-exist", "new_password": "new-password-456",
	})
	if confirmRec.Code != http.StatusUnauthorized {
		t.Fatalf("POST /auth/password-reset/confirm with API key only: status = %d, want %d", confirmRec.Code, http.StatusUnauthorized)
	}
	var resp map[string]string
	_ = json.Unmarshal(confirmRec.Body.Bytes(), &resp)
	if resp["error"] == "falta el header Authorization o tiene un formato inválido" {
		t.Fatalf("/auth/password-reset/confirm incorrectly required a Bearer token: %v", resp)
	}
}

// Email verification, same reasoning as password reset: no session exists
// yet at registration time, so the API key alone must be enough to reach
// both endpoints.
func TestRouter_EmailVerification_NoBearerNeeded(t *testing.T) {
	r, apiKey, _ := newTestRouter(t)

	resendRec := doRequest(r, http.MethodPost, "/auth/verify-email/resend", apiKey, "", map[string]string{
		"email": "nobody@example.com",
	})
	if resendRec.Code != http.StatusNotFound {
		t.Fatalf("POST /auth/verify-email/resend with API key only: status = %d, want %d, body=%s", resendRec.Code, http.StatusNotFound, resendRec.Body.String())
	}

	confirmRec := doRequest(r, http.MethodPost, "/auth/verify-email/confirm", apiKey, "", map[string]string{
		"email": "nobody@example.com", "code": "does-not-exist",
	})
	if confirmRec.Code != http.StatusUnauthorized {
		t.Fatalf("POST /auth/verify-email/confirm with API key only: status = %d, want %d", confirmRec.Code, http.StatusUnauthorized)
	}
	var resp map[string]string
	_ = json.Unmarshal(confirmRec.Body.Bytes(), &resp)
	if resp["error"] == "falta el header Authorization o tiene un formato inválido" {
		t.Fatalf("/auth/verify-email/confirm incorrectly required a Bearer token: %v", resp)
	}
}

// TOTP: enabled in newTestRouter (totpEnabled=true) — a logged-in user can
// reach /auth/totp/enroll and get back an otpauth_url to render as a QR
// code.
func TestRouter_TOTPEnroll_WithBearerSucceeds(t *testing.T) {
	r, apiKey, accessToken := newTestRouter(t)

	rec := doRequest(r, http.MethodPost, "/auth/totp/enroll", apiKey, accessToken, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /auth/totp/enroll with a valid Bearer token: status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp["otpauth_url"] == "" {
		t.Fatalf("response missing otpauth_url: %v", resp)
	}
}

func TestRouter_TOTPEnroll_NoBearerRejected(t *testing.T) {
	r, apiKey, _ := newTestRouter(t)

	rec := doRequest(r, http.MethodPost, "/auth/totp/enroll", apiKey, "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("POST /auth/totp/enroll with no Bearer token: status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// When the server never configured TOTP_ENCRYPTION_KEY, /auth/totp/* must
// not exist at all (404), not exist-but-fail — same reasoning as
// /admin/clients with no ADMIN_API_TOKEN (see router_admin_test.go).
func TestRouter_TOTPRoutes_UnregisteredWhenNotConfigured(t *testing.T) {
	// Bypass newTestRouter (built with totpEnabled=true) — use
	// brokenHealthRouter's own pool/rdb instead of a fresh one, since we
	// need a router built with totpEnabled=false but still need a real
	// logged-in user's api key + bearer token to get past
	// RequireAPIKey/RequireAuth and actually reach chi's routing decision
	// (an unmatched path under an authenticated group still runs that
	// group's middleware before falling through to 404 — sending no
	// credentials would report 401 from the middleware, not proving
	// anything about whether the route itself exists).
	pool := testutil.MSSQLPool(t)
	rdb := testutil.RedisClient(t)
	client, apiKey := testutil.NewAPIClient(t, pool)
	r := brokenHealthRouter(t, pool, rdb)

	users := user.NewService(user.NewRepository(pool))
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	u, err := users.Register(t.Context(), client.ID, email, "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t))
	if err != nil {
		t.Fatalf("seeding test user: %v", err)
	}
	tokens := auth.NewTokenManager(testutil.RSAKey(t), "test-key-1", "test-refresh-secret", 15*time.Minute, 7*24*time.Hour)
	access, err := tokens.IssueAccessToken(u.ID, client.ID, email)
	if err != nil {
		t.Fatalf("issuing access token: %v", err)
	}

	rec := doRequest(r, http.MethodPost, "/auth/totp/enroll", apiKey, access, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("POST /auth/totp/enroll with TOTP not configured: status = %d, want %d (route should not exist), body=%s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

// registerAndVerify drives a fresh account through /auth/register and
// /auth/verify-email/confirm via real HTTP requests against r, returning
// the email used — the shared setup every first-login-choice router test
// needs before it can even attempt /auth/login.
func registerAndVerify(t *testing.T, r http.Handler, apiKey string, mailer *testutil.FakeMailer) (email string) {
	t.Helper()
	email = "user-" + testutil.UniqueSuffix(t) + "@example.com"

	regRec := doRequest(r, http.MethodPost, "/auth/register", apiKey, "", map[string]string{
		"email": email, "password": "correcthorsebattery",
		"username": "user-" + testutil.UniqueSuffix(t), "rut": testutil.UniqueRUT(t),
	})
	if regRec.Code != http.StatusCreated {
		t.Fatalf("register: status = %d, want %d, body=%s", regRec.Code, http.StatusCreated, regRec.Body.String())
	}

	sent, ok := mailer.Last()
	if !ok {
		t.Fatal("register: no verification email was sent")
	}
	code := testutil.ExtractVerificationCode(sent.Body)
	if code == "" {
		t.Fatalf("register: could not find a verification code in email body: %q", sent.Body)
	}

	verifyRec := doRequest(r, http.MethodPost, "/auth/verify-email/confirm", apiKey, "", map[string]string{
		"email": email, "code": code,
	})
	if verifyRec.Code != http.StatusNoContent {
		t.Fatalf("verify-email/confirm: status = %d, want %d, body=%s", verifyRec.Code, http.StatusNoContent, verifyRec.Body.String())
	}
	return email
}

// End-to-end through the real router (middleware chain, rate limiters,
// OptionalAuth included) for the "email" branch of the first-login choice.
func TestRouter_FirstLogin_EmailBranch_EndToEnd(t *testing.T) {
	r, apiKey, mailer := newTestRouterWithChoice(t)
	email := registerAndVerify(t, r, apiKey, mailer)
	sentBeforeLogin := len(mailer.Sent())

	loginRec := doRequest(r, http.MethodPost, "/auth/login", apiKey, "", map[string]string{
		"identifier": email, "password": "correcthorsebattery",
	})
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login: status = %d, want %d, body=%s", loginRec.Code, http.StatusOK, loginRec.Body.String())
	}
	var loginBody struct {
		LoginToken          string `json:"login_token"`
		NeedsTwoFactorSetup bool   `json:"needs_2fa_setup"`
	}
	if err := json.Unmarshal(loginRec.Body.Bytes(), &loginBody); err != nil {
		t.Fatalf("decoding login response: %v", err)
	}
	if !loginBody.NeedsTwoFactorSetup {
		t.Fatal("first login: needs_2fa_setup = false, want true")
	}
	if len(mailer.Sent()) != sentBeforeLogin {
		t.Fatal("first login must not send an OTP email before a method is chosen")
	}

	sendRec := doRequest(r, http.MethodPost, "/auth/login/send-email-code", apiKey, "", map[string]string{
		"login_token": loginBody.LoginToken,
	})
	if sendRec.Code != http.StatusOK {
		t.Fatalf("send-email-code: status = %d, want %d, body=%s", sendRec.Code, http.StatusOK, sendRec.Body.String())
	}
	sent, ok := mailer.Last()
	if !ok {
		t.Fatal("send-email-code: no email was sent")
	}
	code := testutil.ExtractOTPCode(sent.Body)
	if code == "" {
		t.Fatalf("could not find an OTP code in email body: %q", sent.Body)
	}

	verifyRec := doRequest(r, http.MethodPost, "/auth/verify-otp", apiKey, "", map[string]string{
		"login_token": loginBody.LoginToken, "code": code,
	})
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("verify-otp: status = %d, want %d, body=%s", verifyRec.Code, http.StatusOK, verifyRec.Body.String())
	}

	// Second login: choice already made, straight to email, no setup screen.
	sentBeforeSecond := len(mailer.Sent())
	secondLoginRec := doRequest(r, http.MethodPost, "/auth/login", apiKey, "", map[string]string{
		"identifier": email, "password": "correcthorsebattery",
	})
	if secondLoginRec.Code != http.StatusOK {
		t.Fatalf("second login: status = %d, want %d", secondLoginRec.Code, http.StatusOK)
	}
	var secondBody struct {
		NeedsTwoFactorSetup bool `json:"needs_2fa_setup"`
	}
	if err := json.Unmarshal(secondLoginRec.Body.Bytes(), &secondBody); err != nil {
		t.Fatalf("decoding second login response: %v", err)
	}
	if secondBody.NeedsTwoFactorSetup {
		t.Fatal("second login: needs_2fa_setup = true, want false")
	}
	if len(mailer.Sent()) != sentBeforeSecond+1 {
		t.Fatalf("second login: want a new OTP email sent automatically, got %d -> %d", sentBeforeSecond, len(mailer.Sent()))
	}
}

// Same, for the "authenticator app" branch — EnrollTOTP/ConfirmTOTP reached
// through OptionalAuth with no Authorization header at all, only the
// login_token in the body.
func TestRouter_FirstLogin_TOTPBranch_EndToEnd(t *testing.T) {
	r, apiKey, mailer := newTestRouterWithChoice(t)
	email := registerAndVerify(t, r, apiKey, mailer)

	loginRec := doRequest(r, http.MethodPost, "/auth/login", apiKey, "", map[string]string{
		"identifier": email, "password": "correcthorsebattery",
	})
	var loginBody struct {
		LoginToken          string `json:"login_token"`
		NeedsTwoFactorSetup bool   `json:"needs_2fa_setup"`
	}
	if err := json.Unmarshal(loginRec.Body.Bytes(), &loginBody); err != nil {
		t.Fatalf("decoding login response: %v", err)
	}
	if !loginBody.NeedsTwoFactorSetup {
		t.Fatal("first login: needs_2fa_setup = false, want true")
	}

	enrollRec := doRequest(r, http.MethodPost, "/auth/totp/enroll", apiKey, "", map[string]string{
		"login_token": loginBody.LoginToken,
	})
	if enrollRec.Code != http.StatusOK {
		t.Fatalf("enroll (login_token mode): status = %d, want %d, body=%s", enrollRec.Code, http.StatusOK, enrollRec.Body.String())
	}
	var enrollBody struct {
		OTPAuthURL string `json:"otpauth_url"`
	}
	if err := json.Unmarshal(enrollRec.Body.Bytes(), &enrollBody); err != nil {
		t.Fatalf("decoding enroll response: %v", err)
	}
	if enrollBody.OTPAuthURL == "" {
		t.Fatal("enroll response missing otpauth_url")
	}

	code := totpCodeFromOTPAuthURL(t, enrollBody.OTPAuthURL)
	confirmRec := doRequest(r, http.MethodPost, "/auth/totp/confirm", apiKey, "", map[string]string{
		"login_token": loginBody.LoginToken, "code": code,
	})
	if confirmRec.Code != http.StatusOK {
		t.Fatalf("confirm (login_token mode): status = %d, want %d, body=%s", confirmRec.Code, http.StatusOK, confirmRec.Body.String())
	}
	var confirmBody struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(confirmRec.Body.Bytes(), &confirmBody); err != nil {
		t.Fatalf("decoding confirm response: %v", err)
	}
	if confirmBody.AccessToken == "" || confirmBody.RefreshToken == "" {
		t.Fatalf("confirm response missing tokens: %s", confirmRec.Body.String())
	}
}
