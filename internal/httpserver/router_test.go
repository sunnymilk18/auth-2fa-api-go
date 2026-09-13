package httpserver_test

// These tests exercise the fully-wired router (NewRouter) rather than any
// handler or middleware in isolation — the thing they catch is a route
// ending up with the wrong middleware attached (or none at all), which no
// amount of testing the middleware or the handler alone would notice.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/metric/noop"

	"auth-2fa-api/internal/apiclient"
	"auth-2fa-api/internal/auth"
	"auth-2fa-api/internal/device"
	"auth-2fa-api/internal/httpserver"
	"auth-2fa-api/internal/testutil"
	"auth-2fa-api/internal/user"
)

// newTestRouter wires a full router exactly like cmd/api does, against a
// real (local) Postgres and an in-memory Redis. Returns the router, a
// working API key for the tenant, and a Bearer access token for a
// registered, logged-in user under that same tenant.
func newTestRouter(t *testing.T) (router http.Handler, apiKey, accessToken string) {
	t.Helper()

	pool := testutil.PostgresPool(t)
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

	svc := auth.NewService(users, otpStore, tokens, refresh, devices, passwordReset, emailVerification, loginAttempts, testutil.NewFakeMailer(), 5*time.Minute, 7*24*time.Hour, time.Hour, 24*time.Hour)
	handlers := auth.NewHandlers(svc)

	r := httpserver.NewRouter(handlers, tokens, users, pool, rdb, apiClients, false, noop.NewMeterProvider().Meter("test"))

	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	u, err := svc.Register(t.Context(), client.ID, email, "correcthorsebattery")
	if err != nil {
		t.Fatalf("seeding test user: %v", err)
	}
	access, err := tokens.IssueAccessToken(u.ID, client.ID, email)
	if err != nil {
		t.Fatalf("issuing access token: %v", err)
	}

	return r, plaintextKey, access
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

	// Healthy case: both Postgres and Redis are reachable in these tests.
	rec := doRequest(r, http.MethodGet, "/health", "", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthy: status = %d, want %d", rec.Code, http.StatusOK)
	}

	// Broken Postgres: point a pool at an address nothing listens on —
	// pgxpool.New doesn't dial eagerly, so this only fails once /health
	// actually pings it.
	brokenPool, err := pgxpool.New(t.Context(), "postgres://user:pass@127.0.0.1:1/nonexistent?connect_timeout=1")
	if err != nil {
		t.Fatalf("constructing a deliberately-unreachable pool: %v", err)
	}
	t.Cleanup(brokenPool.Close)

	rBroken := brokenHealthRouter(t, brokenPool, testutil.RedisClient(t))

	brokenRec := doRequest(rBroken, http.MethodGet, "/health", "", "", nil)
	if brokenRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("broken postgres: status = %d, want %d, body=%s", brokenRec.Code, http.StatusServiceUnavailable, brokenRec.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(brokenRec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp["status"] != "postgres unreachable" {
		t.Fatalf("status field = %q, want %q", resp["status"], "postgres unreachable")
	}
}

// brokenHealthRouter builds just enough of a router to exercise /health
// with a deliberately-broken Postgres pool — the other dependencies
// (handlers, tokens, users, apiClients) aren't reachable through /health,
// so they're wired minimally rather than duplicating newTestRouter's setup.
func brokenHealthRouter(t *testing.T, pgPool *pgxpool.Pool, rdb *redis.Client) http.Handler {
	t.Helper()
	pool := testutil.PostgresPool(t)
	users := user.NewService(user.NewRepository(pool))
	tokens := auth.NewTokenManager(testutil.RSAKey(t), "test-key-1", "test-refresh-secret", 15*time.Minute, 7*24*time.Hour)
	apiClients := apiclient.NewService(apiclient.NewRepository(pool))
	handlers := auth.NewHandlers(auth.NewService(
		users, auth.NewOTPStore(rdb, 5*time.Minute, 3, 6), tokens, auth.NewRefreshRepository(pool),
		device.NewService(device.NewRepository(pool), 30*24*time.Hour, 3), auth.NewPasswordResetStore(rdb, time.Hour, 3, 6),
		auth.NewEmailVerificationStore(rdb, 24*time.Hour, 3, 6),
		auth.NewLoginAttemptLimiter(rdb, 3, 15*time.Minute),
		testutil.NewFakeMailer(), 5*time.Minute, 7*24*time.Hour, time.Hour, 24*time.Hour,
	))
	return httpserver.NewRouter(handlers, tokens, users, pgPool, rdb, apiClients, false, noop.NewMeterProvider().Meter("test"))
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

func TestRouter_Register_WithAPIKey_Succeeds(t *testing.T) {
	r, apiKey, _ := newTestRouter(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"

	rec := doRequest(r, http.MethodPost, "/auth/register", apiKey, "", map[string]string{
		"email": email, "password": "correcthorsebattery",
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
