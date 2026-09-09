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
	apiClients := apiclient.NewService(apiclient.NewRepository(pool))

	svc := auth.NewService(users, otpStore, tokens, refresh, devices, testutil.NewFakeMailer(), 5*time.Minute, 7*24*time.Hour)
	handlers := auth.NewHandlers(svc)

	r := httpserver.NewRouter(handlers, tokens, users, rdb, apiClients, false)

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
