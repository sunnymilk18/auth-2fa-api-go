package httpserver_test

// Covers /admin/clients: unregistered when no token is configured,
// unauthorized without (or with the wrong) X-Admin-Token, and the actual
// create/list/deactivate/activate/rotate flow when authorized.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.opentelemetry.io/otel/metric/noop"

	"auth-2fa-api/internal/apiclient"
	"auth-2fa-api/internal/auth"
	"auth-2fa-api/internal/device"
	"auth-2fa-api/internal/httpserver"
	"auth-2fa-api/internal/testutil"
	"auth-2fa-api/internal/user"
)

const testAdminToken = "test-admin-token"

func newTestRouterWithAdmin(t *testing.T, adminToken string) http.Handler {
	t.Helper()

	pool := testutil.PostgresPool(t)
	rdb := testutil.RedisClient(t)

	users := user.NewService(user.NewRepository(pool))
	tokens := auth.NewTokenManager(testutil.RSAKey(t), "test-key-1", "test-refresh-secret", 15*time.Minute, 7*24*time.Hour)
	apiClients := apiclient.NewService(apiclient.NewRepository(pool))
	accessRevocation := auth.NewAccessRevocationStore(rdb, 15*time.Minute)
	svc := auth.NewService(
		users, auth.NewOTPStore(rdb, 5*time.Minute, 3, 6), tokens, auth.NewRefreshRepository(pool),
		device.NewService(device.NewRepository(pool), 30*24*time.Hour, 3), auth.NewPasswordResetStore(rdb, time.Hour, 3, 6),
		auth.NewEmailVerificationStore(rdb, 24*time.Hour, 3, 6),
		auth.NewLoginAttemptLimiter(rdb, 3, 15*time.Minute),
		testutil.NewFakeMailer(), 5*time.Minute, 7*24*time.Hour, time.Hour, 24*time.Hour, nil, nil, nil, nil, nil, nil, testLogger(), accessRevocation,
	)
	handlers := auth.NewHandlers(svc)

	return httpserver.NewRouter(handlers, svc, tokens, accessRevocation, users, pool, rdb, apiClients, false, noop.NewMeterProvider().Meter("test"), adminToken, false, false, testLogger())
}

func adminRequest(r http.Handler, method, path, adminToken string, body any) *httptest.ResponseRecorder {
	var buf []byte
	if body != nil {
		buf, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(buf))
	if adminToken != "" {
		req.Header.Set("X-Admin-Token", adminToken)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestAdminClients_UnregisteredWithNoTokenConfigured(t *testing.T) {
	r := newTestRouterWithAdmin(t, "") // ADMIN_API_TOKEN unset

	rec := adminRequest(r, http.MethodGet, "/admin/clients/", testAdminToken, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d (route should not exist at all)", rec.Code, http.StatusNotFound)
	}
}

func TestAdminClients_RequiresCorrectToken(t *testing.T) {
	r := newTestRouterWithAdmin(t, testAdminToken)

	cases := []struct {
		name  string
		token string
	}{
		{"missing", ""},
		{"wrong", "not-the-right-token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := adminRequest(r, http.MethodGet, "/admin/clients/", tc.token, nil)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
			}
		})
	}
}

func TestAdminClients_CreateListDeactivateActivateRotate(t *testing.T) {
	r := newTestRouterWithAdmin(t, testAdminToken)

	// Create
	name := "test-app-" + testutil.UniqueSuffix(t)
	createRec := adminRequest(r, http.MethodPost, "/admin/clients/", testAdminToken, map[string]string{"name": name})
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create: status = %d, body = %s", createRec.Code, createRec.Body.String())
	}
	var created struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Active bool   `json:"active"`
		APIKey string `json:"api_key"`
	}
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decoding create response: %v", err)
	}
	if created.ID == "" || created.Name != name || !created.Active {
		t.Fatalf("unexpected create response: %+v", created)
	}
	if created.APIKey == "" {
		t.Fatalf("create response missing api_key")
	}

	// List includes it
	listRec := adminRequest(r, http.MethodGet, "/admin/clients/", testAdminToken, nil)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list: status = %d", listRec.Code)
	}
	var listed []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decoding list response: %v", err)
	}
	found := false
	for _, c := range listed {
		if c.ID == created.ID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("created client %s not present in list", created.ID)
	}

	// Deactivate
	deactivateRec := adminRequest(r, http.MethodPost, "/admin/clients/"+created.ID+"/deactivate", testAdminToken, nil)
	if deactivateRec.Code != http.StatusNoContent {
		t.Fatalf("deactivate: status = %d", deactivateRec.Code)
	}

	// Activate
	activateRec := adminRequest(r, http.MethodPost, "/admin/clients/"+created.ID+"/activate", testAdminToken, nil)
	if activateRec.Code != http.StatusNoContent {
		t.Fatalf("activate: status = %d", activateRec.Code)
	}

	// Rotate
	rotateRec := adminRequest(r, http.MethodPost, "/admin/clients/"+created.ID+"/rotate", testAdminToken, nil)
	if rotateRec.Code != http.StatusOK {
		t.Fatalf("rotate: status = %d", rotateRec.Code)
	}
	var rotated struct {
		APIKey string `json:"api_key"`
	}
	if err := json.Unmarshal(rotateRec.Body.Bytes(), &rotated); err != nil {
		t.Fatalf("decoding rotate response: %v", err)
	}
	if rotated.APIKey == "" || rotated.APIKey == created.APIKey {
		t.Fatalf("rotate should return a fresh, different key; got %q (original %q)", rotated.APIKey, created.APIKey)
	}

	// Unknown id -> 404
	notFoundRec := adminRequest(r, http.MethodPost, "/admin/clients/00000000-0000-0000-0000-000000000000/deactivate", testAdminToken, nil)
	if notFoundRec.Code != http.StatusNotFound {
		t.Fatalf("deactivate unknown id: status = %d, want %d", notFoundRec.Code, http.StatusNotFound)
	}
}

// TestSystemAdminKey_RotateThenScopedUserModeration covers the full path
// this feature exists for: the operator provisions a client's scoped admin
// key over /admin/clients (its own global token), and that key then works
// against /system-admin/users but only for that client's own users — a
// second client's scoped key gets 404 against the first client's user.
func TestSystemAdminKey_RotateThenScopedUserModeration(t *testing.T) {
	r := newTestRouterWithAdmin(t, testAdminToken)

	// Two tenants, one user each.
	clientA := createTestClient(t, r, "system-admin-a")
	clientB := createTestClient(t, r, "system-admin-b")

	rotateRec := adminRequest(r, http.MethodPost, "/admin/clients/"+clientA.ID+"/system-admin-key/rotate", testAdminToken, nil)
	if rotateRec.Code != http.StatusOK {
		t.Fatalf("rotate system admin key: status = %d, body = %s", rotateRec.Code, rotateRec.Body.String())
	}
	var rotated struct {
		SystemAdminKey string `json:"system_admin_key"`
	}
	if err := json.Unmarshal(rotateRec.Body.Bytes(), &rotated); err != nil {
		t.Fatalf("decoding rotate response: %v", err)
	}
	if rotated.SystemAdminKey == "" {
		t.Fatal("rotate response missing system_admin_key")
	}

	userA := registerTestUser(t, r, clientA.APIKey)
	userB := registerTestUser(t, r, clientB.APIKey)

	// Same tenant: works.
	banOwnRec := systemAdminRequest(r, http.MethodPost, "/system-admin/users/"+userA.id+"/ban", rotated.SystemAdminKey)
	if banOwnRec.Code != http.StatusNoContent {
		t.Fatalf("ban own tenant's user: status = %d, body = %s", banOwnRec.Code, banOwnRec.Body.String())
	}

	// Cross tenant: 404, not 403 — never confirms the id exists elsewhere.
	banOtherRec := systemAdminRequest(r, http.MethodPost, "/system-admin/users/"+userB.id+"/ban", rotated.SystemAdminKey)
	if banOtherRec.Code != http.StatusNotFound {
		t.Fatalf("ban another tenant's user: status = %d, want %d", banOtherRec.Code, http.StatusNotFound)
	}

	// Revoking the key ends its access immediately.
	revokeRec := adminRequest(r, http.MethodDelete, "/admin/clients/"+clientA.ID+"/system-admin-key", testAdminToken, nil)
	if revokeRec.Code != http.StatusNoContent {
		t.Fatalf("revoke system admin key: status = %d", revokeRec.Code)
	}
	afterRevokeRec := systemAdminRequest(r, http.MethodPost, "/system-admin/users/"+userA.id+"/unban", rotated.SystemAdminKey)
	if afterRevokeRec.Code != http.StatusUnauthorized {
		t.Fatalf("using a revoked system admin key: status = %d, want %d", afterRevokeRec.Code, http.StatusUnauthorized)
	}
}

func systemAdminRequest(r http.Handler, method, path, key string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if key != "" {
		req.Header.Set("X-System-Admin-Token", key)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

type testClient struct {
	ID     string
	APIKey string
}

func createTestClient(t *testing.T, r http.Handler, name string) testClient {
	t.Helper()
	rec := adminRequest(r, http.MethodPost, "/admin/clients/", testAdminToken, map[string]string{"name": name + "-" + testutil.UniqueSuffix(t)})
	if rec.Code != http.StatusCreated {
		t.Fatalf("creating test client %q: status = %d, body = %s", name, rec.Code, rec.Body.String())
	}
	var created struct {
		ID     string `json:"id"`
		APIKey string `json:"api_key"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decoding create client response: %v", err)
	}
	return testClient{ID: created.ID, APIKey: created.APIKey}
}

type testUser struct {
	id string
}

// registerTestUser registers and verifies a throwaway account under
// apiKey's tenant, returning its id — enough for the ban/unban tests
// above, which only need a valid id to act on, not a working login.
func registerTestUser(t *testing.T, r http.Handler, apiKey string) testUser {
	t.Helper()
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	body := map[string]string{
		"email":    email,
		"password": "correcthorsebattery",
		"username": "user-" + testutil.UniqueSuffix(t),
		"rut":      testutil.UniqueRUT(t),
	}
	buf, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(buf))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("registering test user: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decoding register response: %v", err)
	}
	return testUser{id: created.ID}
}

// TestRouter_BanInstantlyRevokesAnAlreadyIssuedAccessToken is the router-
// level proof for AccessRevocationStore: a GET /me call with an access
// token minted before AdminBanUser must fail immediately, not just once
// that token would have expired on its own. Own inline wiring (not
// newTestRouterWithAdmin) since this needs direct access to svc/tokens,
// which that helper doesn't expose.
func TestRouter_BanInstantlyRevokesAnAlreadyIssuedAccessToken(t *testing.T) {
	pool := testutil.PostgresPool(t)
	rdb := testutil.RedisClient(t)
	client, _ := testutil.NewAPIClient(t, pool)

	users := user.NewService(user.NewRepository(pool))
	tokens := auth.NewTokenManager(testutil.RSAKey(t), "test-key-1", "test-refresh-secret", 15*time.Minute, 7*24*time.Hour)
	apiClients := apiclient.NewService(apiclient.NewRepository(pool))
	accessRevocation := auth.NewAccessRevocationStore(rdb, 15*time.Minute)
	svc := auth.NewService(
		users, auth.NewOTPStore(rdb, 5*time.Minute, 3, 6), tokens, auth.NewRefreshRepository(pool),
		device.NewService(device.NewRepository(pool), 30*24*time.Hour, 3), auth.NewPasswordResetStore(rdb, time.Hour, 3, 6),
		auth.NewEmailVerificationStore(rdb, 24*time.Hour, 3, 6),
		auth.NewLoginAttemptLimiter(rdb, 3, 15*time.Minute),
		testutil.NewFakeMailer(), 5*time.Minute, 7*24*time.Hour, time.Hour, 24*time.Hour, nil, nil, nil, nil, nil, nil, testLogger(), accessRevocation,
	)
	handlers := auth.NewHandlers(svc)
	r := httpserver.NewRouter(handlers, svc, tokens, accessRevocation, users, pool, rdb, apiClients, false, noop.NewMeterProvider().Meter("test"), "", false, false, testLogger())

	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	u, err := svc.Register(t.Context(), client.ID, email, "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t))
	if err != nil {
		t.Fatalf("seeding test user: %v", err)
	}
	access, err := tokens.IssueAccessToken(u.ID, client.ID, email)
	if err != nil {
		t.Fatalf("issuing access token: %v", err)
	}

	meReq := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/me", nil)
		req.Header.Set("Authorization", "Bearer "+access)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}

	if rec := meReq(); rec.Code != http.StatusOK {
		t.Fatalf("GET /me before ban: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	if err := svc.AdminBanUser(t.Context(), "", u.ID); err != nil {
		t.Fatalf("AdminBanUser: %v", err)
	}

	if rec := meReq(); rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /me with the same access token, right after AdminBanUser: status = %d, want %d (the token's signature/expiry alone are still fine — this is what AccessRevocationStore is for)", rec.Code, http.StatusUnauthorized)
	}
}
