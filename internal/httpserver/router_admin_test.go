package httpserver_test

// Covers /admin/clients: unregistered when no token is configured,
// unauthorized without (or with the wrong) X-Admin-Token, and the actual
// create/list/deactivate/activate/rotate flow when authorized.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
		testutil.NewFakeMailer(), 5*time.Minute, 7*24*time.Hour, time.Hour, 24*time.Hour, time.Hour, nil, nil, nil, nil, nil, nil, testLogger(), accessRevocation, apiClients, "",
	)
	handlers := auth.NewHandlers(svc)

	return httpserver.NewRouter(handlers, svc, tokens, accessRevocation, users, pool, rdb, apiClients, noop.NewMeterProvider().Meter("test"), adminToken, false, false, testLogger())
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

// TestSystemAdminListUsers_ScopedToTenantAndOmitsSensitiveFields covers the
// one Admin* route with no {id}: it must return only the calling tenant's
// own users (never another tenant's, even though both exist in the same
// table) and must never leak PasswordHash — the whole reason the handler
// projects onto userListItem instead of serializing user.User directly.
func TestSystemAdminListUsers_ScopedToTenantAndOmitsSensitiveFields(t *testing.T) {
	r := newTestRouterWithAdmin(t, testAdminToken)

	clientA := createTestClient(t, r, "list-users-a")
	clientB := createTestClient(t, r, "list-users-b")

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

	userA := registerTestUser(t, r, clientA.APIKey)
	_ = registerTestUser(t, r, clientB.APIKey)

	listRec := systemAdminRequest(r, http.MethodGet, "/system-admin/users/", rotated.SystemAdminKey)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list users: status = %d, body = %s", listRec.Code, listRec.Body.String())
	}

	var resp struct {
		Users []map[string]any `json:"users"`
		Page  int              `json:"page"`
		Total int              `json:"total"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding list response: %v", err)
	}
	if resp.Total != 1 {
		t.Fatalf("total = %d, want 1 (only clientA's own user, never clientB's)", resp.Total)
	}
	if len(resp.Users) != 1 {
		t.Fatalf("len(users) = %d, want 1", len(resp.Users))
	}
	if resp.Users[0]["id"] != userA.id {
		t.Fatalf("returned user id = %v, want clientA's user %s", resp.Users[0]["id"], userA.id)
	}
	for _, sensitive := range []string{"password_hash", "PasswordHash", "totp_secret", "totp_secret_enc"} {
		if _, present := resp.Users[0][sensitive]; present {
			t.Fatalf("list response leaked sensitive field %q", sensitive)
		}
	}

	// Wrong/missing key still 401s, same as every other /system-admin/*
	// route — no separate auth path for the one GET among POSTs.
	unauthRec := systemAdminRequest(r, http.MethodGet, "/system-admin/users/", "")
	if unauthRec.Code != http.StatusUnauthorized {
		t.Fatalf("no key: status = %d, want %d", unauthRec.Code, http.StatusUnauthorized)
	}
}

// TestSystemAdminListUsers_SearchByQ covers the ?q= search end to end
// through the HTTP route — case-insensitive partial match, and still
// scoped to the caller's own tenant.
func TestSystemAdminListUsers_SearchByQ(t *testing.T) {
	r := newTestRouterWithAdmin(t, testAdminToken)

	clientA := createTestClient(t, r, "search-users-a")
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

	suffix := testutil.UniqueSuffix(t)
	matchUsername := "findable-" + suffix
	registerUserWithFields(t, r, clientA.APIKey, "unrelated-"+suffix+"@example.com", matchUsername)
	registerUserWithFields(t, r, clientA.APIKey, "unrelated2-"+suffix+"@example.com", "nomatch-"+suffix)

	// Uppercased and only a substring, on purpose — the search must still
	// find it (case-insensitive, partial match).
	searchRec := systemAdminRequest(r, http.MethodGet, "/system-admin/users/?q=FINDABLE-"+suffix, rotated.SystemAdminKey)
	if searchRec.Code != http.StatusOK {
		t.Fatalf("search: status = %d, body = %s", searchRec.Code, searchRec.Body.String())
	}
	var resp struct {
		Users []map[string]any `json:"users"`
		Total int              `json:"total"`
	}
	if err := json.Unmarshal(searchRec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding search response: %v", err)
	}
	if resp.Total != 1 {
		t.Fatalf("total = %d, want 1 (only the matching username)", resp.Total)
	}
	if len(resp.Users) != 1 || resp.Users[0]["username"] != matchUsername {
		t.Fatalf("unexpected search results: %+v", resp.Users)
	}
}

// registerUserWithFields is registerTestUser but with a caller-chosen
// email/username, needed to test ?q= search against a known value.
func registerUserWithFields(t *testing.T, r http.Handler, apiKey, email, username string) testUser {
	t.Helper()
	body := map[string]string{
		"email":    email,
		"password": "correcthorsebattery",
		"username": username,
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

// TestAdminListUsers_UnscopedSpansEveryTenant covers the operator's own
// GET /admin/users (X-Admin-Token, no {id}) — the same ListUsers handler
// as /system-admin/users, but reached with no tenant in context, so it
// must return users from multiple tenants in one call, unlike every other
// Admin* route and unlike /system-admin/users itself.
func TestAdminListUsers_UnscopedSpansEveryTenant(t *testing.T) {
	r := newTestRouterWithAdmin(t, testAdminToken)

	clientA := createTestClient(t, r, "admin-list-a")
	clientB := createTestClient(t, r, "admin-list-b")
	userA := registerTestUser(t, r, clientA.APIKey)
	userB := registerTestUser(t, r, clientB.APIKey)

	// Unregistered without ADMIN_API_TOKEN configured — same as every
	// other /admin/* route.
	noTokenRouter := newTestRouterWithAdmin(t, "")
	notFoundRec := adminRequest(noTokenRouter, http.MethodGet, "/admin/users/", testAdminToken, nil)
	if notFoundRec.Code != http.StatusNotFound {
		t.Fatalf("no ADMIN_API_TOKEN configured: status = %d, want %d", notFoundRec.Code, http.StatusNotFound)
	}

	// Wrong/missing token: 401.
	unauthRec := adminRequest(r, http.MethodGet, "/admin/users/", "wrong-token", nil)
	if unauthRec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: status = %d, want %d", unauthRec.Code, http.StatusUnauthorized)
	}

	listRec := adminRequest(r, http.MethodGet, "/admin/users/?page_size=200", testAdminToken, nil)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list: status = %d, body = %s", listRec.Code, listRec.Body.String())
	}
	var resp struct {
		Users []map[string]any `json:"users"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding list response: %v", err)
	}
	found := map[string]bool{}
	for _, u := range resp.Users {
		found[u["id"].(string)] = true
	}
	if !found[userA.id] || !found[userB.id] {
		t.Fatalf("unscoped /admin/users listing missing users from one or both tenants: got %d users, want to find %s and %s among them", len(resp.Users), userA.id, userB.id)
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
		testutil.NewFakeMailer(), 5*time.Minute, 7*24*time.Hour, time.Hour, 24*time.Hour, time.Hour, nil, nil, nil, nil, nil, nil, testLogger(), accessRevocation, apiClients, "",
	)
	handlers := auth.NewHandlers(svc)
	r := httpserver.NewRouter(handlers, svc, tokens, accessRevocation, users, pool, rdb, apiClients, noop.NewMeterProvider().Meter("test"), "", false, false, testLogger())

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

// TestSystemAdminResetPin_ClearsPinRevokesDevicesAndSessions_ScopedToTenant
// covers POST /system-admin/users/{id}/reset-pin: it must clear the PIN,
// revoke the account's trusted devices and sessions (same pairing as
// AdminBanUser/ResetPassword), and stay scoped to the calling tenant like
// every other action in this group. Direct svc/tokens wiring (same as
// TestRouter_BanInstantlyRevokesAnAlreadyIssuedAccessToken above) since this
// needs to set up a PIN/device/access-token directly, not through a full
// HTTP login flow.
func TestSystemAdminResetPin_ClearsPinRevokesDevicesAndSessions_ScopedToTenant(t *testing.T) {
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
		testutil.NewFakeMailer(), 5*time.Minute, 7*24*time.Hour, time.Hour, 24*time.Hour, time.Hour, nil, nil, nil, nil, nil, nil, testLogger(), accessRevocation, apiClients, "",
	)
	handlers := auth.NewHandlers(svc)
	r := httpserver.NewRouter(handlers, svc, tokens, accessRevocation, users, pool, rdb, apiClients, noop.NewMeterProvider().Meter("test"), testAdminToken, false, false, testLogger())

	clientA, _, err := apiClients.Create(t.Context(), "reset-pin-a-"+testutil.UniqueSuffix(t))
	if err != nil {
		t.Fatalf("creating client A: %v", err)
	}
	clientB, _, err := apiClients.Create(t.Context(), "reset-pin-b-"+testutil.UniqueSuffix(t))
	if err != nil {
		t.Fatalf("creating client B: %v", err)
	}
	systemAdminKeyA, err := apiClients.RotateSystemAdminKey(t.Context(), clientA.ID)
	if err != nil {
		t.Fatalf("rotating system admin key for client A: %v", err)
	}

	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	u, err := svc.Register(t.Context(), clientA.ID, email, "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t))
	if err != nil {
		t.Fatalf("seeding test user: %v", err)
	}
	if err := svc.SetPin(t.Context(), u.ID, "123456", ""); err != nil {
		t.Fatalf("SetPin: %v", err)
	}
	if _, err := svc.RegisterDevice(t.Context(), u.ID, "device-"+testutil.UniqueSuffix(t), "Test Phone", "123456"); err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}
	access, err := tokens.IssueAccessToken(u.ID, clientA.ID, email)
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
		t.Fatalf("GET /me before reset-pin: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// A second tenant's scoped key can't reset the first tenant's user — 404,
	// same isolation rule as ban/unban/etc.
	systemAdminKeyB, err := apiClients.RotateSystemAdminKey(t.Context(), clientB.ID)
	if err != nil {
		t.Fatalf("rotating system admin key for client B: %v", err)
	}
	crossTenantRec := systemAdminRequest(r, http.MethodPost, "/system-admin/users/"+u.ID+"/reset-pin", systemAdminKeyB)
	if crossTenantRec.Code != http.StatusNotFound {
		t.Fatalf("reset-pin from another tenant: status = %d, want %d", crossTenantRec.Code, http.StatusNotFound)
	}

	// The real tenant's key works.
	resetRec := systemAdminRequest(r, http.MethodPost, "/system-admin/users/"+u.ID+"/reset-pin", systemAdminKeyA)
	if resetRec.Code != http.StatusNoContent {
		t.Fatalf("reset-pin: status = %d, body = %s", resetRec.Code, resetRec.Body.String())
	}

	hasPin, err := users.HasPin(t.Context(), u.ID)
	if err != nil || hasPin {
		t.Fatalf("HasPin after reset-pin: hasPin=%v err=%v, want false", hasPin, err)
	}
	devices, err := svc.ListDevices(t.Context(), u.ID)
	if err != nil || len(devices) != 0 {
		t.Fatalf("ListDevices after reset-pin: devices=%v err=%v, want empty (trusted devices must be revoked)", devices, err)
	}
	if rec := meReq(); rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /me with the pre-reset access token: status = %d, want %d (sessions must be revoked too)", rec.Code, http.StatusUnauthorized)
	}
}

// TestSystemAdminChangeEmail_EndToEndAndScopedToTenant covers both new
// routes together: the admin starts the correction (POST .../change-email,
// system-admin-token-gated, scoped to its own tenant like reset-pin above),
// and the account itself confirms it (POST /auth/change-email/confirm, a
// public route — no admin token, no Bearer session, just the API key and
// the code that arrived at the new address).
func TestSystemAdminChangeEmail_EndToEndAndScopedToTenant(t *testing.T) {
	pool := testutil.PostgresPool(t)
	rdb := testutil.RedisClient(t)

	users := user.NewService(user.NewRepository(pool), 5, 15*time.Minute)
	tokens := auth.NewTokenManager(testutil.RSAKey(t), "test-key-1", "test-refresh-secret", 15*time.Minute, 7*24*time.Hour)
	apiClients := apiclient.NewService(apiclient.NewRepository(pool))
	accessRevocation := auth.NewAccessRevocationStore(rdb, 15*time.Minute)
	mailer := testutil.NewFakeMailer()
	svc := auth.NewService(
		users, auth.NewOTPStore(rdb, 5*time.Minute, 3, 6), tokens, auth.NewRefreshRepository(pool),
		device.NewService(device.NewRepository(pool), 30*24*time.Hour), auth.NewPasswordResetStore(rdb, time.Hour, 3, 6),
		auth.NewEmailVerificationStore(rdb, 24*time.Hour, 3, 6),
		auth.NewChangeEmailStore(rdb, time.Hour, 3, 6),
		auth.NewLoginAttemptLimiter(rdb, 3, 15*time.Minute),
		mailer, 5*time.Minute, 7*24*time.Hour, time.Hour, 24*time.Hour, time.Hour, nil, nil, nil, nil, nil, nil, testLogger(), accessRevocation, apiClients, "",
	)
	handlers := auth.NewHandlers(svc)
	r := httpserver.NewRouter(handlers, svc, tokens, accessRevocation, users, pool, rdb, apiClients, noop.NewMeterProvider().Meter("test"), testAdminToken, false, false, testLogger())

	clientA, apiKeyA, err := apiClients.Create(t.Context(), "change-email-a-"+testutil.UniqueSuffix(t))
	if err != nil {
		t.Fatalf("creating client A: %v", err)
	}
	clientB, _, err := apiClients.Create(t.Context(), "change-email-b-"+testutil.UniqueSuffix(t))
	if err != nil {
		t.Fatalf("creating client B: %v", err)
	}
	systemAdminKeyA, err := apiClients.RotateSystemAdminKey(t.Context(), clientA.ID)
	if err != nil {
		t.Fatalf("rotating system admin key for client A: %v", err)
	}
	systemAdminKeyB, err := apiClients.RotateSystemAdminKey(t.Context(), clientB.ID)
	if err != nil {
		t.Fatalf("rotating system admin key for client B: %v", err)
	}

	oldEmail := "typo-" + testutil.UniqueSuffix(t) + "@example.com"
	u, err := svc.Register(t.Context(), clientA.ID, oldEmail, "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t))
	if err != nil {
		t.Fatalf("seeding test user: %v", err)
	}
	newEmail := "fixed-" + testutil.UniqueSuffix(t) + "@example.com"

	// A second tenant's scoped key can't touch the first tenant's user.
	crossReq := httptest.NewRequest(http.MethodPost, "/system-admin/users/"+u.ID+"/change-email", bytes.NewBufferString(`{"new_email":"`+newEmail+`"}`))
	crossReq.Header.Set("X-System-Admin-Token", systemAdminKeyB)
	crossReq.Header.Set("Content-Type", "application/json")
	crossRec := httptest.NewRecorder()
	r.ServeHTTP(crossRec, crossReq)
	if crossRec.Code != http.StatusNotFound {
		t.Fatalf("change-email from another tenant: status = %d, want %d", crossRec.Code, http.StatusNotFound)
	}

	// The real tenant's key starts it.
	startReq := httptest.NewRequest(http.MethodPost, "/system-admin/users/"+u.ID+"/change-email", bytes.NewBufferString(`{"new_email":"`+newEmail+`"}`))
	startReq.Header.Set("X-System-Admin-Token", systemAdminKeyA)
	startReq.Header.Set("Content-Type", "application/json")
	startRec := httptest.NewRecorder()
	r.ServeHTTP(startRec, startReq)
	if startRec.Code != http.StatusNoContent {
		t.Fatalf("change-email: status = %d, body = %s", startRec.Code, startRec.Body.String())
	}

	sent, ok := mailer.Last()
	if !ok || sent.To != newEmail {
		t.Fatalf("expected a code sent to %q, got %+v (ok=%v)", newEmail, sent, ok)
	}
	code := testutil.ExtractChangeEmailCode(sent.Body)

	// The account confirms it itself — public route, API key only.
	confirmRec := doRequest(r, http.MethodPost, "/auth/change-email/confirm", apiKeyA, "", map[string]string{
		"email": newEmail, "code": code,
	})
	if confirmRec.Code != http.StatusNoContent {
		t.Fatalf("change-email/confirm: status = %d, body = %s", confirmRec.Code, confirmRec.Body.String())
	}

	updated, err := users.FindByID(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("FindByID after confirm: %v", err)
	}
	if updated.Email != newEmail {
		t.Fatalf("email after confirm = %q, want %q", updated.Email, newEmail)
	}
	if !updated.EmailVerified {
		t.Fatal("email_verified after confirm = false, want true")
	}
}

// TestSystemAdminChangeEmail_IncludesPanelLinkWhenConfigured covers the
// optional panel link in the email sent to the new address: present
// (pointing at /confirmar-correo?email=<new email, URL-encoded>, without
// the code) when the tenant has configured its own panel_base_url, absent
// when it hasn't — same route, same handler, only the tenant's own config
// changes the email's body.
func TestSystemAdminChangeEmail_IncludesPanelLinkWhenConfigured(t *testing.T) {
	pool := testutil.PostgresPool(t)
	rdb := testutil.RedisClient(t)

	users := user.NewService(user.NewRepository(pool), 5, 15*time.Minute)
	tokens := auth.NewTokenManager(testutil.RSAKey(t), "test-key-1", "test-refresh-secret", 15*time.Minute, 7*24*time.Hour)
	apiClients := apiclient.NewService(apiclient.NewRepository(pool))
	mailer := testutil.NewFakeMailer()
	svc := auth.NewService(
		users, auth.NewOTPStore(rdb, 5*time.Minute, 3, 6), tokens, auth.NewRefreshRepository(pool),
		device.NewService(device.NewRepository(pool), 30*24*time.Hour), auth.NewPasswordResetStore(rdb, time.Hour, 3, 6),
		auth.NewEmailVerificationStore(rdb, 24*time.Hour, 3, 6),
		auth.NewChangeEmailStore(rdb, time.Hour, 3, 6),
		auth.NewLoginAttemptLimiter(rdb, 3, 15*time.Minute),
		mailer, 5*time.Minute, 7*24*time.Hour, time.Hour, 24*time.Hour, time.Hour, nil, nil, nil, nil, nil, nil, testLogger(), nil, apiClients, "",
	)

	clientWithPanel, _, err := apiClients.Create(t.Context(), "change-email-panel-"+testutil.UniqueSuffix(t))
	if err != nil {
		t.Fatalf("creating client: %v", err)
	}
	if err := apiClients.SetPanelBaseURL(t.Context(), clientWithPanel.ID, "https://panel.example.com/"); err != nil {
		t.Fatalf("SetPanelBaseURL: %v", err)
	}
	clientWithoutPanel, _, err := apiClients.Create(t.Context(), "change-email-no-panel-"+testutil.UniqueSuffix(t))
	if err != nil {
		t.Fatalf("creating client: %v", err)
	}

	oldEmailWith := "typo-" + testutil.UniqueSuffix(t) + "@example.com"
	userWith, err := svc.Register(t.Context(), clientWithPanel.ID, oldEmailWith, "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t))
	if err != nil {
		t.Fatalf("seeding test user (with panel): %v", err)
	}
	newEmailWith := "fixed-" + testutil.UniqueSuffix(t) + "@example.com"
	if err := svc.AdminChangeEmail(t.Context(), clientWithPanel.ID, userWith.ID, newEmailWith); err != nil {
		t.Fatalf("AdminChangeEmail (with panel): %v", err)
	}
	sentWith, ok := mailer.Last()
	if !ok || sentWith.To != newEmailWith {
		t.Fatalf("expected a code sent to %q, got %+v (ok=%v)", newEmailWith, sentWith, ok)
	}
	wantLink := "https://panel.example.com/confirmar-correo?email=" + url.QueryEscape(newEmailWith)
	if !strings.Contains(sentWith.Body, wantLink) {
		t.Fatalf("email body = %q, want it to contain panel link %q", sentWith.Body, wantLink)
	}

	oldEmailWithout := "typo-" + testutil.UniqueSuffix(t) + "@example.com"
	userWithout, err := svc.Register(t.Context(), clientWithoutPanel.ID, oldEmailWithout, "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t))
	if err != nil {
		t.Fatalf("seeding test user (without panel): %v", err)
	}
	newEmailWithout := "fixed-" + testutil.UniqueSuffix(t) + "@example.com"
	if err := svc.AdminChangeEmail(t.Context(), clientWithoutPanel.ID, userWithout.ID, newEmailWithout); err != nil {
		t.Fatalf("AdminChangeEmail (without panel): %v", err)
	}
	sentWithout, ok := mailer.Last()
	if !ok || sentWithout.To != newEmailWithout {
		t.Fatalf("expected a code sent to %q, got %+v (ok=%v)", newEmailWithout, sentWithout, ok)
	}
	if strings.Contains(sentWithout.Body, "/confirmar-correo") {
		t.Fatalf("email body = %q, want no panel link when panel_base_url isn't configured", sentWithout.Body)
	}
}

// The operator's unscoped /admin/users/{id}/reset-pin must also exist and
// work — same handler as /system-admin/users/{id}/reset-pin above, just
// reached through the operator's own X-Admin-Token instead.
func TestAdminResetPin_Unscoped(t *testing.T) {
	r := newTestRouterWithAdmin(t, testAdminToken)
	clientA := createTestClient(t, r, "admin-reset-pin-a")
	userA := registerTestUser(t, r, clientA.APIKey)

	rec := adminRequest(r, http.MethodPost, "/admin/users/"+userA.id+"/reset-pin", testAdminToken, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
}
