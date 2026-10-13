package httpserver_test

// Covers /admin/clients: unregistered when no token is configured,
// unauthorized without (or with the wrong) X-Admin-Token, and the actual
// create/list/deactivate/activate/rotate flow when authorized.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/metric/noop"

	"auth-2fa-api/internal/apiclient"
	"auth-2fa-api/internal/auth"
	"auth-2fa-api/internal/device"
	"auth-2fa-api/internal/httpserver"
	"auth-2fa-api/internal/testutil"
	"auth-2fa-api/internal/user"
)

const testAdminToken = "test-admin-token"

// cleanupAPIClient registers a t.Cleanup deleting apiClientID and every
// user under it — same shape as testutil.NewAPIClient's own cleanup, for
// the handful of tests in this file that call apiclient.Service.Create
// directly (to control the client's name, or to create two in one test)
// instead of going through that helper. Without this, every such test run
// leaves its client and users behind forever — see the orphaned-row
// investigation this was added to fix.
func cleanupAPIClient(t *testing.T, pool *pgxpool.Pool, apiClientID string) {
	t.Helper()
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE api_client_id = $1`, apiClientID)
		_, _ = pool.Exec(ctx, `DELETE FROM api_clients WHERE id = $1`, apiClientID)
	})
}

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
		testutil.NewFakeMailer(), 5*time.Minute, 7*24*time.Hour, time.Hour, 24*time.Hour, time.Hour, nil, nil, nil, nil, nil, nil, testLogger(), accessRevocation, apiClients, "", nil, nil, nil,
	)
	handlers := auth.NewHandlers(svc)

	return httpserver.NewRouter(handlers, svc, tokens, accessRevocation, users, pool, rdb, apiClients, noop.NewMeterProvider().Meter("test"), adminToken, false, false, nil, nil, nil, "", false, 0, nil, nil, testLogger())
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
	if resp.Users[0]["api_client_name"] != clientA.Name {
		t.Fatalf("api_client_name = %v, want own tenant's name %q", resp.Users[0]["api_client_name"], clientA.Name)
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
	names := map[string]string{}
	for _, u := range resp.Users {
		names[u["id"].(string)] = u["api_client_name"].(string)
	}
	if _, ok := names[userA.id]; !ok {
		t.Fatalf("unscoped /admin/users listing missing users from one or both tenants: got %d users, want to find %s and %s among them", len(resp.Users), userA.id, userB.id)
	}
	if _, ok := names[userB.id]; !ok {
		t.Fatalf("unscoped /admin/users listing missing users from one or both tenants: got %d users, want to find %s and %s among them", len(resp.Users), userA.id, userB.id)
	}
	if names[userA.id] != clientA.Name {
		t.Fatalf("api_client_name for userA = %q, want %q", names[userA.id], clientA.Name)
	}
	if names[userB.id] != clientB.Name {
		t.Fatalf("api_client_name for userB = %q, want %q", names[userB.id], clientB.Name)
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
	Name   string
	APIKey string
}

func createTestClient(t *testing.T, r http.Handler, name string) testClient {
	t.Helper()
	fullName := name + "-" + testutil.UniqueSuffix(t)
	rec := adminRequest(r, http.MethodPost, "/admin/clients/", testAdminToken, map[string]string{"name": fullName})
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
	return testClient{ID: created.ID, Name: fullName, APIKey: created.APIKey}
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
		testutil.NewFakeMailer(), 5*time.Minute, 7*24*time.Hour, time.Hour, 24*time.Hour, time.Hour, nil, nil, nil, nil, nil, nil, testLogger(), accessRevocation, apiClients, "", nil, nil, nil,
	)
	handlers := auth.NewHandlers(svc)
	r := httpserver.NewRouter(handlers, svc, tokens, accessRevocation, users, pool, rdb, apiClients, noop.NewMeterProvider().Meter("test"), "", false, false, nil, nil, nil, "", false, 0, nil, nil, testLogger())

	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	u, err := svc.Register(t.Context(), client.ID, email, "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t), nil)
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
		testutil.NewFakeMailer(), 5*time.Minute, 7*24*time.Hour, time.Hour, 24*time.Hour, time.Hour, nil, nil, nil, nil, nil, nil, testLogger(), accessRevocation, apiClients, "", nil, nil, nil,
	)
	handlers := auth.NewHandlers(svc)
	r := httpserver.NewRouter(handlers, svc, tokens, accessRevocation, users, pool, rdb, apiClients, noop.NewMeterProvider().Meter("test"), testAdminToken, false, false, nil, nil, nil, "", false, 0, nil, nil, testLogger())

	clientA, _, err := apiClients.Create(t.Context(), "reset-pin-a-"+testutil.UniqueSuffix(t))
	if err != nil {
		t.Fatalf("creating client A: %v", err)
	}
	cleanupAPIClient(t, pool, clientA.ID)
	clientB, _, err := apiClients.Create(t.Context(), "reset-pin-b-"+testutil.UniqueSuffix(t))
	if err != nil {
		t.Fatalf("creating client B: %v", err)
	}
	cleanupAPIClient(t, pool, clientB.ID)
	systemAdminKeyA, err := apiClients.RotateSystemAdminKey(t.Context(), clientA.ID)
	if err != nil {
		t.Fatalf("rotating system admin key for client A: %v", err)
	}

	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	u, err := svc.Register(t.Context(), clientA.ID, email, "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t), nil)
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

// TestSystemAdminSetLoginPinRequired_ScopedToTenant covers
// PUT /system-admin/users/{id}/login-pin-required: it flips
// PinRequiredAtLogin for the right account, 404s for a user that belongs
// to a different tenant's key (same isolation rule as every other Admin*
// route), and 404s for an id that doesn't exist at all.
func TestSystemAdminSetLoginPinRequired_ScopedToTenant(t *testing.T) {
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
		testutil.NewFakeMailer(), 5*time.Minute, 7*24*time.Hour, time.Hour, 24*time.Hour, time.Hour, nil, nil, nil, nil, nil, nil, testLogger(), accessRevocation, apiClients, "", nil, nil, nil,
	)
	handlers := auth.NewHandlers(svc)
	r := httpserver.NewRouter(handlers, svc, tokens, accessRevocation, users, pool, rdb, apiClients, noop.NewMeterProvider().Meter("test"), testAdminToken, false, false, nil, nil, nil, "", false, 0, nil, nil, testLogger())

	clientA, _, err := apiClients.Create(t.Context(), "login-pin-required-a-"+testutil.UniqueSuffix(t))
	if err != nil {
		t.Fatalf("creating client A: %v", err)
	}
	cleanupAPIClient(t, pool, clientA.ID)
	clientB, _, err := apiClients.Create(t.Context(), "login-pin-required-b-"+testutil.UniqueSuffix(t))
	if err != nil {
		t.Fatalf("creating client B: %v", err)
	}
	cleanupAPIClient(t, pool, clientB.ID)
	systemAdminKeyA, err := apiClients.RotateSystemAdminKey(t.Context(), clientA.ID)
	if err != nil {
		t.Fatalf("rotating system admin key for client A: %v", err)
	}
	systemAdminKeyB, err := apiClients.RotateSystemAdminKey(t.Context(), clientB.ID)
	if err != nil {
		t.Fatalf("rotating system admin key for client B: %v", err)
	}

	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	u, err := svc.Register(t.Context(), clientA.ID, email, "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t), nil)
	if err != nil {
		t.Fatalf("seeding test user: %v", err)
	}

	putRequired := func(id, key string, required bool) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]bool{"required": required})
		req := httptest.NewRequest(http.MethodPut, "/system-admin/users/"+id+"/login-pin-required", bytes.NewReader(body))
		req.Header.Set("X-System-Admin-Token", key)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}

	// A second tenant's scoped key can't touch the first tenant's user.
	crossRec := putRequired(u.ID, systemAdminKeyB, true)
	if crossRec.Code != http.StatusNotFound {
		t.Fatalf("set login-pin-required from another tenant: status = %d, want %d", crossRec.Code, http.StatusNotFound)
	}

	// Unknown id -> 404.
	notFoundRec := putRequired("00000000-0000-0000-0000-000000000000", systemAdminKeyA, true)
	if notFoundRec.Code != http.StatusNotFound {
		t.Fatalf("set login-pin-required for unknown id: status = %d, want %d", notFoundRec.Code, http.StatusNotFound)
	}

	// The real tenant's key works, and it actually flips the flag.
	onRec := putRequired(u.ID, systemAdminKeyA, true)
	if onRec.Code != http.StatusNoContent {
		t.Fatalf("set login-pin-required true: status = %d, body = %s", onRec.Code, onRec.Body.String())
	}
	updated, err := users.FindByID(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("FindByID after enabling: %v", err)
	}
	if !updated.PinRequiredAtLogin {
		t.Fatal("PinRequiredAtLogin after enabling = false, want true")
	}

	offRec := putRequired(u.ID, systemAdminKeyA, false)
	if offRec.Code != http.StatusNoContent {
		t.Fatalf("set login-pin-required false: status = %d, body = %s", offRec.Code, offRec.Body.String())
	}
	updated, err = users.FindByID(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("FindByID after disabling: %v", err)
	}
	if updated.PinRequiredAtLogin {
		t.Fatal("PinRequiredAtLogin after disabling = true, want false")
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
		mailer, 5*time.Minute, 7*24*time.Hour, time.Hour, 24*time.Hour, time.Hour, nil, nil, nil, nil, nil, nil, testLogger(), accessRevocation, apiClients, "", nil, nil, nil,
	)
	handlers := auth.NewHandlers(svc)
	r := httpserver.NewRouter(handlers, svc, tokens, accessRevocation, users, pool, rdb, apiClients, noop.NewMeterProvider().Meter("test"), testAdminToken, false, false, nil, nil, nil, "", false, 0, nil, nil, testLogger())

	clientA, apiKeyA, err := apiClients.Create(t.Context(), "change-email-a-"+testutil.UniqueSuffix(t))
	if err != nil {
		t.Fatalf("creating client A: %v", err)
	}
	cleanupAPIClient(t, pool, clientA.ID)
	clientB, _, err := apiClients.Create(t.Context(), "change-email-b-"+testutil.UniqueSuffix(t))
	if err != nil {
		t.Fatalf("creating client B: %v", err)
	}
	cleanupAPIClient(t, pool, clientB.ID)
	systemAdminKeyA, err := apiClients.RotateSystemAdminKey(t.Context(), clientA.ID)
	if err != nil {
		t.Fatalf("rotating system admin key for client A: %v", err)
	}
	systemAdminKeyB, err := apiClients.RotateSystemAdminKey(t.Context(), clientB.ID)
	if err != nil {
		t.Fatalf("rotating system admin key for client B: %v", err)
	}

	oldEmail := "typo-" + testutil.UniqueSuffix(t) + "@example.com"
	u, err := svc.Register(t.Context(), clientA.ID, oldEmail, "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t), nil)
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

// TestSystemAdminChangeEmail_MailerFailure_Returns502 covers the HTTP side
// of auth.ErrEmailSendFailed — when the mail provider itself fails, the
// panel must see a clear 502 with a Spanish message it can show as-is, not
// a generic 500 that reads the same as every other internal error.
func TestSystemAdminChangeEmail_MailerFailure_Returns502(t *testing.T) {
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
		mailer, 5*time.Minute, 7*24*time.Hour, time.Hour, 24*time.Hour, time.Hour, nil, nil, nil, nil, nil, nil, testLogger(), accessRevocation, apiClients, "", nil, nil, nil,
	)
	handlers := auth.NewHandlers(svc)
	r := httpserver.NewRouter(handlers, svc, tokens, accessRevocation, users, pool, rdb, apiClients, noop.NewMeterProvider().Meter("test"), testAdminToken, false, false, nil, nil, nil, "", false, 0, nil, nil, testLogger())

	client, _, err := apiClients.Create(t.Context(), "change-email-fail-"+testutil.UniqueSuffix(t))
	if err != nil {
		t.Fatalf("creating client: %v", err)
	}
	cleanupAPIClient(t, pool, client.ID)
	systemAdminKey, err := apiClients.RotateSystemAdminKey(t.Context(), client.ID)
	if err != nil {
		t.Fatalf("rotating system admin key: %v", err)
	}
	u, err := svc.Register(t.Context(), client.ID, "typo-"+testutil.UniqueSuffix(t)+"@example.com", "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t), nil)
	if err != nil {
		t.Fatalf("seeding test user: %v", err)
	}

	mailer.FailNextSends(errors.New("resend error (500): internal server error"))

	req := httptest.NewRequest(http.MethodPost, "/system-admin/users/"+u.ID+"/change-email", bytes.NewBufferString(`{"new_email":"fixed-`+testutil.UniqueSuffix(t)+`@example.com"}`))
	req.Header.Set("X-System-Admin-Token", systemAdminKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("change-email with a failing mailer: status = %d, body = %s, want %d", rec.Code, rec.Body.String(), http.StatusBadGateway)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding error body: %v", err)
	}
	if body.Error == "" {
		t.Fatal("error body has no \"error\" field")
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
		mailer, 5*time.Minute, 7*24*time.Hour, time.Hour, 24*time.Hour, time.Hour, nil, nil, nil, nil, nil, nil, testLogger(), nil, apiClients, "", nil, nil, nil,
	)

	clientWithPanel, _, err := apiClients.Create(t.Context(), "change-email-panel-"+testutil.UniqueSuffix(t))
	if err != nil {
		t.Fatalf("creating client: %v", err)
	}
	cleanupAPIClient(t, pool, clientWithPanel.ID)
	if err := apiClients.SetPanelBaseURL(t.Context(), clientWithPanel.ID, "https://panel.example.com/"); err != nil {
		t.Fatalf("SetPanelBaseURL: %v", err)
	}
	clientWithoutPanel, _, err := apiClients.Create(t.Context(), "change-email-no-panel-"+testutil.UniqueSuffix(t))
	if err != nil {
		t.Fatalf("creating client: %v", err)
	}
	cleanupAPIClient(t, pool, clientWithoutPanel.ID)

	oldEmailWith := "typo-" + testutil.UniqueSuffix(t) + "@example.com"
	userWith, err := svc.Register(t.Context(), clientWithPanel.ID, oldEmailWith, "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t), nil)
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
	userWithout, err := svc.Register(t.Context(), clientWithoutPanel.ID, oldEmailWithout, "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t), nil)
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

// TestSystemAdminLockouts_ScopedToTenant covers GET .../lockouts and
// POST .../clear-lockouts: the response shape for an account with nothing
// locked, validation of the "which" field, and that neither route can be
// used against another tenant's account. The lockout mechanisms themselves
// (LoginAttemptLimiter, the PIN lockout) already have their own dedicated
// tests elsewhere — this is about routing and isolation, not re-proving
// the underlying throttle logic.
func TestSystemAdminLockouts_ScopedToTenant(t *testing.T) {
	r := newTestRouterWithAdmin(t, testAdminToken)

	clientA := createTestClient(t, r, "lockouts-a")
	clientB := createTestClient(t, r, "lockouts-b")
	userA := registerTestUser(t, r, clientA.APIKey)

	systemAdminKeyA := rotateSystemAdminKey(t, r, clientA.ID)
	systemAdminKeyB := rotateSystemAdminKey(t, r, clientB.ID)

	getLockouts := func(id, key string) *httptest.ResponseRecorder {
		return systemAdminRequest(r, http.MethodGet, "/system-admin/users/"+id+"/lockouts", key)
	}
	clearLockouts := func(id, key, which string) *httptest.ResponseRecorder {
		var body []byte
		if which != "" {
			body, _ = json.Marshal(map[string]string{"which": which})
		}
		req := httptest.NewRequest(http.MethodPost, "/system-admin/users/"+id+"/clear-lockouts", bytes.NewReader(body))
		req.Header.Set("X-System-Admin-Token", key)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}

	// A second tenant's scoped key can't see or clear the first tenant's
	// account lockouts.
	if rec := getLockouts(userA.id, systemAdminKeyB); rec.Code != http.StatusNotFound {
		t.Fatalf("GET lockouts from another tenant: status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	if rec := clearLockouts(userA.id, systemAdminKeyB, "all"); rec.Code != http.StatusNotFound {
		t.Fatalf("clear-lockouts from another tenant: status = %d, want %d", rec.Code, http.StatusNotFound)
	}

	// The real tenant's key works, and a fresh account has nothing locked.
	rec := getLockouts(userA.id, systemAdminKeyA)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET lockouts: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var status struct {
		Login struct {
			Locked bool `json:"locked"`
		} `json:"login"`
		Pin struct {
			Locked bool `json:"locked"`
		} `json:"pin"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatalf("decoding lockouts response: %v", err)
	}
	if status.Login.Locked || status.Pin.Locked {
		t.Fatalf("fresh account lockouts = %+v, want both false", status)
	}

	// which must be one of the three accepted values.
	if rec := clearLockouts(userA.id, systemAdminKeyA, "nonsense"); rec.Code != http.StatusBadRequest {
		t.Fatalf("clear-lockouts with invalid which: status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	// Each accepted value works against the real tenant's own account.
	for _, which := range []string{"login", "pin", "all"} {
		if rec := clearLockouts(userA.id, systemAdminKeyA, which); rec.Code != http.StatusNoContent {
			t.Fatalf("clear-lockouts which=%q: status = %d, body = %s", which, rec.Code, rec.Body.String())
		}
	}

	// Unknown id -> 404, same as every other /system-admin/users/{id}/* route.
	if rec := getLockouts("00000000-0000-0000-0000-000000000000", systemAdminKeyA); rec.Code != http.StatusNotFound {
		t.Fatalf("GET lockouts for unknown id: status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

// rotateSystemAdminKey provisions (or rotates) clientID's scoped
// X-System-Admin-Token via the operator's own X-Admin-Token — the same
// setup step several tests above already repeat inline.
func rotateSystemAdminKey(t *testing.T, r http.Handler, clientID string) string {
	t.Helper()
	rec := adminRequest(r, http.MethodPost, "/admin/clients/"+clientID+"/system-admin-key/rotate", testAdminToken, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("rotating system admin key for %s: status = %d, body = %s", clientID, rec.Code, rec.Body.String())
	}
	var resp struct {
		SystemAdminKey string `json:"system_admin_key"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding system-admin-key response: %v", err)
	}
	return resp.SystemAdminKey
}

// TestSystemAdminBlacklist_ScopedToTenant covers GET /system-admin/blacklist
// and DELETE /system-admin/blacklist/{ip}: a ban is only visible to and
// liftable by the tenant whose own traffic triggered it — a different
// tenant's scoped key gets a 404, same as every other /system-admin/*
// route, never a 403 that would confirm the ban exists elsewhere. Triggers
// a real ban through the actual rate limiter (password-reset/request, the
// lowest limit in the router: 5/hour) rather than reaching into
// middleware.Blacklist directly — this is the thing that proves the whole
// chain (RateLimiter -> Blacklist.RecordViolation -> owner attribution) is
// wired correctly end to end, which middleware package's own unit tests
// can't cover on their own.
func TestSystemAdminBlacklist_ScopedToTenant(t *testing.T) {
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
		testutil.NewFakeMailer(), 5*time.Minute, 7*24*time.Hour, time.Hour, 24*time.Hour, time.Hour, nil, nil, nil, nil, nil, nil, testLogger(), accessRevocation, apiClients, "", nil, nil, nil,
	)
	handlers := auth.NewHandlers(svc)
	r := httpserver.NewRouter(handlers, svc, tokens, accessRevocation, users, pool, rdb, apiClients, noop.NewMeterProvider().Meter("test"), testAdminToken, false, false, nil, []byte("test-ban-reference-secret"), nil, "", false, 0, nil, nil, testLogger())

	clientA := createTestClient(t, r, "blacklist-a")
	clientB := createTestClient(t, r, "blacklist-b")
	systemAdminKeyA := rotateSystemAdminKey(t, r, clientA.ID)
	systemAdminKeyB := rotateSystemAdminKey(t, r, clientB.ID)

	passwordResetRequest := func(apiKey string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"email": "nobody-" + testutil.UniqueSuffix(t) + "@example.com"})
		req := httptest.NewRequest(http.MethodPost, "/auth/password-reset/request", bytes.NewReader(body))
		req.Header.Set("X-API-Key", apiKey)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}

	// password-reset/request allows 5/hour before the rate limiter starts
	// denying (429); the blacklist bans after 3 denials within its own
	// window, so the 8th call (5 allowed + 3 denied) is the one that
	// actually crosses the threshold and creates the ban — it still comes
	// back 429 itself (RateLimiter already decided that response before
	// Blacklist.RecordViolation runs), so a 9th call is what proves the ban
	// took effect, from the same (default httptest) RemoteAddr, owned by
	// clientA.
	for i := 0; i < 8; i++ {
		passwordResetRequest(clientA.APIKey)
	}
	if code := passwordResetRequest(clientA.APIKey).Code; code != http.StatusForbidden {
		t.Fatalf("9th password-reset/request call: status = %d, want %d (banned)", code, http.StatusForbidden)
	}

	// The system-admin calls below come from a different address than the
	// one that got banned above — in reality this is the panel/backend
	// calling from its own network, not the abusive client itself; using
	// the same (default httptest) RemoteAddr here would make these calls
	// get rejected by Blacklist.Middleware's own global IP gate before
	// ever reaching the route, which isn't what this test is about.
	const adminCallerAddr = "198.51.100.200:1"
	listBans := func(key string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/system-admin/blacklist", nil)
		req.RemoteAddr = adminCallerAddr
		if key != "" {
			req.Header.Set("X-System-Admin-Token", key)
		}
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}
	deleteBan := func(ip, key string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodDelete, "/system-admin/blacklist/"+ip, nil)
		req.RemoteAddr = adminCallerAddr
		req.Header.Set("X-System-Admin-Token", key)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}

	// clientB sees no bans of its own — clientA's ban is invisible to it.
	bRec := listBans(systemAdminKeyB)
	if bRec.Code != http.StatusOK {
		t.Fatalf("GET blacklist (tenant B): status = %d, body = %s", bRec.Code, bRec.Body.String())
	}
	var bListing struct {
		Bans []map[string]any `json:"bans"`
	}
	if err := json.Unmarshal(bRec.Body.Bytes(), &bListing); err != nil {
		t.Fatalf("decoding blacklist response (tenant B): %v", err)
	}
	if len(bListing.Bans) != 0 {
		t.Fatalf("tenant B's blacklist listing = %+v, want empty (the ban belongs to tenant A)", bListing.Bans)
	}

	// clientA sees exactly its own ban, with a reference (a secret is
	// configured on this router).
	aRec := listBans(systemAdminKeyA)
	if aRec.Code != http.StatusOK {
		t.Fatalf("GET blacklist (tenant A): status = %d, body = %s", aRec.Code, aRec.Body.String())
	}
	var aListing struct {
		Bans []map[string]any `json:"bans"`
	}
	if err := json.Unmarshal(aRec.Body.Bytes(), &aListing); err != nil {
		t.Fatalf("decoding blacklist response (tenant A): %v", err)
	}
	if len(aListing.Bans) != 1 {
		t.Fatalf("tenant A's blacklist listing = %+v, want exactly one ban", aListing.Bans)
	}
	ban := aListing.Bans[0]
	ip, _ := ban["ip"].(string)
	if ip == "" {
		t.Fatalf("ban missing ip: %+v", ban)
	}
	if ref, _ := ban["reference"].(string); ref == "" {
		t.Fatalf("ban missing reference despite a secret being configured: %+v", ban)
	}

	// Invalid IP in the path -> 400, before any ownership check.
	if rec := deleteBan("not-an-ip", systemAdminKeyA); rec.Code != http.StatusBadRequest {
		t.Fatalf("DELETE blacklist with invalid ip: status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	// clientB can't lift clientA's ban.
	if rec := deleteBan(ip, systemAdminKeyB); rec.Code != http.StatusNotFound {
		t.Fatalf("DELETE blacklist (tenant B, tenant A's ban): status = %d, want %d", rec.Code, http.StatusNotFound)
	}

	// clientA can lift its own ban, and subsequent requests work again.
	if rec := deleteBan(ip, systemAdminKeyA); rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE blacklist (tenant A, own ban): status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if code := passwordResetRequest(clientA.APIKey).Code; code == http.StatusForbidden {
		t.Fatal("still banned after lifting the ban")
	}
}

// TestAdminBlacklistAllowlist_OperatorOnly covers /admin/blacklist/allowlist:
// deliberately NOT exposed under /system-admin/* — the exemption it grants
// is global (protects an IP against every system's strikes, not just
// whoever added it), so letting any one tenant's own credential control it
// would let that tenant weaken protection for every other tenant on the
// platform. Only the operator's own X-Admin-Token can manage it.
func TestAdminBlacklistAllowlist_OperatorOnly(t *testing.T) {
	r := newTestRouterWithAdmin(t, testAdminToken)
	const testIP = "203.0.113.90"

	addToAllowlist := func(ip, token string) *httptest.ResponseRecorder {
		return adminRequest(r, http.MethodPost, "/admin/blacklist/allowlist", token, map[string]string{"ip": ip})
	}
	listAllowlist := func(token string) *httptest.ResponseRecorder {
		return adminRequest(r, http.MethodGet, "/admin/blacklist/allowlist", token, nil)
	}
	removeFromAllowlist := func(ip, token string) *httptest.ResponseRecorder {
		return adminRequest(r, http.MethodDelete, "/admin/blacklist/allowlist/"+ip, token, nil)
	}

	// Wrong/missing X-Admin-Token -> 401, same as every other /admin/* route.
	if rec := addToAllowlist(testIP, "wrong-token"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("add with wrong token: status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	// Not reachable via /system-admin/* at all, even with a real, validly
	// provisioned scoped key — this exemption deliberately isn't something
	// any single tenant's own credential can grant.
	clientA := createTestClient(t, r, "allowlist-not-tenant")
	systemAdminKeyA := rotateSystemAdminKey(t, r, clientA.ID)
	if rec := systemAdminRequest(r, http.MethodGet, "/system-admin/blacklist/allowlist", systemAdminKeyA); rec.Code == http.StatusOK {
		t.Fatalf("GET /system-admin/blacklist/allowlist with a valid scoped key: status = %d, want anything but 200 (route must not exist there)", rec.Code)
	}

	// Invalid IP -> 400.
	if rec := addToAllowlist("not-an-ip", testAdminToken); rec.Code != http.StatusBadRequest {
		t.Fatalf("add invalid ip: status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	if rec := addToAllowlist(testIP, testAdminToken); rec.Code != http.StatusNoContent {
		t.Fatalf("add to allowlist: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	listRec := listAllowlist(testAdminToken)
	var body struct {
		IPs []string `json:"ips"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding allowlist: %v", err)
	}
	if len(body.IPs) != 1 || body.IPs[0] != testIP {
		t.Fatalf("allowlist = %v, want [%s]", body.IPs, testIP)
	}

	if rec := removeFromAllowlist(testIP, testAdminToken); rec.Code != http.StatusNoContent {
		t.Fatalf("remove: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	listRec = listAllowlist(testAdminToken)
	if err := json.Unmarshal(listRec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding allowlist after removal: %v", err)
	}
	if len(body.IPs) != 0 {
		t.Fatalf("allowlist after removal = %v, want empty", body.IPs)
	}

	// Removing an IP that was never added -> 404.
	if rec := removeFromAllowlist("198.51.100.1", testAdminToken); rec.Code != http.StatusNotFound {
		t.Fatalf("remove unknown ip: status = %d, want %d", rec.Code, http.StatusNotFound)
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
