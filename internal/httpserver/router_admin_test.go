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
	handlers := auth.NewHandlers(auth.NewService(
		users, auth.NewOTPStore(rdb, 5*time.Minute, 3, 6), tokens, auth.NewRefreshRepository(pool),
		device.NewService(device.NewRepository(pool), 30*24*time.Hour, 3), auth.NewPasswordResetStore(rdb, time.Hour, 3, 6),
		auth.NewEmailVerificationStore(rdb, 24*time.Hour, 3, 6),
		auth.NewLoginAttemptLimiter(rdb, 3, 15*time.Minute),
		testutil.NewFakeMailer(), 5*time.Minute, 7*24*time.Hour, time.Hour, 24*time.Hour,
	))

	return httpserver.NewRouter(handlers, tokens, users, pool, rdb, apiClients, false, noop.NewMeterProvider().Meter("test"), adminToken)
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
