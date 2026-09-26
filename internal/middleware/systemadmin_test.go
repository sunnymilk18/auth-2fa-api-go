package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"auth-2fa-api/internal/apiclient"
	"auth-2fa-api/internal/auth"
	"auth-2fa-api/internal/testutil"
)

func TestRequireSystemAdminToken_MissingHeader(t *testing.T) {
	pool := testutil.PostgresPool(t)
	svc := apiclient.NewService(apiclient.NewRepository(pool))

	handler := RequireSystemAdminToken(svc)(okHandler())

	req := httptest.NewRequest(http.MethodPost, "/system-admin/users/some-id/ban", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing X-System-Admin-Token: want 401, got %d", rec.Code)
	}
}

func TestRequireSystemAdminToken_UnprovisionedClient(t *testing.T) {
	// A client that has never had a scoped admin key rotated for it must
	// reject every key, same as a wrong one — there's no "exists but has
	// no credential yet" state visible from the outside.
	pool := testutil.PostgresPool(t)
	svc := apiclient.NewService(apiclient.NewRepository(pool))
	testutil.NewAPIClient(t, pool)

	handler := RequireSystemAdminToken(svc)(okHandler())

	req := httptest.NewRequest(http.MethodPost, "/system-admin/users/some-id/ban", nil)
	req.Header.Set("X-System-Admin-Token", "sk_live_does_not_exist")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unprovisioned client, any key: want 401, got %d", rec.Code)
	}
}

func TestRequireSystemAdminToken_ValidKeyScopesToItsOwnClient(t *testing.T) {
	pool := testutil.PostgresPool(t)
	svc := apiclient.NewService(apiclient.NewRepository(pool))
	client, _ := testutil.NewAPIClient(t, pool)
	key, err := svc.RotateSystemAdminKey(t.Context(), client.ID)
	if err != nil {
		t.Fatalf("RotateSystemAdminKey: %v", err)
	}

	var gotClientID string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClientID, _ = auth.APIClientIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	handler := RequireSystemAdminToken(svc)(inner)

	req := httptest.NewRequest(http.MethodPost, "/system-admin/users/some-id/ban", nil)
	req.Header.Set("X-System-Admin-Token", key)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("valid X-System-Admin-Token: want 200, got %d", rec.Code)
	}
	if gotClientID != client.ID {
		t.Fatalf("api client id in context = %q, want %q", gotClientID, client.ID)
	}
}

func TestRequireSystemAdminToken_RevokedKeyIsRejected(t *testing.T) {
	pool := testutil.PostgresPool(t)
	svc := apiclient.NewService(apiclient.NewRepository(pool))
	client, _ := testutil.NewAPIClient(t, pool)
	key, err := svc.RotateSystemAdminKey(t.Context(), client.ID)
	if err != nil {
		t.Fatalf("RotateSystemAdminKey: %v", err)
	}
	if err := svc.RevokeSystemAdminKey(t.Context(), client.ID); err != nil {
		t.Fatalf("RevokeSystemAdminKey: %v", err)
	}

	handler := RequireSystemAdminToken(svc)(okHandler())

	req := httptest.NewRequest(http.MethodPost, "/system-admin/users/some-id/ban", nil)
	req.Header.Set("X-System-Admin-Token", key)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked X-System-Admin-Token: want 401, got %d", rec.Code)
	}
}
