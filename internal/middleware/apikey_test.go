package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"auth-2fa-api/internal/apiclient"
	"auth-2fa-api/internal/auth"
	"auth-2fa-api/internal/testutil"
)

func TestRequireAPIKey_MissingHeader(t *testing.T) {
	pool := testutil.PostgresPool(t)
	svc := apiclient.NewService(apiclient.NewRepository(pool))

	handler := RequireAPIKey(svc)(okHandler())

	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing X-API-Key: want 401, got %d", rec.Code)
	}
}

func TestRequireAPIKey_InvalidKey(t *testing.T) {
	pool := testutil.PostgresPool(t)
	svc := apiclient.NewService(apiclient.NewRepository(pool))

	handler := RequireAPIKey(svc)(okHandler())

	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req.Header.Set("X-API-Key", "sk_live_does_not_exist")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("invalid X-API-Key: want 401, got %d", rec.Code)
	}
}

func TestRequireAPIKey_ValidKey(t *testing.T) {
	pool := testutil.PostgresPool(t)
	svc := apiclient.NewService(apiclient.NewRepository(pool))
	client, plaintextKey := testutil.NewAPIClient(t, pool)

	var gotClientID string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClientID, _ = auth.APIClientIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	handler := RequireAPIKey(svc)(inner)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req.Header.Set("X-API-Key", plaintextKey)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("valid X-API-Key: want 200, got %d", rec.Code)
	}
	if gotClientID != client.ID {
		t.Fatalf("api client id in context = %q, want %q", gotClientID, client.ID)
	}
}

func TestRequireAPIKey_InactiveClient(t *testing.T) {
	pool := testutil.PostgresPool(t)
	svc := apiclient.NewService(apiclient.NewRepository(pool))
	client, plaintextKey := testutil.NewAPIClient(t, pool)

	if _, err := pool.Exec(context.Background(), `UPDATE api_clients SET active = FALSE WHERE id = $1`, client.ID); err != nil {
		t.Fatalf("deactivating test client: %v", err)
	}

	handler := RequireAPIKey(svc)(okHandler())

	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req.Header.Set("X-API-Key", plaintextKey)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("inactive client: want 401, got %d", rec.Code)
	}
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}
