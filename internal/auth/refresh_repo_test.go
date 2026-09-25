package auth_test

import (
	"testing"
	"time"

	"auth-2fa-api/internal/auth"
	"auth-2fa-api/internal/testutil"
)

func TestRefreshRepository_DeleteExpired(t *testing.T) {
	pool := testutil.PostgresPool(t)
	client, _ := testutil.NewAPIClient(t, pool)
	u := testutil.NewUser(t, pool, client.ID, "correcthorsebattery")

	repo := auth.NewRefreshRepository(pool)

	expiredToken := "expired-" + testutil.UniqueSuffix(t)
	if err := repo.Store(t.Context(), u.ID, expiredToken, time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("storing expired token: %v", err)
	}
	liveToken := "live-" + testutil.UniqueSuffix(t)
	if err := repo.Store(t.Context(), u.ID, liveToken, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("storing live token: %v", err)
	}

	n, err := repo.DeleteExpired(t.Context())
	if err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}
	if n < 1 {
		t.Fatalf("DeleteExpired reported %d rows deleted, want at least 1", n)
	}

	var count int
	if err := pool.QueryRow(t.Context(),
		`SELECT count(*) FROM refresh_tokens WHERE user_id = $1`, u.ID,
	).Scan(&count); err != nil {
		t.Fatalf("counting remaining rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("refresh_tokens rows remaining for user = %d, want 1 (only the live token)", count)
	}

	valid, err := repo.IsValid(t.Context(), liveToken)
	if err != nil {
		t.Fatalf("IsValid: %v", err)
	}
	if !valid {
		t.Fatal("live token should still be valid after DeleteExpired")
	}
}
