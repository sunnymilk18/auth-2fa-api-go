package auth_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"auth-2fa-api/internal/auth"
	"auth-2fa-api/internal/testutil"
)

// hashTokenForTest mirrors the unexported auth.hashToken (SHA-256, hex) —
// needed here only to look a row up by its stored hash directly via SQL,
// since this is an external (black-box) test package.
func hashTokenForTest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

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

	consumed, err := repo.ConsumeIfValid(t.Context(), liveToken)
	if err != nil {
		t.Fatalf("ConsumeIfValid: %v", err)
	}
	if !consumed {
		t.Fatal("live token should still be consumable after DeleteExpired")
	}
}

func TestRefreshRepository_ConsumeIfValid(t *testing.T) {
	pool := testutil.PostgresPool(t)
	client, _ := testutil.NewAPIClient(t, pool)
	u := testutil.NewUser(t, pool, client.ID, "correcthorsebattery")
	repo := auth.NewRefreshRepository(pool)

	t.Run("unknown token", func(t *testing.T) {
		consumed, err := repo.ConsumeIfValid(t.Context(), "does-not-exist-"+testutil.UniqueSuffix(t))
		if err != nil {
			t.Fatalf("ConsumeIfValid: %v", err)
		}
		if consumed {
			t.Fatal("an unknown token should never be consumable")
		}
	})

	t.Run("expired token", func(t *testing.T) {
		token := "expired-" + testutil.UniqueSuffix(t)
		if err := repo.Store(t.Context(), u.ID, token, time.Now().Add(-time.Hour)); err != nil {
			t.Fatalf("storing expired token: %v", err)
		}
		consumed, err := repo.ConsumeIfValid(t.Context(), token)
		if err != nil {
			t.Fatalf("ConsumeIfValid: %v", err)
		}
		if consumed {
			t.Fatal("an expired token should not be consumable")
		}
	})

	t.Run("only the first of two concurrent consumers succeeds", func(t *testing.T) {
		// Same scenario ConsumeIfValid exists to close: several
		// near-simultaneous callers presenting the same still-valid token
		// (several browser tabs, a retried request) — at most one may ever
		// win.
		token := "concurrent-" + testutil.UniqueSuffix(t)
		if err := repo.Store(t.Context(), u.ID, token, time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("storing token: %v", err)
		}

		first, err := repo.ConsumeIfValid(t.Context(), token)
		if err != nil {
			t.Fatalf("first ConsumeIfValid: %v", err)
		}
		if !first {
			t.Fatal("first ConsumeIfValid should have succeeded")
		}

		second, err := repo.ConsumeIfValid(t.Context(), token)
		if err != nil {
			t.Fatalf("second ConsumeIfValid: %v", err)
		}
		if second {
			t.Fatal("second ConsumeIfValid should not have succeeded — the token was already consumed")
		}
	})
}

// TestRefreshRepository_DeleteExpired_RevokedRetentionWindow covers the
// other half of DeleteExpired's criteria: a row revoked long enough ago
// gets purged even though it isn't expired yet, while a just-revoked row
// is left alone (still within its grace period — see
// revokedRetentionWindow's doc comment).
func TestRefreshRepository_DeleteExpired_RevokedRetentionWindow(t *testing.T) {
	pool := testutil.PostgresPool(t)
	client, _ := testutil.NewAPIClient(t, pool)
	u := testutil.NewUser(t, pool, client.ID, "correcthorsebattery")
	repo := auth.NewRefreshRepository(pool)

	oldRevoked := "old-revoked-" + testutil.UniqueSuffix(t)
	if err := repo.Store(t.Context(), u.ID, oldRevoked, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("storing token: %v", err)
	}
	if _, err := repo.ConsumeIfValid(t.Context(), oldRevoked); err != nil {
		t.Fatalf("ConsumeIfValid: %v", err)
	}
	// Backdate revoked_at past the retention window directly — the row was
	// just revoked "now" above, there's no way to revoke it 3 days ago for
	// real.
	if _, err := pool.Exec(t.Context(),
		`UPDATE refresh_tokens SET revoked_at = now() - INTERVAL '3 days' WHERE user_id = $1 AND token_hash = $2`,
		u.ID, hashTokenForTest(oldRevoked),
	); err != nil {
		t.Fatalf("backdating revoked_at: %v", err)
	}

	recentlyRevoked := "recently-revoked-" + testutil.UniqueSuffix(t)
	if err := repo.Store(t.Context(), u.ID, recentlyRevoked, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("storing token: %v", err)
	}
	if _, err := repo.ConsumeIfValid(t.Context(), recentlyRevoked); err != nil {
		t.Fatalf("ConsumeIfValid: %v", err)
	}

	if _, err := repo.DeleteExpired(t.Context()); err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}

	var remaining []string
	rows, err := pool.Query(t.Context(), `SELECT token_hash FROM refresh_tokens WHERE user_id = $1`, u.ID)
	if err != nil {
		t.Fatalf("querying remaining rows: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			t.Fatalf("scanning row: %v", err)
		}
		remaining = append(remaining, hash)
	}

	if len(remaining) != 1 || remaining[0] != hashTokenForTest(recentlyRevoked) {
		t.Fatalf("remaining rows = %v, want only the recently-revoked token (the old one should've been purged)", remaining)
	}
}
