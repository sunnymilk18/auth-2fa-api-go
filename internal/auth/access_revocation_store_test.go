package auth_test

import (
	"testing"
	"time"

	"auth-2fa-api/internal/auth"
	"auth-2fa-api/internal/testutil"
)

func TestAccessRevocationStore_NoMarkerMeansNotRevoked(t *testing.T) {
	rdb := testutil.RedisClient(t)
	store := auth.NewAccessRevocationStore(rdb, 15*time.Minute)

	revoked, err := store.IsRevoked(t.Context(), "some-user-id", time.Now())
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if revoked {
		t.Fatal("a user with no marker at all should never be reported as revoked")
	}
}

func TestAccessRevocationStore_MarkRevoked_RejectsTokensIssuedBeforeButNotAfter(t *testing.T) {
	rdb := testutil.RedisClient(t)
	store := auth.NewAccessRevocationStore(rdb, 15*time.Minute)
	userID := "user-" + testutil.UniqueSuffix(t)

	issuedBefore := time.Now()
	time.Sleep(5 * time.Millisecond) // guarantee strict ordering vs. MarkRevoked's own now()

	if err := store.MarkRevoked(t.Context(), userID); err != nil {
		t.Fatalf("MarkRevoked: %v", err)
	}

	time.Sleep(5 * time.Millisecond)
	issuedAfter := time.Now()

	revoked, err := store.IsRevoked(t.Context(), userID, issuedBefore)
	if err != nil {
		t.Fatalf("IsRevoked(issuedBefore): %v", err)
	}
	if !revoked {
		t.Fatal("a token issued before MarkRevoked should be reported as revoked")
	}

	revoked, err = store.IsRevoked(t.Context(), userID, issuedAfter)
	if err != nil {
		t.Fatalf("IsRevoked(issuedAfter): %v", err)
	}
	if revoked {
		t.Fatal("a token issued after MarkRevoked should NOT be reported as revoked — it couldn't have existed at ban time")
	}
}

func TestAccessRevocationStore_MarkerIsPerUser(t *testing.T) {
	rdb := testutil.RedisClient(t)
	store := auth.NewAccessRevocationStore(rdb, 15*time.Minute)
	bannedUser := "banned-" + testutil.UniqueSuffix(t)
	otherUser := "other-" + testutil.UniqueSuffix(t)

	issuedAt := time.Now()
	time.Sleep(5 * time.Millisecond)
	if err := store.MarkRevoked(t.Context(), bannedUser); err != nil {
		t.Fatalf("MarkRevoked: %v", err)
	}

	revoked, err := store.IsRevoked(t.Context(), otherUser, issuedAt)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if revoked {
		t.Fatal("marking one user revoked must not affect a different user's tokens")
	}
}

func TestAccessRevocationStore_MarkerExpiresWithTTL(t *testing.T) {
	rdb, mr := testutil.RedisClientAndServer(t)
	store := auth.NewAccessRevocationStore(rdb, time.Minute)
	userID := "user-" + testutil.UniqueSuffix(t)

	issuedAt := time.Now()
	time.Sleep(5 * time.Millisecond)
	if err := store.MarkRevoked(t.Context(), userID); err != nil {
		t.Fatalf("MarkRevoked: %v", err)
	}

	mr.FastForward(2 * time.Minute)

	revoked, err := store.IsRevoked(t.Context(), userID, issuedAt)
	if err != nil {
		t.Fatalf("IsRevoked after TTL: %v", err)
	}
	if revoked {
		t.Fatal("the revocation marker should have expired and no longer apply — any token from before it would've expired under its own TTL by now anyway")
	}
}
