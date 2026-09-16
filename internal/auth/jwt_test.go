package auth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"auth-2fa-api/internal/auth"
)

// genKey generates a fresh RSA key — deliberately not testutil.RSAKey,
// which memoizes a single shared key per test binary; these tests need two
// distinct keys (old + new) to exercise rotation.
func genKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating rsa key: %v", err)
	}
	return key
}

// During a key rotation's overlap window, a token issued by the OLD key
// must keep verifying once the TokenManager has moved on to signing with a
// NEW key — as long as the old key's public half was registered via
// AddVerificationKey. This is the entire point of the rotation mechanism:
// without it, every access token issued in roughly the last accessTTL
// before a rotation would suddenly become invalid.
func TestTokenManager_VerifiesTokensFromPreviousKeyDuringOverlap(t *testing.T) {
	oldKey := genKey(t)
	newKey := genKey(t)

	oldTM := auth.NewTokenManager(oldKey, "key-1", "refresh-secret", 15*time.Minute, 7*24*time.Hour)
	oldToken, err := oldTM.IssueAccessToken("user-1", "client-1", "user@example.com")
	if err != nil {
		t.Fatalf("issuing token with old key: %v", err)
	}

	// The rotation: a new TokenManager signs with the new key, but still
	// knows how to verify tokens the old key issued.
	newTM := auth.NewTokenManager(newKey, "key-2", "refresh-secret", 15*time.Minute, 7*24*time.Hour)
	newTM.AddVerificationKey("key-1", &oldKey.PublicKey)

	claims, err := newTM.ParseAccessToken(oldToken)
	if err != nil {
		t.Fatalf("parsing pre-rotation token during overlap: unexpected error %v", err)
	}
	if claims.Subject != "user-1" {
		t.Fatalf("claims.Subject = %q, want %q", claims.Subject, "user-1")
	}

	// And tokens signed with the new key work too, obviously.
	newToken, err := newTM.IssueAccessToken("user-2", "client-1", "other@example.com")
	if err != nil {
		t.Fatalf("issuing token with new key: %v", err)
	}
	if _, err := newTM.ParseAccessToken(newToken); err != nil {
		t.Fatalf("parsing a token signed with the current key: unexpected error %v", err)
	}
}

// Once the overlap window ends and the old key is dropped (the operator
// simply stops calling AddVerificationKey for it on the next deploy), a
// token still bearing that kid must be rejected like any other invalid
// token — not panic, not silently accepted.
func TestTokenManager_RejectsUnknownKeyID(t *testing.T) {
	oldKey := genKey(t)
	newKey := genKey(t)

	oldTM := auth.NewTokenManager(oldKey, "key-1", "refresh-secret", 15*time.Minute, 7*24*time.Hour)
	oldToken, err := oldTM.IssueAccessToken("user-1", "client-1", "user@example.com")
	if err != nil {
		t.Fatalf("issuing token with old key: %v", err)
	}

	// newTM never registers "key-1" — simulating the old key having aged
	// out of the verification set after its rotation window ended.
	newTM := auth.NewTokenManager(newKey, "key-2", "refresh-secret", 15*time.Minute, 7*24*time.Hour)

	if _, err := newTM.ParseAccessToken(oldToken); err != auth.ErrInvalidToken {
		t.Fatalf("parsing a token with a retired kid: err = %v, want %v", err, auth.ErrInvalidToken)
	}
}

// PublicKeys must expose every registered key (for JWKS), not just the
// current signing key.
func TestTokenManager_PublicKeysIncludesPreviousDuringOverlap(t *testing.T) {
	oldKey := genKey(t)
	newKey := genKey(t)

	tm := auth.NewTokenManager(newKey, "key-2", "refresh-secret", 15*time.Minute, 7*24*time.Hour)
	if len(tm.PublicKeys()) != 1 {
		t.Fatalf("PublicKeys() before rotation = %d keys, want 1", len(tm.PublicKeys()))
	}

	tm.AddVerificationKey("key-1", &oldKey.PublicKey)
	keys := tm.PublicKeys()
	if len(keys) != 2 {
		t.Fatalf("PublicKeys() during overlap = %d keys, want 2", len(keys))
	}
	if _, ok := keys["key-1"]; !ok {
		t.Error(`PublicKeys() missing "key-1"`)
	}
	if _, ok := keys["key-2"]; !ok {
		t.Error(`PublicKeys() missing "key-2"`)
	}
}
