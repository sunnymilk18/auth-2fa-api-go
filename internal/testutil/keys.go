package testutil

import (
	"crypto/rand"
	"crypto/rsa"
	"sync"
	"testing"
)

var (
	rsaKeyOnce sync.Once
	rsaKey     *rsa.PrivateKey
	rsaKeyErr  error
)

// RSAKey returns a 2048-bit RSA key for signing access tokens in tests.
// Generated once per test binary run (real key generation is slow enough
// that doing it per-test would add up) and safe to share since tests never
// mutate it.
func RSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	rsaKeyOnce.Do(func() {
		rsaKey, rsaKeyErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	if rsaKeyErr != nil {
		t.Fatalf("generating test RSA key: %v", rsaKeyErr)
	}
	return rsaKey
}
