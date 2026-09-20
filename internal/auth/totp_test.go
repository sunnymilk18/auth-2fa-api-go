package auth_test

import (
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"auth-2fa-api/internal/auth"
)

func TestTOTPManager_NewRejectsWrongKeyLength(t *testing.T) {
	if _, err := auth.NewTOTPManager("test", []byte("too-short")); err == nil {
		t.Fatal("NewTOTPManager with a non-32-byte key: want an error, got nil")
	}
}

func TestTOTPManager_GenerateSecret_ProducesAValidatableSecret(t *testing.T) {
	m, err := auth.NewTOTPManager("test-issuer", testTOTPKey)
	if err != nil {
		t.Fatalf("NewTOTPManager: %v", err)
	}

	secret, otpauthURL, err := m.GenerateSecret("user@example.com")
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if secret == "" {
		t.Fatal("GenerateSecret: empty secret")
	}
	if !strings.HasPrefix(otpauthURL, "otpauth://totp/") {
		t.Fatalf("otpauthURL = %q, want it to start with otpauth://totp/", otpauthURL)
	}
	if !strings.Contains(otpauthURL, "test-issuer") {
		t.Fatalf("otpauthURL = %q, want it to contain the issuer", otpauthURL)
	}

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("computing a code for the generated secret: %v", err)
	}
	if !m.ValidateCode(secret, code) {
		t.Fatal("ValidateCode: want true for a freshly computed code, got false")
	}
	if m.ValidateCode(secret, "000000") {
		t.Fatal("ValidateCode: want false for an arbitrary wrong code (vanishingly unlikely to collide), got true")
	}
}

func TestTOTPManager_EncryptDecrypt_RoundTrip(t *testing.T) {
	m, err := auth.NewTOTPManager("test-issuer", testTOTPKey)
	if err != nil {
		t.Fatalf("NewTOTPManager: %v", err)
	}

	const secret = "JBSWY3DPEHPK3PXP"
	encrypted, err := m.Encrypt(secret)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if encrypted == secret {
		t.Fatal("Encrypt: ciphertext equals the plaintext secret — it must be encrypted")
	}

	decrypted, err := m.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if decrypted != secret {
		t.Fatalf("Decrypt: got %q, want %q", decrypted, secret)
	}
}

// A different manager (a different key — simulates TOTP_ENCRYPTION_KEY
// being misconfigured or rotated without a migration) must not be able to
// decrypt a secret encrypted under the original key.
func TestTOTPManager_Decrypt_FailsWithWrongKey(t *testing.T) {
	m1, err := auth.NewTOTPManager("test-issuer", testTOTPKey)
	if err != nil {
		t.Fatalf("NewTOTPManager: %v", err)
	}
	otherKey := []byte(strings.Repeat("f", 32))
	m2, err := auth.NewTOTPManager("test-issuer", otherKey)
	if err != nil {
		t.Fatalf("NewTOTPManager: %v", err)
	}

	encrypted, err := m1.Encrypt("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := m2.Decrypt(encrypted); err == nil {
		t.Fatal("Decrypt with the wrong key: want an error, got nil")
	}
}
