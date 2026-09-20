package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/pquerna/otp/totp"
)

// ErrInvalidTOTPCode is returned by ConfirmTOTPEnrollment and the TOTP login
// path when the 6-digit code from the authenticator app doesn't match —
// deliberately the same shape as ErrInvalidCode (the email-OTP equivalent),
// so callers/handlers don't need to know which second-factor method an
// account uses to report "wrong code" the same way.
var ErrInvalidTOTPCode = errors.New("invalid totp code")

// TOTPManager generates/validates Google-Authenticator-compatible TOTP
// codes (RFC 6238) and encrypts the per-account secret at rest.
//
// Unlike a password (bcrypt-hashed, one-way) or a refresh/device token
// (sha256-hashed, only ever compared, never recovered), a TOTP secret can't
// be one-way hashed: verifying a code means recomputing what code is valid
// right now from the secret itself, so the server must be able to recover
// the actual secret, not just compare a hash of it. Encrypting it at rest
// (AES-256-GCM, under an app-level key separate from the database) is the
// standard mitigation — a raw DB leak alone then isn't enough to mint valid
// codes for every account, the same way a raw DB leak alone isn't enough to
// recover anyone's plaintext password.
type TOTPManager struct {
	issuer string
	key    []byte // 32 bytes, AES-256
}

// NewTOTPManager builds a manager from a 32-byte AES-256 key. issuer is the
// label shown in the authenticator app (e.g. next to the account name) —
// see GenerateSecret.
func NewTOTPManager(issuer string, encryptionKey []byte) (*TOTPManager, error) {
	if len(encryptionKey) != 32 {
		return nil, fmt.Errorf("totp encryption key must be 32 bytes, got %d", len(encryptionKey))
	}
	return &TOTPManager{issuer: issuer, key: encryptionKey}, nil
}

// GenerateSecret creates a new random TOTP secret for accountLabel (this
// project passes the account's email — it's what ends up displayed next to
// the issuer name in the authenticator app). Returns the raw base32 secret
// (never stored as-is — see Encrypt) and the otpauth:// URL a client can
// render as a QR code.
func (m *TOTPManager) GenerateSecret(accountLabel string) (secret, otpauthURL string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      m.issuer,
		AccountName: accountLabel,
	})
	if err != nil {
		return "", "", fmt.Errorf("generating totp secret: %w", err)
	}
	return key.Secret(), key.URL(), nil
}

// ValidateCode reports whether code is currently valid for secret — allows
// one 30-second step of clock skew on either side (pquerna/otp's default,
// same tolerance Google Authenticator/Authy clients assume), since phone
// clocks drift slightly and a login shouldn't fail over that.
func (m *TOTPManager) ValidateCode(secret, code string) bool {
	return totp.Validate(code, secret)
}

// Encrypt returns secret sealed with AES-256-GCM under the manager's key, as
// base64 (nonce || ciphertext) — the form actually stored in Postgres.
func (m *TOTPManager) Encrypt(secret string) (string, error) {
	block, err := aes.NewCipher(m.key)
	if err != nil {
		return "", fmt.Errorf("building aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("building gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, []byte(secret), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt reverses Encrypt.
func (m *TOTPManager) Decrypt(encrypted string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", fmt.Errorf("decoding encrypted totp secret: %w", err)
	}
	block, err := aes.NewCipher(m.key)
	if err != nil {
		return "", fmt.Errorf("building aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("building gcm: %w", err)
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("encrypted totp secret is too short")
	}
	nonce, ciphertext := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypting totp secret: %w", err)
	}
	return string(plain), nil
}
