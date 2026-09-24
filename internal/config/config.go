package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

// Config holds all environment-driven settings for the service.
type Config struct {
	Port string

	PostgresDSN string

	// RedisURL supports redis:// (plain) and rediss:// (TLS) schemes, e.g.
	// rediss://default:<password>@<host>:<port> as provided by Upstash.
	RedisURL string

	// Access tokens are signed with RS256 using this private key; the
	// public key is published via /.well-known/jwks.json so other systems
	// can verify tokens without calling back to this API. Loaded from
	// JWTPrivateKeyPath normally; JWTPrivateKeyPEMBase64 (the .pem file's
	// contents, base64-encoded) takes priority when set — for platforms
	// with no persistent/writable filesystem to put a key file on.
	JWTPrivateKeyPath      string
	JWTPrivateKeyPEMBase64 string
	JWTKeyID               string

	// Both optional, and only meaningful together with each other — set
	// during a JWT key rotation's overlap window so the *previous* signing
	// key's public half stays verifiable for a while after a new key
	// (JWTPrivateKeyPath/PEMBase64 + JWTKeyID above) takes over signing.
	// See auth.TokenManager.AddVerificationKey and README's "Rotación de
	// claves JWT" for the actual rotation procedure. Left empty (the
	// default), JWKS publishes exactly one key, same as always.
	JWTPreviousKeyID              string
	JWTPreviousPublicKeyPEMBase64 string

	// Refresh tokens stay HS256 (shared secret) — they're only ever
	// presented back to this API's own /auth/refresh endpoint.
	JWTRefreshSecret string
	AccessTokenTTL   time.Duration
	RefreshTokenTTL  time.Duration

	OTPLength   int
	OTPTTL      time.Duration
	OTPMaxTries int

	// Password reset: a short numeric code, same shape and default length
	// as the login OTP — hashed + attempt-limited in Redis, not a token the
	// user has to copy verbatim. Unlike the OTP, this code isn't gated
	// behind a correct password first (anyone who knows the account's
	// email can attempt it), but the attempt limit already does the real
	// work against brute force either way — a longer code buys very little
	// extra given how few tries are allowed, so it isn't worth the
	// inconsistency with the OTP length.
	PasswordResetTTL        time.Duration
	PasswordResetCodeLength int
	PasswordResetMaxTries   int

	// Email verification: same short-numeric-code shape as password reset,
	// required before LoginStep1 will issue an OTP — see auth.Service's
	// Register/LoginStep1 doc comments for why. TTL defaults much longer
	// than OTP/password-reset (a day, not minutes) since confirming a new
	// account is lower urgency than a login or reset in progress — no harm
	// in a user getting to it later that same day.
	EmailVerificationTTL        time.Duration
	EmailVerificationCodeLength int
	EmailVerificationMaxTries   int

	// Per-account login throttle (on top of the per-IP rate limiter) —
	// catches password guessing spread across many IPs against one
	// account. A temporary throttle, not a permanent lockout — see
	// LoginAttemptLimiter's doc comment for why.
	LoginMaxFailedAttempts int
	LoginLockoutWindow     time.Duration

	// Trusted device + PIN shortcut around password+OTP.
	DeviceTrustTTL    time.Duration
	DevicePinMaxTries int

	// Resend (https://resend.com) — HTTP API, not SMTP, so it isn't at
	// risk of a host blocking/filtering an outbound SMTP port (this
	// project hit exactly that on Render). ResendFrom defaults to
	// Resend's own sandbox sender, which needs no domain verification but
	// can only deliver to the email address on your Resend account —
	// verify a real domain in the Resend dashboard to send to anyone else.
	ResendAPIKey string
	ResendFrom   string

	// TrustProxyHeaders makes the rate limiter read the client IP from
	// X-Forwarded-For instead of the raw connection. Only enable this when
	// a reverse proxy you control sits in front and overwrites that header
	// — otherwise any client can forge it to dodge the rate limit.
	TrustProxyHeaders bool

	// AdminAPIToken gates /admin/* (provisioning api_clients over HTTP —
	// the same operations as cmd/createclient, for when running the CLI
	// over SSH is more friction than it's worth). Checked against the
	// X-Admin-Token header via RequireAdminToken.
	//
	// Empty (the default) disables /admin/* entirely rather than falling
	// back to some default token — an admin endpoint reachable with no
	// secret configured would be a much worse mistake than requiring an
	// explicit opt-in.
	AdminAPIToken string

	// TOTPEncryptionKeyBase64 enables the optional TOTP (Google
	// Authenticator-style) second factor as an alternative to the email
	// OTP flow. Base64 of exactly 32 raw bytes (AES-256) — generate one
	// like any other high-entropy secret, e.g. `openssl rand -base64 32`.
	//
	// Empty (the default) disables /auth/totp/* entirely, same reasoning
	// as AdminAPIToken: an opt-in feature with no secret configured should
	// not exist, not fall back to some default key.
	TOTPEncryptionKeyBase64 string
	// TOTPIssuer is the label shown next to the account name in the
	// authenticator app (e.g. "Auth2FA — Acme Inc"). Purely cosmetic.
	TOTPIssuer string

	// FirebaseCredentialsPath enables push-notification login approval — a
	// third alternative to the email OTP / TOTP second factor, for accounts
	// that opted a trusted device into it. Path to a Firebase service
	// account JSON key file (see README's "Configurar Firebase Cloud
	// Messaging" section for how to generate one).
	//
	// Empty (the default) disables /auth/devices/{id}/push and the
	// push-login endpoints entirely, same reasoning as TOTPEncryptionKeyBase64.
	FirebaseCredentialsPath string
	// PushLoginTTL is how long a push-approval request stays answerable
	// before it expires — long enough to notice the notification and pick
	// up the phone, short enough that a stale request isn't hanging around
	// for an attacker to still be trying when the real user finally checks.
	PushLoginTTL time.Duration
	// PushMaxRequests/PushRequestWindow cap how many push-approval requests
	// one account can trigger in a rolling window — see
	// auth.PushRequestLimiter's doc comment for why this (not just the
	// number-matching challenge) is the actual defense against someone with
	// a stolen password spamming approval prompts hoping for a blind tap.
	PushMaxRequests   int
	PushRequestWindow time.Duration
}

// Load reads a .env file if present (ignored if missing) and then reads
// environment variables, applying sane defaults for local development.
func Load() (*Config, error) {
	_ = godotenv.Load()

	cfg := &Config{
		Port: getEnv("PORT", "8080"),

		PostgresDSN: getEnv("POSTGRES_DSN", "postgres://postgres:postgres@localhost:5432/auth2fa?sslmode=disable"),

		RedisURL: getEnv("REDIS_URL", "redis://localhost:6379/0"),

		JWTPrivateKeyPath:      getEnv("JWT_PRIVATE_KEY_PATH", "keys/private.pem"),
		JWTPrivateKeyPEMBase64: getEnv("JWT_PRIVATE_KEY_PEM_BASE64", ""),
		JWTKeyID:               getEnv("JWT_KEY_ID", "auth-2fa-api-1"),

		JWTPreviousKeyID:              getEnv("JWT_PREVIOUS_KEY_ID", ""),
		JWTPreviousPublicKeyPEMBase64: getEnv("JWT_PREVIOUS_PUBLIC_KEY_PEM_BASE64", ""),

		JWTRefreshSecret: getEnv("JWT_REFRESH_SECRET", ""),

		ResendAPIKey: getEnv("RESEND_API_KEY", ""),
		ResendFrom:   getEnv("RESEND_FROM", "onboarding@resend.dev"),

		AdminAPIToken: getEnv("ADMIN_API_TOKEN", ""),

		TOTPEncryptionKeyBase64: getEnv("TOTP_ENCRYPTION_KEY", ""),
		TOTPIssuer:              getEnv("TOTP_ISSUER", "auth-2fa-api"),

		FirebaseCredentialsPath: getEnv("FIREBASE_CREDENTIALS_PATH", ""),
	}

	var err error
	if cfg.OTPLength, err = getEnvInt("OTP_LENGTH", 6); err != nil {
		return nil, err
	}
	if cfg.OTPMaxTries, err = getEnvInt("OTP_MAX_TRIES", 5); err != nil {
		return nil, err
	}
	if cfg.AccessTokenTTL, err = getEnvDuration("ACCESS_TOKEN_TTL", 15*time.Minute); err != nil {
		return nil, err
	}
	if cfg.RefreshTokenTTL, err = getEnvDuration("REFRESH_TOKEN_TTL", 7*24*time.Hour); err != nil {
		return nil, err
	}
	if cfg.OTPTTL, err = getEnvDuration("OTP_TTL", 5*time.Minute); err != nil {
		return nil, err
	}
	if cfg.PasswordResetTTL, err = getEnvDuration("PASSWORD_RESET_TTL", time.Hour); err != nil {
		return nil, err
	}
	if cfg.PasswordResetCodeLength, err = getEnvInt("PASSWORD_RESET_CODE_LENGTH", 6); err != nil {
		return nil, err
	}
	if cfg.PasswordResetMaxTries, err = getEnvInt("PASSWORD_RESET_MAX_TRIES", 5); err != nil {
		return nil, err
	}
	if cfg.EmailVerificationTTL, err = getEnvDuration("EMAIL_VERIFICATION_TTL", 24*time.Hour); err != nil {
		return nil, err
	}
	if cfg.EmailVerificationCodeLength, err = getEnvInt("EMAIL_VERIFICATION_CODE_LENGTH", 6); err != nil {
		return nil, err
	}
	if cfg.EmailVerificationMaxTries, err = getEnvInt("EMAIL_VERIFICATION_MAX_TRIES", 5); err != nil {
		return nil, err
	}
	if cfg.LoginMaxFailedAttempts, err = getEnvInt("LOGIN_MAX_FAILED_ATTEMPTS", 10); err != nil {
		return nil, err
	}
	if cfg.LoginLockoutWindow, err = getEnvDuration("LOGIN_LOCKOUT_WINDOW", 15*time.Minute); err != nil {
		return nil, err
	}
	if cfg.DeviceTrustTTL, err = getEnvDuration("DEVICE_TRUST_TTL", 30*24*time.Hour); err != nil {
		return nil, err
	}
	if cfg.DevicePinMaxTries, err = getEnvInt("DEVICE_PIN_MAX_TRIES", 5); err != nil {
		return nil, err
	}
	if cfg.TrustProxyHeaders, err = getEnvBool("TRUST_PROXY_HEADERS", false); err != nil {
		return nil, err
	}
	if cfg.PushLoginTTL, err = getEnvDuration("PUSH_LOGIN_TTL", 60*time.Second); err != nil {
		return nil, err
	}
	if cfg.PushMaxRequests, err = getEnvInt("PUSH_MAX_REQUESTS", 5); err != nil {
		return nil, err
	}
	if cfg.PushRequestWindow, err = getEnvDuration("PUSH_REQUEST_WINDOW", 15*time.Minute); err != nil {
		return nil, err
	}

	if cfg.JWTRefreshSecret == "" {
		return nil, fmt.Errorf("JWT_REFRESH_SECRET must be set")
	}
	if cfg.JWTPrivateKeyPath == "" {
		return nil, fmt.Errorf("JWT_PRIVATE_KEY_PATH must be set")
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) (int, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("invalid int for %s: %w", key, err)
	}
	return n, nil
}

func getEnvBool(key string, fallback bool) (bool, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("invalid bool for %s: %w", key, err)
	}
	return b, nil
}

func getEnvDuration(key string, fallback time.Duration) (time.Duration, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("invalid duration for %s: %w", key, err)
	}
	return d, nil
}
