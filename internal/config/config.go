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
	// Refresh tokens stay HS256 (shared secret) — they're only ever
	// presented back to this API's own /auth/refresh endpoint.
	JWTRefreshSecret string
	AccessTokenTTL   time.Duration
	RefreshTokenTTL  time.Duration

	OTPLength   int
	OTPTTL      time.Duration
	OTPMaxTries int

	// Password reset: a short numeric code, same shape as the login OTP —
	// hashed + attempt-limited in Redis, not a token the user has to copy
	// verbatim. Longer than the login OTP by default since, unlike it, this
	// code isn't gated behind a correct password first: anyone who knows
	// the account's email can attempt it.
	PasswordResetTTL        time.Duration
	PasswordResetCodeLength int
	PasswordResetMaxTries   int

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
		JWTRefreshSecret:       getEnv("JWT_REFRESH_SECRET", ""),

		ResendAPIKey: getEnv("RESEND_API_KEY", ""),
		ResendFrom:   getEnv("RESEND_FROM", "onboarding@resend.dev"),
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
	if cfg.PasswordResetCodeLength, err = getEnvInt("PASSWORD_RESET_CODE_LENGTH", 8); err != nil {
		return nil, err
	}
	if cfg.PasswordResetMaxTries, err = getEnvInt("PASSWORD_RESET_MAX_TRIES", 5); err != nil {
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
