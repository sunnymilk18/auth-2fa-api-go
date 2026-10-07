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
	// rediss://default:<password>@<host>:<port> as provided by most managed
	// Redis hosts.
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

	// Admin-initiated email correction (POST /system-admin/users/{id}/
	// change-email + the public POST /auth/change-email/confirm) — same
	// short-numeric-code shape as the other two above, sent to the NEW
	// email rather than the account's current one. TTL short like
	// password reset (not a day like email verification): unlike a new
	// signup, this is an admin acting right now on a known, specific
	// problem, not something to leave pending indefinitely.
	ChangeEmailTTL        time.Duration
	ChangeEmailCodeLength int
	ChangeEmailMaxTries   int

	// PanelBaseURL is a deployment-wide fallback for the per-tenant
	// api_clients.panel_base_url (see apiclient.Service.SetPanelBaseURL) —
	// used only when a tenant hasn't configured its own. Empty by default:
	// the change-email email then goes out with no link at all, same as
	// before this feature existed.
	PanelBaseURL string

	// TrustedProxyCIDRs, comma-separated (e.g. "10.0.1.0/24"), is the set of
	// networks allowed to tell this API the real client IP via
	// X-Forwarded-For — only a request whose RemoteAddr falls inside one of
	// these ranges gets the header trusted; everyone else's RemoteAddr is
	// used as-is, exactly like before this setting existed. Empty by default
	// (no proxy trusted at all) — see middleware.ClientIP's doc comment for
	// why a blanket trust-the-header flag isn't safe.
	TrustedProxyCIDRs string

	// BanReferenceSecret derives the short "reference" code
	// GET /system-admin/blacklist shows for a ban instead of the raw IP —
	// see middleware.Blacklist.Reference's doc comment. Empty (the
	// default) disables it: the field is simply omitted from responses,
	// not a startup failure. Deliberately its own secret, not reused from
	// JWT_REFRESH_SECRET or anything else already in this project.
	BanReferenceSecret string

	// Per-account login throttle (on top of the per-IP rate limiter) —
	// catches password guessing spread across many IPs against one
	// account. A temporary throttle, not a permanent lockout — see
	// LoginAttemptLimiter's doc comment for why.
	LoginMaxFailedAttempts int
	LoginLockoutWindow     time.Duration

	// Trusted device shortcut around password+OTP — the PIN that gates it
	// lives on the account (see PinMaxFailedAttempts/PinLockMinutes below),
	// not here.
	DeviceTrustTTL time.Duration

	// Account PIN: one per user, unlocks a trusted device and confirms
	// sensitive actions from any client (see user.Service.VerifyPin).
	// PinMaxFailedAttempts consecutive wrong guesses — across every use:
	// changing the PIN, verifying it, registering or logging in with a
	// device — lock it for PinLockMinutes.
	PinMaxFailedAttempts int
	PinLockMinutes       int

	// LoginPinTTL bounds how long a pin_token from the mandatory
	// login-pin step (see auth.Service.LoginResult/LoginPinStep,
	// PinRequiredAtLogin) stays valid — short, like a login_token: a few
	// minutes is plenty for someone to type their PIN right after
	// finishing the second factor.
	LoginPinTTL time.Duration

	// Resend (https://resend.com) — HTTP API, not SMTP, so it isn't at
	// risk of a host blocking/filtering an outbound SMTP port (this
	// project hit exactly that on Render). ResendFrom defaults to
	// Resend's own sandbox sender, which needs no domain verification but
	// can only deliver to the email address on your Resend account —
	// verify a real domain in the Resend dashboard to send to anyone else.
	ResendAPIKey string
	ResendFrom   string

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
	// FirebaseCredentialsJSONBase64 is FirebaseCredentialsPath's alternative
	// for a platform with no persistent/writable filesystem to put the key
	// file on — same reasoning, and same pattern, as
	// JWTPrivateKeyPEMBase64/JWTPrivateKeyPath. Takes priority over
	// FirebaseCredentialsPath when set (see cmd/api/main.go's setupPush).
	// Base64 of the service account JSON file's raw contents.
	FirebaseCredentialsJSONBase64 string
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

	// AdminPanelOrigin enables the operator panel's own login
	// (/admin/auth/*, /admin/accounts/*) and the credentialed CORS carve-out
	// those routes need — the exact origin (scheme + host, e.g.
	// "https://panel.example.com", no trailing slash) the panel is served
	// from. Browsers reject a credentialed (cookie-carrying) CORS response
	// against "*", so this can't reuse the wildcard the rest of the API's
	// CORS already allows — see httpserver.NewRouter's own doc comment on
	// the two separate CORS configs this produces.
	//
	// Empty (the default) disables /admin/auth/* and /admin/accounts/*
	// entirely, same opt-in-or-404 reasoning as AdminAPIToken/
	// TOTPEncryptionKeyBase64 — a login surface with no configured origin
	// to accept cookies from would be useless and shouldn't exist.
	AdminPanelOrigin string

	// AdminSessionCrossSite controls the panel's session cookie's SameSite
	// attribute: true means SameSite=None (the panel and the API are on
	// different registrable domains — true today, with both on separate
	// sslip.io addresses, since sslip.io is itself on the Public Suffix
	// List and so counts as a different "site" per subdomain), false means
	// SameSite=Strict (once both move under one real domain the operator
	// controls, e.g. panel.example.com + api.example.com). See
	// middleware.RequireAdminAccess's adminPanelHeader doc comment for the
	// CSRF mitigation that stays in effect regardless of this setting (and
	// is the actual reason SameSite=None is safe to use here, not just a
	// looser default). Defaults to true (None) — the safer assumption when
	// unset, since a same-domain deployment can always opt into Strict
	// explicitly once it's actually true.
	AdminSessionCrossSite bool

	// AdminSessionTTL bounds how long a panel login stays valid before
	// requiring a fresh one — independent of the end-user AccessTokenTTL,
	// since this is the highest-privilege session in the system and a
	// shorter lifetime is worth the extra logins.
	AdminSessionTTL time.Duration

	// AuditRetentionDays bounds how long an admin_audit_log entry survives
	// before the periodic cleanup removes it — see internal/audit.Service.
	// A plain int (days), not a time.Duration string, so setting it is as
	// simple as "365" rather than needing to spell out "8760h" — retention
	// is always thought about in days/months/years, never hours/minutes.
	// Configurable (not a fixed constant) because different institutions
	// can have different retention requirements, and that shouldn't need a
	// code change to adjust.
	AuditRetentionDays int
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

		PanelBaseURL: getEnv("PANEL_BASE_URL", ""),

		TrustedProxyCIDRs: getEnv("TRUSTED_PROXY_CIDRS", ""),

		BanReferenceSecret: getEnv("BAN_REFERENCE_SECRET", ""),

		TOTPEncryptionKeyBase64: getEnv("TOTP_ENCRYPTION_KEY", ""),
		TOTPIssuer:              getEnv("TOTP_ISSUER", "auth-2fa-api"),

		FirebaseCredentialsPath:       getEnv("FIREBASE_CREDENTIALS_PATH", ""),
		FirebaseCredentialsJSONBase64: getEnv("FIREBASE_CREDENTIALS_JSON_BASE64", ""),

		AdminPanelOrigin: getEnv("ADMIN_PANEL_ORIGIN", ""),
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
	if cfg.ChangeEmailTTL, err = getEnvDuration("CHANGE_EMAIL_TTL", time.Hour); err != nil {
		return nil, err
	}
	if cfg.ChangeEmailCodeLength, err = getEnvInt("CHANGE_EMAIL_CODE_LENGTH", 6); err != nil {
		return nil, err
	}
	if cfg.ChangeEmailMaxTries, err = getEnvInt("CHANGE_EMAIL_MAX_TRIES", 5); err != nil {
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
	if cfg.PinMaxFailedAttempts, err = getEnvInt("PIN_MAX_FAILED_ATTEMPTS", 5); err != nil {
		return nil, err
	}
	if cfg.PinLockMinutes, err = getEnvInt("PIN_LOCK_MINUTES", 15); err != nil {
		return nil, err
	}
	if cfg.LoginPinTTL, err = getEnvDuration("LOGIN_PIN_TTL", 5*time.Minute); err != nil {
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

	if cfg.AdminSessionCrossSite, err = getEnvBool("ADMIN_SESSION_CROSS_SITE", true); err != nil {
		return nil, err
	}
	if cfg.AdminSessionTTL, err = getEnvDuration("ADMIN_SESSION_TTL", 12*time.Hour); err != nil {
		return nil, err
	}
	if cfg.AuditRetentionDays, err = getEnvInt("AUDIT_RETENTION_DAYS", 365); err != nil {
		return nil, err
	}

	if cfg.JWTRefreshSecret == "" {
		return nil, fmt.Errorf("JWT_REFRESH_SECRET must be set")
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
