package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	// Embeds the full IANA timezone database into the binary — GET
	// /admin/stats accepts an arbitrary tz query param (e.g.
	// "America/Santiago") and resolves it via time.LoadLocation, which
	// otherwise depends on the OS shipping a tzdata package. The runtime
	// image is alpine:3.20 with only ca-certificates installed (see
	// Dockerfile), so without this blank import every non-UTC tz would
	// fail in production with "unknown time zone" even though the exact
	// same binary works fine on a developer's machine (most OSes already
	// have tzdata installed system-wide).
	_ "time/tzdata"

	"auth-2fa-api/internal/adminauth"
	"auth-2fa-api/internal/apiclient"
	"auth-2fa-api/internal/audit"
	"auth-2fa-api/internal/auth"
	"auth-2fa-api/internal/authevents"
	"auth-2fa-api/internal/config"
	"auth-2fa-api/internal/db"
	"auth-2fa-api/internal/device"
	"auth-2fa-api/internal/httpserver"
	"auth-2fa-api/internal/mailer"
	"auth-2fa-api/internal/middleware"
	"auth-2fa-api/internal/push"
	"auth-2fa-api/internal/telemetry"
	"auth-2fa-api/internal/user"

	"github.com/redis/go-redis/v9"
)

func main() {
	// Set up structured logging before anything else — every log line
	// from here on (including run()'s own fatal error, if any) goes
	// through this, so it's JSON on stdout (Dokploy/`docker logs` keep
	// working exactly as before) and, when configured, also shipped via
	// OTLP to the collector for Loki. See SetupLogging's doc comment.
	logger, shutdownLogging, err := telemetry.SetupLogging(context.Background(), os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"), "auth-2fa-api")
	if err != nil {
		// SetupLogging still returns a usable stdout-only *slog.Logger even
		// when the OTLP half fails to set up — log the failure through it
		// and keep going; logging is not worth failing startup over.
		logger.Error("telemetry logging setup failed, continuing with stdout-only logging", "error", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shutdownLogging(shutdownCtx)
	}()

	if err := run(logger); err != nil {
		logger.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	trustedProxyCIDRs, invalidProxyCIDRs := middleware.ValidateTrustedProxyCIDRs(cfg.TrustedProxyCIDRs)
	if len(invalidProxyCIDRs) > 0 {
		logger.Warn("TRUSTED_PROXY_CIDRS has invalid entries, ignoring them", "invalid", invalidProxyCIDRs)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pgPool, err := db.NewPostgres(ctx, cfg.PostgresDSN)
	if err != nil {
		return err
	}
	defer pgPool.Close()
	logger.Info("connected to postgres")

	rdb, err := db.NewRedis(ctx, cfg.RedisURL)
	if err != nil {
		return err
	}
	defer rdb.Close()
	logger.Info("connected to redis")

	// Wiring: repositories -> services -> handlers.
	userRepo := user.NewRepository(pgPool)
	userSvc := user.NewService(userRepo, cfg.PinMaxFailedAttempts, time.Duration(cfg.PinLockMinutes)*time.Minute)

	privateKey, err := loadPrivateKey(cfg)
	if err != nil {
		return err
	}

	otpStore := auth.NewOTPStore(rdb, cfg.OTPTTL, cfg.OTPMaxTries, cfg.OTPLength)
	tokenMgr := auth.NewTokenManager(privateKey, cfg.JWTKeyID, cfg.JWTRefreshSecret, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)
	if err := addPreviousVerificationKey(tokenMgr, cfg); err != nil {
		return err
	}
	refreshRepo := auth.NewRefreshRepository(pgPool)
	passwordResetStore := auth.NewPasswordResetStore(rdb, cfg.PasswordResetTTL, cfg.PasswordResetMaxTries, cfg.PasswordResetCodeLength)
	emailVerificationStore := auth.NewEmailVerificationStore(rdb, cfg.EmailVerificationTTL, cfg.EmailVerificationMaxTries, cfg.EmailVerificationCodeLength)
	changeEmailStore := auth.NewChangeEmailStore(rdb, cfg.ChangeEmailTTL, cfg.ChangeEmailMaxTries, cfg.ChangeEmailCodeLength)
	loginAttempts := auth.NewLoginAttemptLimiter(rdb, cfg.LoginMaxFailedAttempts, cfg.LoginLockoutWindow)

	deviceRepo := device.NewRepository(pgPool)
	deviceSvc := device.NewService(deviceRepo, cfg.DeviceTrustTTL)

	apiClientRepo := apiclient.NewRepository(pgPool)
	apiClientSvc := apiclient.NewService(apiClientRepo)

	resendMailer := mailer.NewResendMailer(cfg.ResendAPIKey, cfg.ResendFrom)

	totpManager, totpLoginStore, twoFactorSetupStore, err := setupTOTP(cfg, rdb)
	if err != nil {
		return err
	}

	pushClient, err := setupPush(ctx, cfg)
	if err != nil {
		return err
	}
	var pushLoginStore *auth.PushLoginStore
	var pushRequestLimiter *auth.PushRequestLimiter
	if pushClient != nil {
		pushLoginStore = auth.NewPushLoginStore(rdb, cfg.PushLoginTTL)
		pushRequestLimiter = auth.NewPushRequestLimiter(rdb, cfg.PushMaxRequests, int(cfg.PushRequestWindow.Seconds()))
		logger.Info("push approval configured")
	}

	// ttl matches AccessTokenTTL: once that much time passes since a
	// revocation marker was set, everything it was protecting against has
	// expired on its own anyway — see AccessRevocationStore's doc comment.
	accessRevocation := auth.NewAccessRevocationStore(rdb, cfg.AccessTokenTTL)

	loginPinStore := auth.NewPinLoginStore(rdb, cfg.LoginPinTTL)

	// OTEL_EXPORTER_OTLP_ENDPOINT unset -> SetupMetrics returns a no-op
	// shutdown and the meter stays a no-op too; metrics are an optional
	// extra, not something that should block startup or need its own
	// on/off flag.
	shutdownMetrics, err := telemetry.SetupMetrics(ctx, os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"), "auth-2fa-api")
	if err != nil {
		return fmt.Errorf("setting up telemetry: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shutdownMetrics(shutdownCtx)
	}()
	meter := telemetry.Meter("auth-2fa-api")

	// Always constructed (unlike adminAccounts below) — the audit log
	// covers every /admin/* action, including the X-Admin-Token/script
	// path, which exists independently of whether the panel's own login
	// (TOTP) is configured at all.
	auditSvc := audit.NewService(audit.NewRepository(pgPool), time.Duration(cfg.AuditRetentionDays)*24*time.Hour, meter, logger)

	// Always constructed, same as auditSvc — see authevents.Service.Log's
	// own doc comment for why a nil-safe, best-effort write never needs a
	// feature flag the way TOTP/push do.
	if cfg.AuthEventsEmailHashSecret == "" {
		logger.Warn("AUTH_EVENTS_EMAIL_HASH_SECRET not set — auth_events.email_hash will be empty for every attempt against an unknown identifier")
	}
	authEventsSvc := authevents.NewService(
		authevents.NewRepository(pgPool),
		time.Duration(cfg.AuthEventsRetentionDays)*24*time.Hour,
		[]byte(cfg.AuthEventsEmailHashSecret),
		meter, logger,
	)

	authSvc := auth.NewService(userSvc, otpStore, tokenMgr, refreshRepo, deviceSvc, passwordResetStore, emailVerificationStore, changeEmailStore, loginAttempts, resendMailer, cfg.OTPTTL, cfg.RefreshTokenTTL, cfg.PasswordResetTTL, cfg.EmailVerificationTTL, cfg.ChangeEmailTTL, totpManager, totpLoginStore, twoFactorSetupStore, pushClient, pushLoginStore, pushRequestLimiter, logger, accessRevocation, apiClientSvc, cfg.PanelBaseURL, loginPinStore, authEventsSvc, trustedProxyCIDRs)
	authHandlers := auth.NewHandlers(authSvc)

	// nil when TOTP isn't configured server-wide (TOTPEncryptionKeyBase64
	// unset) — an admin account's TOTP secret can't be encrypted at rest
	// without it, and TOTP is mandatory for every admin account (see
	// adminauth's own doc comments), so the operator panel's login simply
	// doesn't exist in that case, same as /auth/totp/* itself. Reuses
	// loginAttempts (the same limiter end-user login already uses) under
	// its own fixed namespace — see adminauth.loginLimiterNamespace.
	var adminAccounts *adminauth.Service
	var adminSessions *adminauth.SessionRepository
	if totpManager != nil {
		adminSessions = adminauth.NewSessionRepository(pgPool)
		adminAccounts = adminauth.NewService(
			adminauth.NewAccountRepository(pgPool),
			adminSessions,
			adminauth.NewTOTPRotationStore(rdb),
			totpManager,
			loginAttempts,
			cfg.AdminSessionTTL,
		)
	}

	router := httpserver.NewRouter(authHandlers, authSvc, tokenMgr, accessRevocation, userSvc, pgPool, rdb, apiClientSvc, meter, cfg.AdminAPIToken, totpManager != nil, pushClient != nil, trustedProxyCIDRs, []byte(cfg.BanReferenceSecret), adminAccounts, cfg.AdminPanelOrigin, cfg.AdminSessionCrossSite, cfg.AdminSessionTTL, auditSvc, authEventsSvc, logger)

	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		logger.Info("listening", "port", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	go cleanupExpiredRefreshTokens(ctx, refreshRepo, logger)
	if adminSessions != nil {
		go cleanupExpiredAdminSessions(ctx, adminSessions, logger)
	}
	go cleanupExpiredAuditLog(ctx, auditSvc, logger)
	go cleanupExpiredAuthEvents(ctx, authEventsSvc, logger)

	<-ctx.Done()
	logger.Info("shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// cleanupExpiredRefreshTokens runs once at startup (so a fresh deploy
// doesn't wait a full day for the first sweep) and then once every 24h
// until ctx is cancelled, deleting refresh_tokens rows past their
// expires_at — see RefreshRepository.DeleteExpired's doc comment for why
// this exists: IsValid rejects expired tokens but never removes them, so
// the table grows unbounded without a periodic sweep. Safe to run from
// more than one instance at once (each run is just a DELETE ... WHERE, no
// coordination needed) if this ever moves to a multi-replica deployment.
func cleanupExpiredRefreshTokens(ctx context.Context, refreshRepo *auth.RefreshRepository, logger *slog.Logger) {
	sweep := func() {
		n, err := refreshRepo.DeleteExpired(ctx)
		if err != nil {
			logger.Error("refresh token cleanup failed", "error", err)
			return
		}
		if n > 0 {
			logger.Info("refresh token cleanup", "deleted", n)
		}
	}

	sweep()

	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweep()
		}
	}
}

// cleanupExpiredAuditLog is cleanupExpiredRefreshTokens' exact counterpart
// for admin_audit_log — same once-at-startup-then-every-24h cadence,
// removing entries older than AUDIT_RETENTION_DAYS (see audit.Service.
// DeleteExpired).
func cleanupExpiredAuditLog(ctx context.Context, auditSvc *audit.Service, logger *slog.Logger) {
	sweep := func() {
		n, err := auditSvc.DeleteExpired(ctx)
		if err != nil {
			logger.Error("audit log cleanup failed", "error", err)
			return
		}
		if n > 0 {
			logger.Info("audit log cleanup", "deleted", n)
		}
	}

	sweep()

	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweep()
		}
	}
}

// cleanupExpiredAuthEvents is cleanupExpiredAuditLog's exact counterpart
// for auth_events — same once-at-startup-then-every-24h cadence, removing
// entries older than AUTH_EVENTS_RETENTION_DAYS (see authevents.Service.
// DeleteExpired).
func cleanupExpiredAuthEvents(ctx context.Context, authEventsSvc *authevents.Service, logger *slog.Logger) {
	sweep := func() {
		n, err := authEventsSvc.DeleteExpired(ctx)
		if err != nil {
			logger.Error("auth events cleanup failed", "error", err)
			return
		}
		if n > 0 {
			logger.Info("auth events cleanup", "deleted", n)
		}
	}

	sweep()

	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweep()
		}
	}
}

// cleanupExpiredAdminSessions is cleanupExpiredRefreshTokens' exact
// counterpart for admin_sessions — same reasoning (SessionRepository.
// FindValidAccountID rejects an expired/revoked row but never removes it)
// and same once-at-startup-then-every-24h cadence. Only started when the
// operator panel's login is actually configured (adminSessions != nil —
// see this file's own wiring of adminauth.Service).
func cleanupExpiredAdminSessions(ctx context.Context, sessions *adminauth.SessionRepository, logger *slog.Logger) {
	sweep := func() {
		n, err := sessions.DeleteExpired(ctx)
		if err != nil {
			logger.Error("admin session cleanup failed", "error", err)
			return
		}
		if n > 0 {
			logger.Info("admin session cleanup", "deleted", n)
		}
	}

	sweep()

	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweep()
		}
	}
}

// loadPrivateKey prefers JWTPrivateKeyPEMBase64 (a platform env var) over
// JWTPrivateKeyPath (a file on disk) when both are set — see Config's doc
// comment on why a platform without a persistent/writable filesystem needs
// the env-var form.
func loadPrivateKey(cfg *config.Config) (*rsa.PrivateKey, error) {
	if cfg.JWTPrivateKeyPEMBase64 != "" {
		pemBytes, err := base64.StdEncoding.DecodeString(cfg.JWTPrivateKeyPEMBase64)
		if err != nil {
			return nil, fmt.Errorf("decoding JWT_PRIVATE_KEY_PEM_BASE64: %w", err)
		}
		return auth.ParsePrivateKeyPEM(pemBytes)
	}
	return auth.LoadPrivateKey(cfg.JWTPrivateKeyPath)
}

// addPreviousVerificationKey wires in the previous signing key's public
// half, if configured, so access tokens issued right before a JWT key
// rotation stay verifiable during the overlap window — see
// auth.TokenManager.AddVerificationKey and README's "Rotación de claves
// JWT". A no-op (not an error) when neither JWT_PREVIOUS_KEY_ID nor
// JWT_PREVIOUS_PUBLIC_KEY_PEM_BASE64 is set, which is the normal case
// outside of an active rotation.
func addPreviousVerificationKey(tokenMgr *auth.TokenManager, cfg *config.Config) error {
	if cfg.JWTPreviousKeyID == "" && cfg.JWTPreviousPublicKeyPEMBase64 == "" {
		return nil
	}
	if cfg.JWTPreviousKeyID == "" || cfg.JWTPreviousPublicKeyPEMBase64 == "" {
		return fmt.Errorf("JWT_PREVIOUS_KEY_ID and JWT_PREVIOUS_PUBLIC_KEY_PEM_BASE64 must be set together")
	}

	pemBytes, err := base64.StdEncoding.DecodeString(cfg.JWTPreviousPublicKeyPEMBase64)
	if err != nil {
		return fmt.Errorf("decoding JWT_PREVIOUS_PUBLIC_KEY_PEM_BASE64: %w", err)
	}
	pub, err := auth.ParsePublicKeyPEM(pemBytes)
	if err != nil {
		return fmt.Errorf("parsing JWT_PREVIOUS_PUBLIC_KEY_PEM_BASE64: %w", err)
	}

	tokenMgr.AddVerificationKey(cfg.JWTPreviousKeyID, pub)
	return nil
}

// setupTOTP builds the TOTP manager/login store/setup store when
// TOTP_ENCRYPTION_KEY is configured — see Config.TOTPEncryptionKeyBase64's
// doc comment for why this is opt-in rather than always-on. All three
// return values are nil (not an error) when unset; auth.Service treats a
// nil totp/totpLogin/twoFactorSetup as "feature not configured" rather than
// requiring every caller here to branch on it.
func setupTOTP(cfg *config.Config, rdb *redis.Client) (*auth.TOTPManager, *auth.TOTPLoginStore, *auth.TwoFactorSetupStore, error) {
	if cfg.TOTPEncryptionKeyBase64 == "" {
		return nil, nil, nil, nil
	}

	key, err := base64.StdEncoding.DecodeString(cfg.TOTPEncryptionKeyBase64)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decoding TOTP_ENCRYPTION_KEY: %w", err)
	}
	totpManager, err := auth.NewTOTPManager(cfg.TOTPIssuer, key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("setting up totp: %w", err)
	}
	return totpManager, auth.NewTOTPLoginStore(rdb, cfg.OTPTTL), auth.NewTwoFactorSetupStore(rdb, cfg.OTPTTL), nil
}

// setupPush builds the Firebase Cloud Messaging client when either
// FIREBASE_CREDENTIALS_PATH or FIREBASE_CREDENTIALS_JSON_BASE64 is
// configured — see Config.FirebaseCredentialsPath's doc comment for why
// this is opt-in rather than always-on. A nil, non-error return means the
// feature isn't configured; auth.Service treats a nil push client the same
// way it treats a nil totp/totpLogin.
func setupPush(ctx context.Context, cfg *config.Config) (*push.Client, error) {
	credentialsJSON, err := loadFirebaseCredentials(cfg)
	if err != nil {
		return nil, fmt.Errorf("setting up push: %w", err)
	}
	if credentialsJSON == nil {
		return nil, nil
	}
	client, err := push.NewClient(ctx, credentialsJSON)
	if err != nil {
		return nil, fmt.Errorf("setting up push: %w", err)
	}
	return client, nil
}

// loadFirebaseCredentials prefers FirebaseCredentialsJSONBase64 (a platform
// env var) over FirebaseCredentialsPath (a file on disk) when both are set
// — same precedence, and the same reasoning, as loadPrivateKey above: a
// deploy target with no persistent/writable filesystem (or, as it turned
// out here, one where the configured bind mount silently isn't what the
// running container actually sees) needs the env-var form. Returns a nil
// slice (not an error) when neither is set — the caller treats that as
// "push not configured", not "misconfigured".
func loadFirebaseCredentials(cfg *config.Config) ([]byte, error) {
	if cfg.FirebaseCredentialsJSONBase64 != "" {
		raw, err := base64.StdEncoding.DecodeString(cfg.FirebaseCredentialsJSONBase64)
		if err != nil {
			return nil, fmt.Errorf("decoding FIREBASE_CREDENTIALS_JSON_BASE64: %w", err)
		}
		return raw, nil
	}
	if cfg.FirebaseCredentialsPath == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(cfg.FirebaseCredentialsPath)
	if err != nil {
		return nil, fmt.Errorf("reading FIREBASE_CREDENTIALS_PATH: %w", err)
	}
	return raw, nil
}
