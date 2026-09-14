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

	"auth-2fa-api/internal/apiclient"
	"auth-2fa-api/internal/auth"
	"auth-2fa-api/internal/config"
	"auth-2fa-api/internal/db"
	"auth-2fa-api/internal/device"
	"auth-2fa-api/internal/httpserver"
	"auth-2fa-api/internal/mailer"
	"auth-2fa-api/internal/telemetry"
	"auth-2fa-api/internal/user"
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
	userSvc := user.NewService(userRepo)

	privateKey, err := loadPrivateKey(cfg)
	if err != nil {
		return err
	}

	otpStore := auth.NewOTPStore(rdb, cfg.OTPTTL, cfg.OTPMaxTries, cfg.OTPLength)
	tokenMgr := auth.NewTokenManager(privateKey, cfg.JWTKeyID, cfg.JWTRefreshSecret, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)
	refreshRepo := auth.NewRefreshRepository(pgPool)
	passwordResetStore := auth.NewPasswordResetStore(rdb, cfg.PasswordResetTTL, cfg.PasswordResetMaxTries, cfg.PasswordResetCodeLength)
	emailVerificationStore := auth.NewEmailVerificationStore(rdb, cfg.EmailVerificationTTL, cfg.EmailVerificationMaxTries, cfg.EmailVerificationCodeLength)
	loginAttempts := auth.NewLoginAttemptLimiter(rdb, cfg.LoginMaxFailedAttempts, cfg.LoginLockoutWindow)

	deviceRepo := device.NewRepository(pgPool)
	deviceSvc := device.NewService(deviceRepo, cfg.DeviceTrustTTL, cfg.DevicePinMaxTries)

	apiClientRepo := apiclient.NewRepository(pgPool)
	apiClientSvc := apiclient.NewService(apiClientRepo)

	resendMailer := mailer.NewResendMailer(cfg.ResendAPIKey, cfg.ResendFrom)

	authSvc := auth.NewService(userSvc, otpStore, tokenMgr, refreshRepo, deviceSvc, passwordResetStore, emailVerificationStore, loginAttempts, resendMailer, cfg.OTPTTL, cfg.RefreshTokenTTL, cfg.PasswordResetTTL, cfg.EmailVerificationTTL)
	authHandlers := auth.NewHandlers(authSvc)

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

	router := httpserver.NewRouter(authHandlers, tokenMgr, userSvc, pgPool, rdb, apiClientSvc, cfg.TrustProxyHeaders, meter, cfg.AdminAPIToken, logger)

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

	<-ctx.Done()
	logger.Info("shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
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
