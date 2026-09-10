package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"log"
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
	"auth-2fa-api/internal/user"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("fatal: %v", err)
	}
}

func run() error {
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
	log.Println("connected to postgres")

	rdb, err := db.NewRedis(ctx, cfg.RedisURL)
	if err != nil {
		return err
	}
	defer rdb.Close()
	log.Println("connected to redis")

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

	router := httpserver.NewRouter(authHandlers, tokenMgr, userSvc, pgPool, rdb, apiClientSvc, cfg.TrustProxyHeaders)

	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("listening on :%s", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down...")

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
