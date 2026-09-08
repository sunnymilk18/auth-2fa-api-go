package auth

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"auth-2fa-api/internal/device"
	"auth-2fa-api/internal/mailer"
	"auth-2fa-api/internal/user"
)

// Service wires together password verification, OTP issuance/checking and
// JWT issuance into the full two-factor login flow, plus the trusted-device
// + PIN shortcut that lets a recognized device skip password+OTP.
type Service struct {
	users      *user.Service
	otp        *OTPStore
	tokens     *TokenManager
	refresh    *RefreshRepository
	devices    *device.Service
	mailer     mailer.Mailer
	otpTTL     time.Duration
	refreshTTL time.Duration
}

func NewService(
	users *user.Service,
	otp *OTPStore,
	tokens *TokenManager,
	refresh *RefreshRepository,
	devices *device.Service,
	m mailer.Mailer,
	otpTTL time.Duration,
	refreshTTL time.Duration,
) *Service {
	return &Service{
		users:      users,
		otp:        otp,
		tokens:     tokens,
		refresh:    refresh,
		devices:    devices,
		mailer:     m,
		otpTTL:     otpTTL,
		refreshTTL: refreshTTL,
	}
}

// Register creates a new user account, scoped to the calling api client.
func (s *Service) Register(ctx context.Context, apiClientID, email, password string) (*user.User, error) {
	return s.users.Register(ctx, apiClientID, email, password)
}

// LoginStep1 verifies email+password within one api client (tenant) and, on
// success, generates and emails an OTP code. It returns a login token the
// client must present in LoginStep2 along with the code — the code itself
// is never returned here.
func (s *Service) LoginStep1(ctx context.Context, apiClientID, email, password string) (loginToken string, err error) {
	u, err := s.users.VerifyPassword(ctx, apiClientID, email, password)
	if err != nil {
		return "", err
	}

	loginToken, code, err := s.otp.StartSession(ctx, u.ID, u.APIClientID, u.Email)
	if err != nil {
		return "", err
	}

	body := fmt.Sprintf(
		"Tu código de verificación es: %s\n\nExpira en %s. Si no solicitaste este código, ignora este correo.",
		code, s.otpTTL.String(),
	)
	if err := s.mailer.Send(ctx, u.Email, "Tu código de verificación", body); err != nil {
		return "", fmt.Errorf("sending otp email: %w", err)
	}

	return loginToken, nil
}

// LoginStep2 verifies the OTP code and, on success, issues a fresh
// access/refresh token pair.
func (s *Service) LoginStep2(ctx context.Context, loginToken, code string) (accessToken, refreshToken string, err error) {
	userID, apiClientID, email, err := s.otp.VerifyCode(ctx, loginToken, code)
	if err != nil {
		return "", "", err
	}
	return s.issueTokenPair(ctx, userID, apiClientID, email)
}

// issueTokenPair mints an access+refresh token pair for an already-verified
// user and persists the refresh token. Shared by every login path (password
// + OTP, device + PIN, and refresh rotation).
func (s *Service) issueTokenPair(ctx context.Context, userID, apiClientID, email string) (accessToken, refreshToken string, err error) {
	accessToken, err = s.tokens.IssueAccessToken(userID, apiClientID, email)
	if err != nil {
		return "", "", err
	}
	refreshToken, err = s.tokens.IssueRefreshToken(userID, apiClientID, email)
	if err != nil {
		return "", "", err
	}
	if err := s.refresh.Store(ctx, userID, refreshToken, time.Now().Add(s.refreshTTL)); err != nil {
		return "", "", err
	}
	return accessToken, refreshToken, nil
}

// Refresh validates a refresh token and issues a new access token, rotating
// the refresh token (old one revoked, new one issued) to limit replay risk.
func (s *Service) Refresh(ctx context.Context, refreshToken string) (accessToken, newRefreshToken string, err error) {
	claims, err := s.tokens.ParseRefreshToken(refreshToken)
	if err != nil {
		return "", "", ErrRefreshTokenInvalid
	}

	valid, err := s.refresh.IsValid(ctx, refreshToken)
	if err != nil {
		return "", "", err
	}
	if !valid {
		return "", "", ErrRefreshTokenInvalid
	}

	if err := s.refresh.Revoke(ctx, refreshToken); err != nil {
		return "", "", err
	}

	return s.issueTokenPair(ctx, claims.Subject, claims.APIClientID, claims.Email)
}

// Logout revokes a refresh token so it can no longer be used.
func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	return s.refresh.Revoke(ctx, refreshToken)
}

// PublicKey exposes the access-token signing key's public half, for JWKS.
func (s *Service) PublicKey() (*rsa.PublicKey, string) {
	return s.tokens.PublicKey()
}

// RegisterDevice marks deviceID as trusted for the already-authenticated
// userID (the caller must have just completed a full password+OTP login)
// and returns a device token the client must store securely — it's shown
// only once.
func (s *Service) RegisterDevice(ctx context.Context, userID, deviceID, deviceName, pin string) (deviceToken string, err error) {
	return s.devices.Register(ctx, userID, deviceID, deviceName, pin)
}

// DeviceLogin verifies a device_token + pin pair and, on success, issues a
// fresh access/refresh token pair — the trusted-device shortcut around
// password+OTP. It also returns a rotated device token that MUST replace
// the client's stored one; the old one stops working.
func (s *Service) DeviceLogin(ctx context.Context, deviceID, deviceToken, pin string) (accessToken, refreshToken, newDeviceToken string, err error) {
	userID, newDeviceToken, err := s.devices.VerifyPin(ctx, deviceID, deviceToken, pin)
	if err != nil {
		return "", "", "", err
	}

	u, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return "", "", "", err
	}

	accessToken, refreshToken, err = s.issueTokenPair(ctx, u.ID, u.APIClientID, u.Email)
	if err != nil {
		return "", "", "", err
	}
	return accessToken, refreshToken, newDeviceToken, nil
}

// ListDevices returns the authenticated user's trusted devices.
func (s *Service) ListDevices(ctx context.Context, userID string) ([]device.Info, error) {
	return s.devices.List(ctx, userID)
}

// RevokeDevice revokes one of the authenticated user's trusted devices.
func (s *Service) RevokeDevice(ctx context.Context, userID, deviceRowID string) error {
	return s.devices.Revoke(ctx, userID, deviceRowID)
}

var ErrUnauthorized = errors.New("unauthorized")
