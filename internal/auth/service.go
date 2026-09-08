package auth

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"auth-2fa-api/internal/mailer"
	"auth-2fa-api/internal/user"
)

// Service wires together password verification, OTP issuance/checking and
// JWT issuance into the full two-factor login flow.
type Service struct {
	users      *user.Service
	otp        *OTPStore
	tokens     *TokenManager
	refresh    *RefreshRepository
	mailer     mailer.Mailer
	otpTTL     time.Duration
	refreshTTL time.Duration
}

func NewService(
	users *user.Service,
	otp *OTPStore,
	tokens *TokenManager,
	refresh *RefreshRepository,
	m mailer.Mailer,
	otpTTL time.Duration,
	refreshTTL time.Duration,
) *Service {
	return &Service{
		users:      users,
		otp:        otp,
		tokens:     tokens,
		refresh:    refresh,
		mailer:     m,
		otpTTL:     otpTTL,
		refreshTTL: refreshTTL,
	}
}

// Register creates a new user account.
func (s *Service) Register(ctx context.Context, email, password string) (*user.User, error) {
	return s.users.Register(ctx, email, password)
}

// LoginStep1 verifies email+password and, on success, generates and emails
// an OTP code. It returns a login token the client must present in
// LoginStep2 along with the code — the code itself is never returned here.
func (s *Service) LoginStep1(ctx context.Context, email, password string) (loginToken string, err error) {
	u, err := s.users.VerifyPassword(ctx, email, password)
	if err != nil {
		return "", err
	}

	loginToken, code, err := s.otp.StartSession(ctx, u.ID, u.Email)
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
	userID, email, err := s.otp.VerifyCode(ctx, loginToken, code)
	if err != nil {
		return "", "", err
	}

	accessToken, err = s.tokens.IssueAccessToken(userID, email)
	if err != nil {
		return "", "", err
	}
	refreshToken, err = s.tokens.IssueRefreshToken(userID, email)
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

	accessToken, err = s.tokens.IssueAccessToken(claims.Subject, claims.Email)
	if err != nil {
		return "", "", err
	}
	newRefreshToken, err = s.tokens.IssueRefreshToken(claims.Subject, claims.Email)
	if err != nil {
		return "", "", err
	}
	if err := s.refresh.Store(ctx, claims.Subject, newRefreshToken, time.Now().Add(s.refreshTTL)); err != nil {
		return "", "", err
	}

	return accessToken, newRefreshToken, nil
}

// Logout revokes a refresh token so it can no longer be used.
func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	return s.refresh.Revoke(ctx, refreshToken)
}

// PublicKey exposes the access-token signing key's public half, for JWKS.
func (s *Service) PublicKey() (*rsa.PublicKey, string) {
	return s.tokens.PublicKey()
}

var ErrUnauthorized = errors.New("unauthorized")
