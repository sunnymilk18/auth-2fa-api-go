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
	users            *user.Service
	otp              *OTPStore
	tokens           *TokenManager
	refresh          *RefreshRepository
	devices          *device.Service
	passwordReset    *PasswordResetStore
	loginAttempts    *LoginAttemptLimiter
	mailer           mailer.Mailer
	otpTTL           time.Duration
	refreshTTL       time.Duration
	passwordResetTTL time.Duration
}

func NewService(
	users *user.Service,
	otp *OTPStore,
	tokens *TokenManager,
	refresh *RefreshRepository,
	devices *device.Service,
	passwordReset *PasswordResetStore,
	loginAttempts *LoginAttemptLimiter,
	m mailer.Mailer,
	otpTTL time.Duration,
	refreshTTL time.Duration,
	passwordResetTTL time.Duration,
) *Service {
	return &Service{
		users:            users,
		otp:              otp,
		tokens:           tokens,
		refresh:          refresh,
		devices:          devices,
		passwordReset:    passwordReset,
		loginAttempts:    loginAttempts,
		mailer:           m,
		otpTTL:           otpTTL,
		refreshTTL:       refreshTTL,
		passwordResetTTL: passwordResetTTL,
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
//
// Guards against password-guessing spread across many IPs against one
// account (see LoginAttemptLimiter) — checked before, and recorded after,
// VerifyPassword itself, so an account that doesn't exist is throttled
// exactly the same way a real one would be (same as VerifyPassword's own
// error not distinguishing the two) — this must not become a way to probe
// which emails are registered.
func (s *Service) LoginStep1(ctx context.Context, apiClientID, email, password string) (loginToken string, err error) {
	locked, err := s.loginAttempts.IsLocked(ctx, apiClientID, email)
	if err != nil {
		return "", err
	}
	if locked {
		return "", ErrTooManyFailedLogins
	}

	u, err := s.users.VerifyPassword(ctx, apiClientID, email, password)
	if err != nil {
		if errors.Is(err, user.ErrInvalidCredentials) {
			// Best-effort: a Redis hiccup here shouldn't turn a legitimate
			// wrong-password response into a 500.
			_ = s.loginAttempts.RecordFailure(ctx, apiClientID, email)
		}
		return "", err
	}
	// Best-effort for the same reason — a stale counter after this just
	// means a slightly stricter throttle later, not a security hole.
	_ = s.loginAttempts.Reset(ctx, apiClientID, email)

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

// RequestPasswordReset emails a reset token if apiClientID/email matches an
// account. Always succeeds from the caller's point of view regardless of
// whether the account exists — same reasoning as VerifyPassword returning
// one error for both "no such user" and "wrong password": the response
// must not leak which emails are registered.
func (s *Service) RequestPasswordReset(ctx context.Context, apiClientID, email string) error {
	u, err := s.users.FindByEmail(ctx, apiClientID, email)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			return nil
		}
		return err
	}

	code, err := s.passwordReset.StartReset(ctx, u.ID, u.APIClientID, email)
	if err != nil {
		return err
	}

	body := fmt.Sprintf(
		"Usa este código para restablecer tu contraseña: %s\n\nExpira en %s. Si no solicitaste esto, ignora este correo.",
		code, s.passwordResetTTL.String(),
	)
	if err := s.mailer.Send(ctx, u.Email, "Restablece tu contraseña", body); err != nil {
		return fmt.Errorf("sending password reset email: %w", err)
	}
	return nil
}

// ResetPassword consumes a reset code and sets a new password. It also
// revokes every refresh token and every trusted device (PIN unlock) the
// user has — a password reset should force re-authentication everywhere:
// the trusted-device shortcut bypasses password+OTP entirely, so leaving it
// intact would let whoever set it up (possibly an attacker, during whatever
// compromise prompted the reset) keep getting in regardless of the new
// password.
func (s *Service) ResetPassword(ctx context.Context, apiClientID, email, code, newPassword string) error {
	userID, err := s.passwordReset.ConsumeCode(ctx, apiClientID, email, code)
	if err != nil {
		return err
	}
	if err := s.users.UpdatePassword(ctx, userID, newPassword); err != nil {
		return err
	}
	if err := s.refresh.RevokeAllForUser(ctx, userID); err != nil {
		return err
	}
	return s.devices.RevokeAllForUser(ctx, userID)
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
