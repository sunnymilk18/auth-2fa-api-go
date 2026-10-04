package auth

import (
	"context"
	"errors"
	"fmt"
)

// This file holds every Service method specific to the optional second
// factor beyond the emailed OTP: TOTP enrollment/verification/disabling,
// and the "email" branch of the first-login method choice
// (SendLoginEmailCode — its "authenticator app" branch lives here too, via
// ConfirmTOTPEnrollmentAndLogin). LoginStep1/LoginStep2 in service.go call
// into this file (verifyTOTPLogin, and the twoFactorSetup/totpLogin fields
// directly) but own the core login flow themselves — see service.go's own
// doc comments for that half.

// ErrTOTPNotConfigured is returned by every TOTP-related method when this
// deployment never set TOTP_ENCRYPTION_KEY — the feature is opt-in at the
// deployment level (see cmd/api/main.go), same as ADMIN_API_TOKEN gating
// /admin/*: absent config means the capability doesn't exist here, not
// "exists but insecure".
var ErrTOTPNotConfigured = errors.New("totp is not configured on this server")

// SendLoginEmailCode is the "email" branch of the first-login choice (see
// LoginStep1's doc comment): the client already has a pending-setup
// loginToken from LoginStep1 (needsSetup == true) and picked email instead
// of the authenticator app. Generates and sends the OTP code under that
// SAME token — the client keeps using it with LoginStep2/VerifyOTP exactly
// like any other email login from here on, no second token to juggle.
func (s *Service) SendLoginEmailCode(ctx context.Context, loginToken string) error {
	if s.twoFactorSetup == nil {
		return ErrTOTPNotConfigured
	}

	sess, found, err := s.twoFactorSetup.Peek(ctx, loginToken)
	if err != nil {
		return err
	}
	if !found {
		return ErrLoginSessionNotFound
	}

	code, err := s.otp.StartSessionWithToken(ctx, loginToken, sess.UserID, sess.APIClientID, sess.Email)
	if err != nil {
		return err
	}
	// The account has now committed to email — consume the setup session
	// (the login_token belongs to the OTP store from here on) and mark the
	// choice made, so this screen never appears again for this account.
	if err := s.twoFactorSetup.Consume(ctx, loginToken); err != nil {
		return err
	}
	_ = s.users.MarkTwoFactorMethodChosen(ctx, sess.UserID)

	body := fmt.Sprintf(
		"Tu código de verificación es: %s\n\nExpira en %s. Si no solicitaste este código, ignora este correo.",
		code, humanDuration(s.otpTTL),
	)
	if err := s.mailer.Send(ctx, sess.Email, "Tu código de verificación", body); err != nil {
		return fmt.Errorf("sending otp email: %w", err)
	}
	return nil
}

// verifyTOTPLogin checks code against sess's account's TOTP secret,
// rate-limited the same way password guesses are (see loginAttempts) so a
// login token alone (already gated behind a correct password) can't be
// used to brute-force the 10^6 possible codes. Keyed by "totp:"+loginToken
// rather than the account id — this counter is about how many guesses this
// one login attempt gets, not the account's overall failed-login history,
// which loginAttempts already tracks separately in LoginStep1. Called only
// from LoginStep2 (service.go), once it already confirmed loginToken
// belongs to a pending TOTP login, not the email-OTP flow.
func (s *Service) verifyTOTPLogin(ctx context.Context, loginToken string, sess pendingLoginSession, code string) (LoginResult, error) {
	lockoutKey := "totp:" + loginToken

	locked, _, err := s.loginAttempts.IsLocked(ctx, sess.APIClientID, lockoutKey)
	if err != nil {
		return LoginResult{}, err
	}
	if locked {
		_ = s.totpLogin.Consume(ctx, loginToken)
		return LoginResult{}, ErrTooManyAttempts
	}

	encryptedSecret, enabled, err := s.users.GetTOTPSecret(ctx, sess.UserID)
	if err != nil {
		return LoginResult{}, err
	}
	if !enabled || encryptedSecret == "" {
		// The account disabled TOTP after LoginStep1 issued this token
		// (e.g. from another device/tab) — nothing left to verify against.
		_ = s.totpLogin.Consume(ctx, loginToken)
		return LoginResult{}, ErrInvalidTOTPCode
	}

	secret, err := s.totp.Decrypt(encryptedSecret)
	if err != nil {
		return LoginResult{}, err
	}

	if !s.totp.ValidateCode(secret, code) {
		_ = s.loginAttempts.RecordFailure(ctx, sess.APIClientID, lockoutKey)
		return LoginResult{}, ErrInvalidTOTPCode
	}

	_ = s.loginAttempts.Reset(ctx, sess.APIClientID, lockoutKey)
	if err := s.totpLogin.Consume(ctx, loginToken); err != nil {
		return LoginResult{}, err
	}
	return s.finishLogin(ctx, sess.UserID, sess.APIClientID, sess.Email)
}

// StartTOTPEnrollment generates a new TOTP secret for the already
// password+OTP-authenticated userID and stores it encrypted, but NOT yet
// enabled — LoginStep1 won't start expecting a TOTP code for this account
// until ConfirmTOTPEnrollment proves the user actually scanned the QR and
// their app is producing matching codes. Returns the otpauth:// URL a
// client renders as a QR code (or shows as a manual-entry secret).
func (s *Service) StartTOTPEnrollment(ctx context.Context, userID, email string) (otpauthURL string, err error) {
	if s.totp == nil {
		return "", ErrTOTPNotConfigured
	}

	secret, otpauthURL, err := s.totp.GenerateSecret(email)
	if err != nil {
		return "", err
	}
	encrypted, err := s.totp.Encrypt(secret)
	if err != nil {
		return "", err
	}
	if err := s.users.SetPendingTOTPSecret(ctx, userID, encrypted); err != nil {
		return "", err
	}
	return otpauthURL, nil
}

// ConfirmTOTPEnrollment validates code against the pending secret set by
// StartTOTPEnrollment and, on success, enables it — from then on,
// LoginStep1 sends this account through the TOTP path instead of emailing
// a code.
func (s *Service) ConfirmTOTPEnrollment(ctx context.Context, userID, code string) error {
	if s.totp == nil {
		return ErrTOTPNotConfigured
	}

	encryptedSecret, _, err := s.users.GetTOTPSecret(ctx, userID)
	if err != nil {
		return err
	}
	if encryptedSecret == "" {
		return ErrInvalidTOTPCode
	}
	secret, err := s.totp.Decrypt(encryptedSecret)
	if err != nil {
		return err
	}
	if !s.totp.ValidateCode(secret, code) {
		return ErrInvalidTOTPCode
	}
	if err := s.users.EnableTOTP(ctx, userID); err != nil {
		return err
	}
	// Idempotent — a no-op for an account changing methods later that had
	// already chosen one; the meaningful case is the first-login setup
	// flow (see ConfirmTOTPEnrollmentAndLogin), where this is what actually
	// marks the choice made.
	return s.users.MarkTwoFactorMethodChosen(ctx, userID)
}

// PeekTwoFactorSetup resolves a pending first-login loginToken (see
// LoginStep1's doc comment) to the account it belongs to, without consuming
// it — used by EnrollTOTP's setup-flow path (no access_token exists yet at
// this point) to know which account to generate a secret for. Doesn't
// commit to anything on its own: the client can still back out and pick
// email instead via SendLoginEmailCode, or call this again to get a fresh
// secret if it wants to re-scan.
func (s *Service) PeekTwoFactorSetup(ctx context.Context, loginToken string) (userID, email string, err error) {
	if s.twoFactorSetup == nil {
		return "", "", ErrTOTPNotConfigured
	}
	sess, found, err := s.twoFactorSetup.Peek(ctx, loginToken)
	if err != nil {
		return "", "", err
	}
	if !found {
		return "", "", ErrLoginSessionNotFound
	}
	return sess.UserID, sess.Email, nil
}

// ConfirmTOTPEnrollmentAndLogin is the "authenticator app" branch of the
// first-login choice (see LoginStep1's doc comment): validates code against
// the secret StartTOTPEnrollment generated for the account behind
// loginToken, and — unlike the regular ConfirmTOTPEnrollment, which is
// called from an already-authenticated settings screen — completes the
// login right there, issuing a token pair directly. There's no separate
// VerifyOTP step for this path: confirming the code both activates TOTP and
// finishes the login in one call.
func (s *Service) ConfirmTOTPEnrollmentAndLogin(ctx context.Context, loginToken, code string) (LoginResult, error) {
	if s.twoFactorSetup == nil {
		return LoginResult{}, ErrTOTPNotConfigured
	}
	sess, found, err := s.twoFactorSetup.Peek(ctx, loginToken)
	if err != nil {
		return LoginResult{}, err
	}
	if !found {
		return LoginResult{}, ErrLoginSessionNotFound
	}

	if err := s.ConfirmTOTPEnrollment(ctx, sess.UserID, code); err != nil {
		return LoginResult{}, err
	}
	if err := s.twoFactorSetup.Consume(ctx, loginToken); err != nil {
		return LoginResult{}, err
	}
	return s.finishLogin(ctx, sess.UserID, sess.APIClientID, sess.Email)
}

// DisableTOTP turns the TOTP second factor off — login falls back to the
// email OTP flow. No code confirmation required, same bar as RevokeDevice:
// a valid access token (already-authenticated session) is enough.
func (s *Service) DisableTOTP(ctx context.Context, userID string) error {
	return s.users.DisableTOTP(ctx, userID)
}
