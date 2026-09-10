package auth_test

import (
	"testing"

	"auth-2fa-api/internal/auth"
	"auth-2fa-api/internal/device"
	"auth-2fa-api/internal/testutil"
)

func TestPasswordReset_FullFlow(t *testing.T) {
	svc, _, mailer, apiClientID := newTestService(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, apiClientID, email, "old-password-123")

	if err := svc.RequestPasswordReset(t.Context(), apiClientID, email); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	sent, ok := mailer.Last()
	if !ok {
		t.Fatal("RequestPasswordReset: no email was sent")
	}
	if sent.To != email {
		t.Fatalf("reset email sent to %q, want %q", sent.To, email)
	}
	code := testutil.ExtractResetCode(sent.Body)
	if code == "" {
		t.Fatalf("could not find a reset code in email body: %q", sent.Body)
	}

	if err := svc.ResetPassword(t.Context(), apiClientID, email, code, "new-password-456"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	// Old password no longer works; the new one does.
	if _, err := svc.LoginStep1(t.Context(), apiClientID, email, "old-password-123"); err == nil {
		t.Fatal("LoginStep1 with the old password: want an error, got nil")
	}
	if _, err := svc.LoginStep1(t.Context(), apiClientID, email, "new-password-456"); err != nil {
		t.Fatalf("LoginStep1 with the new password: unexpected error %v", err)
	}
}

func TestPasswordReset_UnknownEmailDoesNotErrorOrEmail(t *testing.T) {
	svc, _, mailer, apiClientID := newTestService(t)

	if err := svc.RequestPasswordReset(t.Context(), apiClientID, "nobody@example.com"); err != nil {
		t.Fatalf("RequestPasswordReset for an unknown email: want nil (must not leak whether the account exists), got %v", err)
	}
	if len(mailer.Sent()) != 0 {
		t.Fatal("RequestPasswordReset for an unknown email must not send anything")
	}
}

func TestPasswordReset_UnknownCode(t *testing.T) {
	svc, _, _, apiClientID := newTestService(t)
	if err := svc.ResetPassword(t.Context(), apiClientID, "nobody@example.com", "12345678", "new-password-456"); err != auth.ErrPasswordResetNotFound {
		t.Fatalf("err = %v, want %v", err, auth.ErrPasswordResetNotFound)
	}
}

func TestPasswordReset_WrongCode(t *testing.T) {
	svc, _, mailer, apiClientID := newTestService(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, apiClientID, email, "old-password-123")

	if err := svc.RequestPasswordReset(t.Context(), apiClientID, email); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	sent, _ := mailer.Last()
	code := testutil.ExtractResetCode(sent.Body)
	wrongCode := "0"
	if code == wrongCode {
		wrongCode = "1"
	}
	// Pad to the same length so it's a plausible-but-wrong code, not just a
	// different-length string.
	for len(wrongCode) < len(code) {
		wrongCode = "0" + wrongCode
	}

	if err := svc.ResetPassword(t.Context(), apiClientID, email, wrongCode, "new-password-456"); err != auth.ErrPasswordResetInvalidCode {
		t.Fatalf("err = %v, want %v", err, auth.ErrPasswordResetInvalidCode)
	}
}

func TestPasswordReset_CodeIsSingleUse(t *testing.T) {
	svc, _, mailer, apiClientID := newTestService(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, apiClientID, email, "old-password-123")

	if err := svc.RequestPasswordReset(t.Context(), apiClientID, email); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	sent, _ := mailer.Last()
	code := testutil.ExtractResetCode(sent.Body)

	if err := svc.ResetPassword(t.Context(), apiClientID, email, code, "new-password-456"); err != nil {
		t.Fatalf("first ResetPassword: %v", err)
	}
	if err := svc.ResetPassword(t.Context(), apiClientID, email, code, "yet-another-789"); err != auth.ErrPasswordResetNotFound {
		t.Fatalf("second ResetPassword with the same code: err = %v, want %v", err, auth.ErrPasswordResetNotFound)
	}
}

func TestPasswordReset_RevokesExistingSessions(t *testing.T) {
	svc, _, mailer, apiClientID := newTestService(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, apiClientID, email, "old-password-123")

	loginToken, err := svc.LoginStep1(t.Context(), apiClientID, email, "old-password-123")
	if err != nil {
		t.Fatalf("LoginStep1: %v", err)
	}
	otpSent, _ := mailer.Last()
	otpCode := testutil.ExtractOTPCode(otpSent.Body)
	_, refreshTok, err := svc.LoginStep2(t.Context(), loginToken, otpCode)
	if err != nil {
		t.Fatalf("LoginStep2: %v", err)
	}

	if err := svc.RequestPasswordReset(t.Context(), apiClientID, email); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	resetSent, _ := mailer.Last()
	resetCode := testutil.ExtractResetCode(resetSent.Body)
	if err := svc.ResetPassword(t.Context(), apiClientID, email, resetCode, "new-password-456"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	// The session obtained before the reset must no longer work.
	if _, _, err := svc.Refresh(t.Context(), refreshTok); err != auth.ErrRefreshTokenInvalid {
		t.Fatalf("Refresh with a pre-reset refresh token: err = %v, want %v", err, auth.ErrRefreshTokenInvalid)
	}
}

func TestPasswordReset_RevokesTrustedDevices(t *testing.T) {
	svc, tokens, mailer, apiClientID := newTestService(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, apiClientID, email, "old-password-123")

	loginToken, err := svc.LoginStep1(t.Context(), apiClientID, email, "old-password-123")
	if err != nil {
		t.Fatalf("LoginStep1: %v", err)
	}
	otpSent, _ := mailer.Last()
	otpCode := testutil.ExtractOTPCode(otpSent.Body)
	access, _, err := svc.LoginStep2(t.Context(), loginToken, otpCode)
	if err != nil {
		t.Fatalf("LoginStep2: %v", err)
	}
	claims, err := tokens.ParseAccessToken(access)
	if err != nil {
		t.Fatalf("parsing access token: %v", err)
	}

	deviceID := "device-" + testutil.UniqueSuffix(t)
	deviceToken, err := svc.RegisterDevice(t.Context(), claims.Subject, deviceID, "Test Phone", "123456")
	if err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}

	if err := svc.RequestPasswordReset(t.Context(), apiClientID, email); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	resetSent, _ := mailer.Last()
	resetCode := testutil.ExtractResetCode(resetSent.Body)
	if err := svc.ResetPassword(t.Context(), apiClientID, email, resetCode, "new-password-456"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	// The device that was trusted before the reset must no longer work —
	// otherwise whoever set it up (possibly an attacker) could keep
	// bypassing the new password entirely via the PIN shortcut.
	if _, _, _, err := svc.DeviceLogin(t.Context(), deviceID, deviceToken, "123456"); err != device.ErrDeviceNotTrusted {
		t.Fatalf("DeviceLogin with a pre-reset device token: err = %v, want %v", err, device.ErrDeviceNotTrusted)
	}
}

func TestPasswordReset_TooManyWrongCodesInvalidatesSession(t *testing.T) {
	svc, _, mailer, apiClientID := newTestService(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, apiClientID, email, "old-password-123")

	if err := svc.RequestPasswordReset(t.Context(), apiClientID, email); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	sent, _ := mailer.Last()
	code := testutil.ExtractResetCode(sent.Body)
	wrongCode := "0"
	if code == wrongCode {
		wrongCode = "1"
	}
	for len(wrongCode) < len(code) {
		wrongCode = "0" + wrongCode
	}

	// Default PASSWORD_RESET_MAX_TRIES in tests is whatever newTestService
	// wires up — exhaust attempts with the wrong code.
	var lastErr error
	for i := 0; i < 10; i++ {
		lastErr = svc.ResetPassword(t.Context(), apiClientID, email, wrongCode, "new-password-456")
		if lastErr == auth.ErrPasswordResetTooManyTries {
			break
		}
	}
	if lastErr != auth.ErrPasswordResetTooManyTries {
		t.Fatalf("after repeated wrong codes: last err = %v, want %v", lastErr, auth.ErrPasswordResetTooManyTries)
	}

	// Even the correct code no longer works — the session was invalidated.
	if err := svc.ResetPassword(t.Context(), apiClientID, email, code, "new-password-456"); err != auth.ErrPasswordResetNotFound {
		t.Fatalf("ResetPassword with the correct code after lockout: err = %v, want %v", err, auth.ErrPasswordResetNotFound)
	}
}
