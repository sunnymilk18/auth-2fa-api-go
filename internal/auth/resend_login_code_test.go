package auth_test

import (
	"testing"

	"auth-2fa-api/internal/auth"
	"auth-2fa-api/internal/testutil"
)

func TestResendLoginOTP_SendsFreshCodeUnderSameToken(t *testing.T) {
	svc, _, mailer, apiClientID := newTestService(t)

	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")

	loginToken, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery")
	if err != nil {
		t.Fatalf("LoginStep1: %v", err)
	}
	firstSent, ok := mailer.Last()
	if !ok {
		t.Fatal("LoginStep1: no OTP email was sent")
	}
	firstCode := testutil.ExtractOTPCode(firstSent.Body)

	if err := svc.ResendLoginOTP(t.Context(), loginToken); err != nil {
		t.Fatalf("ResendLoginOTP: %v", err)
	}
	secondSent, ok := mailer.Last()
	if !ok {
		t.Fatal("ResendLoginOTP: no OTP email was sent")
	}
	if secondSent.To != email {
		t.Fatalf("email sent to %q, want %q", secondSent.To, email)
	}
	secondCode := testutil.ExtractOTPCode(secondSent.Body)
	if secondCode == firstCode {
		t.Fatal("ResendLoginOTP: resent code is identical to the original — should be freshly generated")
	}

	// The old code, issued before the resend, must no longer work — the
	// session it belonged to was overwritten.
	if _, _, err := svc.LoginStep2(t.Context(), loginToken, firstCode); err != auth.ErrInvalidCode {
		t.Fatalf("LoginStep2 with the pre-resend code: err = %v, want ErrInvalidCode", err)
	}

	// The same loginToken, with the newly resent code, completes the login.
	access, refresh, err := svc.LoginStep2(t.Context(), loginToken, secondCode)
	if err != nil {
		t.Fatalf("LoginStep2 with the resent code: %v", err)
	}
	if access == "" || refresh == "" {
		t.Fatal("LoginStep2 returned empty tokens")
	}
}

func TestResendLoginOTP_UnknownToken(t *testing.T) {
	svc, _, _, _ := newTestService(t)

	if err := svc.ResendLoginOTP(t.Context(), "does-not-exist"); err != auth.ErrLoginSessionNotFound {
		t.Fatalf("ResendLoginOTP with unknown token: err = %v, want ErrLoginSessionNotFound", err)
	}
}

func TestResendLoginOTP_TOTPAccount_ReturnsClearError(t *testing.T) {
	svc, tokens, mailer, apiClientID := newTestService(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")
	userID, _, _ := mustLoginFull(t, svc, tokens, mailer, apiClientID, email, "correcthorsebattery")

	otpauthURL, err := svc.StartTOTPEnrollment(t.Context(), userID, email)
	if err != nil {
		t.Fatalf("StartTOTPEnrollment: %v", err)
	}
	if err := svc.ConfirmTOTPEnrollment(t.Context(), userID, totpCodeFromOTPAuthURL(t, otpauthURL)); err != nil {
		t.Fatalf("ConfirmTOTPEnrollment: %v", err)
	}

	loginToken, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery")
	if err != nil {
		t.Fatalf("LoginStep1 after enabling TOTP: %v", err)
	}

	if err := svc.ResendLoginOTP(t.Context(), loginToken); err != auth.ErrTOTPCodeNotResendable {
		t.Fatalf("ResendLoginOTP for a TOTP login: err = %v, want ErrTOTPCodeNotResendable", err)
	}
}
