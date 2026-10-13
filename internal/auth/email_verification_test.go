package auth_test

import (
	"strings"
	"testing"

	"auth-2fa-api/internal/auth"
	"auth-2fa-api/internal/testutil"
)

func TestEmailVerification_BlocksLoginUntilConfirmed(t *testing.T) {
	svc, _, mailer, apiClientID := newTestService(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"

	if _, err := svc.Register(t.Context(), apiClientID, email, "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t), nil); err != nil {
		t.Fatalf("Register: %v", err)
	}
	sent, ok := mailer.Last()
	if !ok {
		t.Fatal("Register: no verification email was sent")
	}
	if sent.To != email {
		t.Fatalf("verification email sent to %q, want %q", sent.To, email)
	}
	code := testutil.ExtractVerificationCode(sent.Body)
	if code == "" {
		t.Fatalf("could not find a verification code in email body: %q", sent.Body)
	}

	// Correct password, but the account isn't verified yet — login must be
	// refused rather than silently proceeding.
	if _, _, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery", nil); err != auth.ErrEmailNotVerified {
		t.Fatalf("LoginStep1 before verifying: err = %v, want %v", err, auth.ErrEmailNotVerified)
	}

	if err := svc.ConfirmEmailVerification(t.Context(), apiClientID, email, code); err != nil {
		t.Fatalf("ConfirmEmailVerification: %v", err)
	}

	// Now it works.
	if _, _, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery", nil); err != nil {
		t.Fatalf("LoginStep1 after verifying: unexpected error %v", err)
	}
}

// Confirming with a differently-cased email than the one Register stored
// (Register normalizes to lowercase internally) must still find the
// pending session — the confirm request has to key off the same
// normalized email the code was actually stored under.
func TestEmailVerification_ConfirmWorksWithDifferentCasing(t *testing.T) {
	svc, _, mailer, apiClientID := newTestService(t)
	lower := "user-" + testutil.UniqueSuffix(t) + "@example.com"

	if _, err := svc.Register(t.Context(), apiClientID, lower, "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t), nil); err != nil {
		t.Fatalf("Register: %v", err)
	}
	sent, _ := mailer.Last()
	code := testutil.ExtractVerificationCode(sent.Body)

	mixedCase := strings.ToUpper(lower[:1]) + lower[1:]
	if err := svc.ConfirmEmailVerification(t.Context(), apiClientID, mixedCase, code); err != nil {
		t.Fatalf("ConfirmEmailVerification with different casing than Register: unexpected error %v", err)
	}
}

func TestEmailVerification_UnknownCode(t *testing.T) {
	svc, _, _, apiClientID := newTestService(t)
	if err := svc.ConfirmEmailVerification(t.Context(), apiClientID, "nobody@example.com", "123456"); err != auth.ErrEmailVerificationNotFound {
		t.Fatalf("err = %v, want %v", err, auth.ErrEmailVerificationNotFound)
	}
}

func TestEmailVerification_WrongCode(t *testing.T) {
	svc, _, mailer, apiClientID := newTestService(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	if _, err := svc.Register(t.Context(), apiClientID, email, "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t), nil); err != nil {
		t.Fatalf("Register: %v", err)
	}
	sent, _ := mailer.Last()
	code := testutil.ExtractVerificationCode(sent.Body)
	wrongCode := "0"
	if code == wrongCode {
		wrongCode = "1"
	}
	for len(wrongCode) < len(code) {
		wrongCode = "0" + wrongCode
	}

	if err := svc.ConfirmEmailVerification(t.Context(), apiClientID, email, wrongCode); err != auth.ErrEmailVerificationInvalidCode {
		t.Fatalf("err = %v, want %v", err, auth.ErrEmailVerificationInvalidCode)
	}
}

func TestEmailVerification_CodeIsSingleUse(t *testing.T) {
	svc, _, mailer, apiClientID := newTestService(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	if _, err := svc.Register(t.Context(), apiClientID, email, "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t), nil); err != nil {
		t.Fatalf("Register: %v", err)
	}
	sent, _ := mailer.Last()
	code := testutil.ExtractVerificationCode(sent.Body)

	if err := svc.ConfirmEmailVerification(t.Context(), apiClientID, email, code); err != nil {
		t.Fatalf("first ConfirmEmailVerification: %v", err)
	}
	if err := svc.ConfirmEmailVerification(t.Context(), apiClientID, email, code); err != auth.ErrEmailVerificationNotFound {
		t.Fatalf("second ConfirmEmailVerification with the same code: err = %v, want %v", err, auth.ErrEmailVerificationNotFound)
	}
}

func TestEmailVerification_TooManyWrongCodesInvalidatesSession(t *testing.T) {
	svc, _, mailer, apiClientID := newTestService(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	if _, err := svc.Register(t.Context(), apiClientID, email, "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t), nil); err != nil {
		t.Fatalf("Register: %v", err)
	}
	sent, _ := mailer.Last()
	code := testutil.ExtractVerificationCode(sent.Body)
	wrongCode := "0"
	if code == wrongCode {
		wrongCode = "1"
	}
	for len(wrongCode) < len(code) {
		wrongCode = "0" + wrongCode
	}

	var lastErr error
	for i := 0; i < 10; i++ {
		lastErr = svc.ConfirmEmailVerification(t.Context(), apiClientID, email, wrongCode)
		if lastErr == auth.ErrEmailVerificationTooManyTries {
			break
		}
	}
	if lastErr != auth.ErrEmailVerificationTooManyTries {
		t.Fatalf("after repeated wrong codes: last err = %v, want %v", lastErr, auth.ErrEmailVerificationTooManyTries)
	}

	// Even the correct code no longer works — the session was invalidated.
	if err := svc.ConfirmEmailVerification(t.Context(), apiClientID, email, code); err != auth.ErrEmailVerificationNotFound {
		t.Fatalf("ConfirmEmailVerification with the correct code after lockout: err = %v, want %v", err, auth.ErrEmailVerificationNotFound)
	}
}

func TestResendEmailVerification_UnknownAccount(t *testing.T) {
	svc, _, _, apiClientID := newTestService(t)
	if err := svc.ResendEmailVerification(t.Context(), apiClientID, "nobody@example.com"); err == nil {
		t.Fatal("ResendEmailVerification for an unknown account: want an error, got nil")
	}
}

func TestResendEmailVerification_AlreadyVerified(t *testing.T) {
	svc, _, mailer, apiClientID := newTestService(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery") // mustRegister confirms it too

	if err := svc.ResendEmailVerification(t.Context(), apiClientID, email); err != auth.ErrEmailAlreadyVerified {
		t.Fatalf("err = %v, want %v", err, auth.ErrEmailAlreadyVerified)
	}
}

func TestResendEmailVerification_NewCodeWorks(t *testing.T) {
	svc, _, mailer, apiClientID := newTestService(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	if _, err := svc.Register(t.Context(), apiClientID, email, "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t), nil); err != nil {
		t.Fatalf("Register: %v", err)
	}
	firstSent, _ := mailer.Last()
	firstCode := testutil.ExtractVerificationCode(firstSent.Body)

	if err := svc.ResendEmailVerification(t.Context(), apiClientID, email); err != nil {
		t.Fatalf("ResendEmailVerification: %v", err)
	}
	secondSent, _ := mailer.Last()
	secondCode := testutil.ExtractVerificationCode(secondSent.Body)

	// The old code from the first email no longer works — resend replaced it.
	if err := svc.ConfirmEmailVerification(t.Context(), apiClientID, email, firstCode); err != nil && firstCode != secondCode {
		// Only assert this when the two codes actually differ — a random
		// collision, while astronomically unlikely at 6 digits, shouldn't
		// flake the test.
		if err != auth.ErrEmailVerificationInvalidCode {
			t.Fatalf("confirming with the pre-resend code: err = %v, want %v", err, auth.ErrEmailVerificationInvalidCode)
		}
	}

	if err := svc.ConfirmEmailVerification(t.Context(), apiClientID, email, secondCode); err != nil {
		t.Fatalf("confirming with the resent code: %v", err)
	}
}
