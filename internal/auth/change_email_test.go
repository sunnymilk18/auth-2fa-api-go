package auth_test

import (
	"testing"

	"auth-2fa-api/internal/auth"
	"auth-2fa-api/internal/device"
	"auth-2fa-api/internal/testutil"
	"auth-2fa-api/internal/user"
)

func TestChangeEmail_FullFlow(t *testing.T) {
	svc, tokens, mailer, apiClientID := newTestService(t)
	oldEmail := "typo-" + testutil.UniqueSuffix(t) + "@example.com"
	userID := mustRegisterAndLogin(t, svc, tokens, mailer, apiClientID, oldEmail, "correcthorsebattery")

	newEmail := "fixed-" + testutil.UniqueSuffix(t) + "@example.com"
	if err := svc.AdminChangeEmail(t.Context(), apiClientID, userID, newEmail); err != nil {
		t.Fatalf("AdminChangeEmail: %v", err)
	}

	sent, ok := mailer.Last()
	if !ok {
		t.Fatal("AdminChangeEmail: no email was sent")
	}
	if sent.To != newEmail {
		t.Fatalf("code sent to %q, want the NEW email %q (the admin never sees it)", sent.To, newEmail)
	}
	code := testutil.ExtractChangeEmailCode(sent.Body)
	if code == "" {
		t.Fatalf("could not find a code in email body: %q", sent.Body)
	}

	if err := svc.ConfirmChangeEmail(t.Context(), apiClientID, newEmail, code); err != nil {
		t.Fatalf("ConfirmChangeEmail: %v", err)
	}

	// The account logs in with the new email now; the old one is free.
	if _, _, _, err := svc.LoginStep1(t.Context(), apiClientID, newEmail, "correcthorsebattery"); err != nil {
		t.Fatalf("LoginStep1 with the new email: unexpected error %v", err)
	}
	if _, _, _, err := svc.LoginStep1(t.Context(), apiClientID, oldEmail, "correcthorsebattery"); err != user.ErrInvalidCredentials {
		t.Fatalf("LoginStep1 with the old email: err = %v, want %v", err, user.ErrInvalidCredentials)
	}

	// The old address was notified.
	allSent := mailer.Sent()
	noticeSent := false
	for _, e := range allSent {
		if e.To == oldEmail {
			noticeSent = true
		}
	}
	if !noticeSent {
		t.Fatalf("old address %q was never notified of the change; sent = %+v", oldEmail, allSent)
	}
}

// The whole point of this flow: an account that typo'd its email at
// registration never verified it, so LoginStep1 always refused it (see
// ErrEmailNotVerified) — confirming the correction must unstick that.
func TestChangeEmail_MarksEmailVerified(t *testing.T) {
	svc, _, mailer, apiClientID := newTestService(t)
	oldEmail := "typo-" + testutil.UniqueSuffix(t) + "@example.com"
	u, err := svc.Register(t.Context(), apiClientID, oldEmail, "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Deliberately never verified — that's the scenario this flow exists for.
	if _, _, _, err := svc.LoginStep1(t.Context(), apiClientID, oldEmail, "correcthorsebattery"); err != auth.ErrEmailNotVerified {
		t.Fatalf("sanity check, LoginStep1 before any fix: err = %v, want %v", err, auth.ErrEmailNotVerified)
	}

	newEmail := "fixed-" + testutil.UniqueSuffix(t) + "@example.com"
	if err := svc.AdminChangeEmail(t.Context(), apiClientID, u.ID, newEmail); err != nil {
		t.Fatalf("AdminChangeEmail: %v", err)
	}
	sent, _ := mailer.Last()
	code := testutil.ExtractChangeEmailCode(sent.Body)
	if err := svc.ConfirmChangeEmail(t.Context(), apiClientID, newEmail, code); err != nil {
		t.Fatalf("ConfirmChangeEmail: %v", err)
	}

	if _, _, _, err := svc.LoginStep1(t.Context(), apiClientID, newEmail, "correcthorsebattery"); err != nil {
		t.Fatalf("LoginStep1 after the fix: unexpected error %v (email_verified should now be true)", err)
	}
}

func TestChangeEmail_RevokesExistingSessionsDevicesAndAccessTokens(t *testing.T) {
	svc, tokens, mailer, apiClientID := newTestService(t)
	oldEmail := "typo-" + testutil.UniqueSuffix(t) + "@example.com"
	userID := mustRegisterAndLogin(t, svc, tokens, mailer, apiClientID, oldEmail, "correcthorsebattery")

	// A session + trusted device from before the change.
	loginToken, _, _, err := svc.LoginStep1(t.Context(), apiClientID, oldEmail, "correcthorsebattery")
	if err != nil {
		t.Fatalf("LoginStep1: %v", err)
	}
	otpSent, _ := mailer.Last()
	_, refreshTok, err := loginStep2Tokens(t, svc, loginToken, testutil.ExtractOTPCode(otpSent.Body))
	if err != nil {
		t.Fatalf("LoginStep2: %v", err)
	}
	deviceID := "device-" + testutil.UniqueSuffix(t)
	deviceToken, err := svc.RegisterDevice(t.Context(), userID, deviceID, "Test Phone", "123456")
	if err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}

	newEmail := "fixed-" + testutil.UniqueSuffix(t) + "@example.com"
	if err := svc.AdminChangeEmail(t.Context(), apiClientID, userID, newEmail); err != nil {
		t.Fatalf("AdminChangeEmail: %v", err)
	}
	sent, _ := mailer.Last()
	code := testutil.ExtractChangeEmailCode(sent.Body)
	if err := svc.ConfirmChangeEmail(t.Context(), apiClientID, newEmail, code); err != nil {
		t.Fatalf("ConfirmChangeEmail: %v", err)
	}

	if _, _, err := svc.Refresh(t.Context(), refreshTok); err != auth.ErrRefreshTokenInvalid {
		t.Fatalf("Refresh with a pre-change refresh token: err = %v, want %v", err, auth.ErrRefreshTokenInvalid)
	}
	if _, _, _, err := svc.DeviceLogin(t.Context(), deviceID, deviceToken, "123456"); err != device.ErrDeviceNotTrusted {
		t.Fatalf("DeviceLogin with a pre-change device token: err = %v, want %v", err, device.ErrDeviceNotTrusted)
	}
	// Instant access-token revocation (AccessRevocationStore) is exercised
	// directly at the httpserver layer (see router_admin_test.go's Ban
	// test) — not re-tested here, same access/refresh/devices pairing
	// ResetPassword already relies on.
}

func TestChangeEmail_NewEmailAlreadyTaken(t *testing.T) {
	svc, tokens, mailer, apiClientID := newTestService(t)
	takenEmail := "taken-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegisterAndLogin(t, svc, tokens, mailer, apiClientID, takenEmail, "correcthorsebattery")

	oldEmail := "typo-" + testutil.UniqueSuffix(t) + "@example.com"
	userID := mustRegisterAndLogin(t, svc, tokens, mailer, apiClientID, oldEmail, "correcthorsebattery")

	if err := svc.AdminChangeEmail(t.Context(), apiClientID, userID, takenEmail); err != user.ErrEmailTaken {
		t.Fatalf("err = %v, want %v", err, user.ErrEmailTaken)
	}
}

func TestChangeEmail_InvalidNewEmailFormat(t *testing.T) {
	svc, tokens, mailer, apiClientID := newTestService(t)
	oldEmail := "typo-" + testutil.UniqueSuffix(t) + "@example.com"
	userID := mustRegisterAndLogin(t, svc, tokens, mailer, apiClientID, oldEmail, "correcthorsebattery")

	if err := svc.AdminChangeEmail(t.Context(), apiClientID, userID, "not-an-email"); err != user.ErrInvalidEmail {
		t.Fatalf("err = %v, want %v", err, user.ErrInvalidEmail)
	}
}

func TestChangeEmail_UnknownUser(t *testing.T) {
	svc, _, _, apiClientID := newTestService(t)
	if err := svc.AdminChangeEmail(t.Context(), apiClientID, "00000000-0000-0000-0000-000000000000", "new@example.com"); err != user.ErrNotFound {
		t.Fatalf("err = %v, want %v", err, user.ErrNotFound)
	}
}

// A system-admin credential scoped to one tenant must not be able to
// change the email of a user belonging to a different tenant — same
// isolation rule (404-shaped, via user.ErrNotFound) as ban/unban/reset-pin.
func TestChangeEmail_ScopedToOwnTenant(t *testing.T) {
	svc, tokens, mailer, apiClientID := newTestService(t)
	_, _, _, otherClientID := newTestService(t) // a second, unrelated tenant
	oldEmail := "typo-" + testutil.UniqueSuffix(t) + "@example.com"
	userID := mustRegisterAndLogin(t, svc, tokens, mailer, apiClientID, oldEmail, "correcthorsebattery")

	if err := svc.AdminChangeEmail(t.Context(), otherClientID, userID, "new@example.com"); err != user.ErrNotFound {
		t.Fatalf("change-email from a different tenant: err = %v, want %v", err, user.ErrNotFound)
	}
}

func TestChangeEmail_WrongCode(t *testing.T) {
	svc, tokens, mailer, apiClientID := newTestService(t)
	oldEmail := "typo-" + testutil.UniqueSuffix(t) + "@example.com"
	userID := mustRegisterAndLogin(t, svc, tokens, mailer, apiClientID, oldEmail, "correcthorsebattery")

	newEmail := "fixed-" + testutil.UniqueSuffix(t) + "@example.com"
	if err := svc.AdminChangeEmail(t.Context(), apiClientID, userID, newEmail); err != nil {
		t.Fatalf("AdminChangeEmail: %v", err)
	}
	sent, _ := mailer.Last()
	code := testutil.ExtractChangeEmailCode(sent.Body)
	wrongCode := "0"
	if code == wrongCode {
		wrongCode = "1"
	}
	for len(wrongCode) < len(code) {
		wrongCode = "0" + wrongCode
	}

	if err := svc.ConfirmChangeEmail(t.Context(), apiClientID, newEmail, wrongCode); err != auth.ErrChangeEmailInvalidCode {
		t.Fatalf("err = %v, want %v", err, auth.ErrChangeEmailInvalidCode)
	}
	// The real code still works — the wrong guess didn't consume it.
	if err := svc.ConfirmChangeEmail(t.Context(), apiClientID, newEmail, code); err != nil {
		t.Fatalf("ConfirmChangeEmail with the correct code after a wrong guess: unexpected error %v", err)
	}
}

func TestChangeEmail_UnknownPendingChange(t *testing.T) {
	svc, _, _, apiClientID := newTestService(t)
	if err := svc.ConfirmChangeEmail(t.Context(), apiClientID, "nobody-is-changing-to-this@example.com", "123456"); err != auth.ErrChangeEmailNotFound {
		t.Fatalf("err = %v, want %v", err, auth.ErrChangeEmailNotFound)
	}
}

// Requesting a second change before the first was confirmed replaces it —
// only the most recently emailed code is valid, same as every other
// code-based flow in this package.
func TestChangeEmail_SecondRequestReplacesFirst(t *testing.T) {
	svc, tokens, mailer, apiClientID := newTestService(t)
	oldEmail := "typo-" + testutil.UniqueSuffix(t) + "@example.com"
	userID := mustRegisterAndLogin(t, svc, tokens, mailer, apiClientID, oldEmail, "correcthorsebattery")

	firstTarget := "first-" + testutil.UniqueSuffix(t) + "@example.com"
	if err := svc.AdminChangeEmail(t.Context(), apiClientID, userID, firstTarget); err != nil {
		t.Fatalf("first AdminChangeEmail: %v", err)
	}
	firstSent, _ := mailer.Last()
	firstCode := testutil.ExtractChangeEmailCode(firstSent.Body)

	secondTarget := "second-" + testutil.UniqueSuffix(t) + "@example.com"
	if err := svc.AdminChangeEmail(t.Context(), apiClientID, userID, secondTarget); err != nil {
		t.Fatalf("second AdminChangeEmail: %v", err)
	}
	secondSent, _ := mailer.Last()
	secondCode := testutil.ExtractChangeEmailCode(secondSent.Body)

	// The first target's pending change is simply gone now (different Redis
	// key, from the first target's own email) — confirming it 404s/expired.
	if err := svc.ConfirmChangeEmail(t.Context(), apiClientID, firstTarget, firstCode); err != auth.ErrChangeEmailNotFound {
		t.Fatalf("confirming the superseded first request: err = %v, want %v", err, auth.ErrChangeEmailNotFound)
	}
	if err := svc.ConfirmChangeEmail(t.Context(), apiClientID, secondTarget, secondCode); err != nil {
		t.Fatalf("confirming the second (current) request: unexpected error %v", err)
	}
}
