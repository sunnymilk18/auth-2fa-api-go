package auth_test

import (
	"testing"
	"time"

	"auth-2fa-api/internal/auth"
	"auth-2fa-api/internal/device"
	"auth-2fa-api/internal/testutil"
	"auth-2fa-api/internal/user"
)

// newTestService wires a full auth.Service against a real (local) Postgres
// and an in-memory Redis, with a fake mailer so no real email is ever sent.
// Returns the service, its token manager (to parse access tokens in tests),
// the fake mailer (to read OTP/verification/reset codes off "sent" emails),
// and the api client every user in the test belongs to.
func newTestService(t *testing.T) (svc *auth.Service, tokens *auth.TokenManager, mailer *testutil.FakeMailer, apiClientID string) {
	t.Helper()

	pool := testutil.PostgresPool(t)
	rdb := testutil.RedisClient(t)
	client, _ := testutil.NewAPIClient(t, pool)

	users := user.NewService(user.NewRepository(pool))
	otpStore := auth.NewOTPStore(rdb, 5*time.Minute, 3, 6)
	tokens = auth.NewTokenManager(testutil.RSAKey(t), "test-key-1", "test-refresh-secret", 15*time.Minute, 7*24*time.Hour)
	refresh := auth.NewRefreshRepository(pool)
	devices := device.NewService(device.NewRepository(pool), 30*24*time.Hour, 3)
	passwordReset := auth.NewPasswordResetStore(rdb, time.Hour, 3, 6)
	emailVerification := auth.NewEmailVerificationStore(rdb, 24*time.Hour, 3, 6)
	loginAttempts := auth.NewLoginAttemptLimiter(rdb, 3, 15*time.Minute)
	mailer = testutil.NewFakeMailer()

	svc = auth.NewService(users, otpStore, tokens, refresh, devices, passwordReset, emailVerification, loginAttempts, mailer, 5*time.Minute, 7*24*time.Hour, time.Hour, 24*time.Hour)
	return svc, tokens, mailer, client.ID
}

// mustRegister creates a verified, ready-to-login user. Registering alone
// isn't enough anymore — Register now requires confirming the emailed
// verification code before the account can log in — so this immediately
// consumes that code off the fake mailer, mirroring what a real client does
// right after registering, for every test that just needs a working account
// rather than testing the verification flow itself.
func mustRegister(t *testing.T, svc *auth.Service, mailer *testutil.FakeMailer, apiClientID, email, password string) {
	t.Helper()
	if _, err := svc.Register(t.Context(), apiClientID, email, password); err != nil {
		t.Fatalf("Register(%q): %v", email, err)
	}
	sent, ok := mailer.Last()
	if !ok {
		t.Fatalf("Register(%q): no verification email was sent", email)
	}
	code := testutil.ExtractVerificationCode(sent.Body)
	if code == "" {
		t.Fatalf("Register(%q): could not find a verification code in email body: %q", email, sent.Body)
	}
	if err := svc.ConfirmEmailVerification(t.Context(), apiClientID, email, code); err != nil {
		t.Fatalf("ConfirmEmailVerification(%q): %v", email, err)
	}
}

func TestLoginFlow_PasswordPlusOTP(t *testing.T) {
	svc, _, mailer, apiClientID := newTestService(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")

	loginToken, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery")
	if err != nil {
		t.Fatalf("LoginStep1: %v", err)
	}
	if loginToken == "" {
		t.Fatal("LoginStep1: empty login token")
	}

	sent, ok := mailer.Last()
	if !ok {
		t.Fatal("LoginStep1: no OTP email was sent")
	}
	if sent.To != email {
		t.Fatalf("OTP email sent to %q, want %q", sent.To, email)
	}
	code := testutil.ExtractOTPCode(sent.Body)
	if code == "" {
		t.Fatalf("could not find an OTP code in email body: %q", sent.Body)
	}

	access, refreshTok, err := svc.LoginStep2(t.Context(), loginToken, code)
	if err != nil {
		t.Fatalf("LoginStep2: %v", err)
	}
	if access == "" || refreshTok == "" {
		t.Fatal("LoginStep2: expected non-empty access and refresh tokens")
	}

	// The login token is single-use: verifying again (even with the right
	// code) must fail now that the session was consumed.
	if _, _, err := svc.LoginStep2(t.Context(), loginToken, code); err == nil {
		t.Fatal("LoginStep2 a second time: want error (session already consumed), got nil")
	}
}

func TestLoginStep1_WrongPassword(t *testing.T) {
	svc, _, mailer, apiClientID := newTestService(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")
	sentBeforeLogin := len(mailer.Sent()) // mustRegister itself already sent a verification email

	_, err := svc.LoginStep1(t.Context(), apiClientID, email, "wrong-password")
	if err != user.ErrInvalidCredentials {
		t.Fatalf("LoginStep1 with wrong password: err = %v, want %v", err, user.ErrInvalidCredentials)
	}
	if len(mailer.Sent()) != sentBeforeLogin {
		t.Fatal("LoginStep1 with wrong password must not send an OTP email")
	}
}

// Regression coverage for the per-account login throttle: repeated wrong
// passwords against ONE account eventually lock it out even though each
// individual attempt is well within the per-IP rate limiter's own budget
// (that limiter isn't exercised here at all — this is purely
// auth.Service/LoginAttemptLimiter) — the scenario that limiter alone can't
// catch: someone spreading guesses across many source IPs.
func TestLoginStep1_LocksOutAfterTooManyFailures(t *testing.T) {
	svc, _, mailer, apiClientID := newTestService(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")

	// newTestService builds the limiter with maxFails=3.
	for i := 1; i <= 2; i++ {
		if _, err := svc.LoginStep1(t.Context(), apiClientID, email, "wrong"); err != user.ErrInvalidCredentials {
			t.Fatalf("wrong password attempt %d: err = %v, want %v", i, err, user.ErrInvalidCredentials)
		}
	}
	if _, err := svc.LoginStep1(t.Context(), apiClientID, email, "wrong"); err != user.ErrInvalidCredentials {
		t.Fatalf("wrong password attempt 3: err = %v, want %v", err, user.ErrInvalidCredentials)
	}

	// Locked out now — even the CORRECT password is rejected.
	if _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery"); err != auth.ErrTooManyFailedLogins {
		t.Fatalf("correct password after lockout: err = %v, want %v", err, auth.ErrTooManyFailedLogins)
	}
}

// The lockout must not become a way to enumerate which emails are
// registered: an account that doesn't exist gets throttled exactly the same
// way a real one would, since VerifyPassword already returns the same
// error for both.
func TestLoginStep1_LockoutAppliesEvenToUnknownAccounts(t *testing.T) {
	svc, _, _, apiClientID := newTestService(t)
	email := "nobody-" + testutil.UniqueSuffix(t) + "@example.com"

	for i := 1; i <= 3; i++ {
		if _, err := svc.LoginStep1(t.Context(), apiClientID, email, "whatever"); err != user.ErrInvalidCredentials {
			t.Fatalf("attempt %d against unknown account: err = %v, want %v", i, err, user.ErrInvalidCredentials)
		}
	}
	if _, err := svc.LoginStep1(t.Context(), apiClientID, email, "whatever"); err != auth.ErrTooManyFailedLogins {
		t.Fatalf("err = %v, want %v", err, auth.ErrTooManyFailedLogins)
	}
}

// A successful login resets the counter, so past mistakes don't linger.
func TestLoginStep1_SuccessResetsFailureCount(t *testing.T) {
	svc, _, mailer, apiClientID := newTestService(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")

	if _, err := svc.LoginStep1(t.Context(), apiClientID, email, "wrong"); err != user.ErrInvalidCredentials {
		t.Fatalf("wrong password attempt: err = %v, want %v", err, user.ErrInvalidCredentials)
	}
	if _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery"); err != nil {
		t.Fatalf("correct password: unexpected error %v", err)
	}
	_, _ = mailer.Last() // drain, not asserted on here

	// Two more wrong guesses shouldn't be attempt 2-and-3-of-3 against the
	// pre-reset count — they're 1-and-2 of a fresh window.
	for i := 1; i <= 2; i++ {
		if _, err := svc.LoginStep1(t.Context(), apiClientID, email, "wrong"); err != user.ErrInvalidCredentials {
			t.Fatalf("post-reset wrong attempt %d: err = %v, want %v", i, err, user.ErrInvalidCredentials)
		}
	}
	if _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery"); err != nil {
		t.Fatalf("correct password (should not be locked out yet): unexpected error %v", err)
	}
}

func TestLoginStep2_WrongCodeExhaustsAttempts(t *testing.T) {
	svc, _, mailer, apiClientID := newTestService(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")

	loginToken, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery")
	if err != nil {
		t.Fatalf("LoginStep1: %v", err)
	}
	sent, _ := mailer.Last()
	realCode := testutil.ExtractOTPCode(sent.Body)
	wrongCode := "000000"
	if wrongCode == realCode {
		wrongCode = "111111"
	}

	// The test service was built with maxTries=3 (see newTestService).
	for i := 1; i <= 2; i++ {
		if _, _, err := svc.LoginStep2(t.Context(), loginToken, wrongCode); err != auth.ErrInvalidCode {
			t.Fatalf("wrong code attempt %d: err = %v, want %v", i, err, auth.ErrInvalidCode)
		}
	}
	// Third wrong attempt hits the limit and invalidates the session.
	if _, _, err := svc.LoginStep2(t.Context(), loginToken, wrongCode); err != auth.ErrTooManyAttempts {
		t.Fatalf("wrong code attempt 3: err = %v, want %v", err, auth.ErrTooManyAttempts)
	}
	// Even the *right* code no longer works — session was invalidated.
	if _, _, err := svc.LoginStep2(t.Context(), loginToken, realCode); err != auth.ErrLoginSessionNotFound {
		t.Fatalf("correct code after lockout: err = %v, want %v", err, auth.ErrLoginSessionNotFound)
	}
}

func TestLoginStep2_UnknownLoginToken(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	if _, _, err := svc.LoginStep2(t.Context(), "does-not-exist", "123456"); err != auth.ErrLoginSessionNotFound {
		t.Fatalf("err = %v, want %v", err, auth.ErrLoginSessionNotFound)
	}
}

// Users registered under different api clients (tenants) are fully
// isolated — the same email can be a different account per tenant, and
// credentials from one tenant must never authenticate against another.
func TestMultiTenant_SameEmailDifferentClients(t *testing.T) {
	svc, _, mailer, apiClientA := newTestService(t)
	pool := testutil.PostgresPool(t)
	clientB, _ := testutil.NewAPIClient(t, pool)

	email := "shared-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientA, email, "passwordA123")
	mustRegister(t, svc, mailer, clientB.ID, email, "passwordB456")

	if _, err := svc.LoginStep1(t.Context(), apiClientA, email, "passwordB456"); err != user.ErrInvalidCredentials {
		t.Fatalf("tenant A login with tenant B's password: err = %v, want %v", err, user.ErrInvalidCredentials)
	}
	if _, err := svc.LoginStep1(t.Context(), apiClientA, email, "passwordA123"); err != nil {
		t.Fatalf("tenant A login with its own password: unexpected error %v", err)
	}
}

func TestRefreshAndLogout(t *testing.T) {
	svc, _, mailer, apiClientID := newTestService(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")

	loginToken, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery")
	if err != nil {
		t.Fatalf("LoginStep1: %v", err)
	}
	sent, _ := mailer.Last()
	code := testutil.ExtractOTPCode(sent.Body)
	_, refreshTok, err := svc.LoginStep2(t.Context(), loginToken, code)
	if err != nil {
		t.Fatalf("LoginStep2: %v", err)
	}

	newAccess, newRefresh, err := svc.Refresh(t.Context(), refreshTok)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if newAccess == "" || newRefresh == "" || newRefresh == refreshTok {
		t.Fatalf("Refresh: expected fresh, different tokens; got access=%q refresh=%q", newAccess, newRefresh)
	}

	// Rotation: the old refresh token is revoked and can't be reused.
	if _, _, err := svc.Refresh(t.Context(), refreshTok); err != auth.ErrRefreshTokenInvalid {
		t.Fatalf("reusing rotated-out refresh token: err = %v, want %v", err, auth.ErrRefreshTokenInvalid)
	}

	if err := svc.Logout(t.Context(), newRefresh); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, _, err := svc.Refresh(t.Context(), newRefresh); err != auth.ErrRefreshTokenInvalid {
		t.Fatalf("using refresh token after logout: err = %v, want %v", err, auth.ErrRefreshTokenInvalid)
	}
}

func TestDeviceLoginFlow(t *testing.T) {
	svc, tokens, mailer, apiClientID := newTestService(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")

	// Full password+OTP login first, as the real flow requires.
	loginToken, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery")
	if err != nil {
		t.Fatalf("LoginStep1: %v", err)
	}
	sent, _ := mailer.Last()
	code := testutil.ExtractOTPCode(sent.Body)
	access, _, err := svc.LoginStep2(t.Context(), loginToken, code)
	if err != nil {
		t.Fatalf("LoginStep2: %v", err)
	}

	claims, err := tokens.ParseAccessToken(access)
	if err != nil {
		t.Fatalf("parsing access token: %v", err)
	}
	userID := claims.Subject

	deviceID := "device-" + testutil.UniqueSuffix(t)
	deviceToken, err := svc.RegisterDevice(t.Context(), userID, deviceID, "Test Phone", "123456")
	if err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}

	// Wrong PIN doesn't authenticate.
	if _, _, _, err := svc.DeviceLogin(t.Context(), deviceID, deviceToken, "000000"); err != device.ErrInvalidPin {
		t.Fatalf("DeviceLogin with wrong pin: err = %v, want %v", err, device.ErrInvalidPin)
	}

	// Right device token + PIN logs in and rotates the device token.
	newAccess, newRefresh, rotatedToken, err := svc.DeviceLogin(t.Context(), deviceID, deviceToken, "123456")
	if err != nil {
		t.Fatalf("DeviceLogin: %v", err)
	}
	if newAccess == "" || newRefresh == "" || rotatedToken == "" || rotatedToken == deviceToken {
		t.Fatalf("DeviceLogin: expected fresh tokens and a rotated device token distinct from the original")
	}

	// The old (pre-rotation) device token no longer works.
	if _, _, _, err := svc.DeviceLogin(t.Context(), deviceID, deviceToken, "123456"); err != device.ErrDeviceNotTrusted {
		t.Fatalf("DeviceLogin with stale (rotated-out) device token: err = %v, want %v", err, device.ErrDeviceNotTrusted)
	}

	// The rotated token works.
	if _, _, _, err := svc.DeviceLogin(t.Context(), deviceID, rotatedToken, "123456"); err != nil {
		t.Fatalf("DeviceLogin with rotated device token: unexpected error %v", err)
	}
}

func TestDeviceLogin_TooManyFailedPinsRevokesTrust(t *testing.T) {
	svc, tokens, mailer, apiClientID := newTestService(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")

	loginToken, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery")
	if err != nil {
		t.Fatalf("LoginStep1: %v", err)
	}
	sent, _ := mailer.Last()
	code := testutil.ExtractOTPCode(sent.Body)
	access, _, err := svc.LoginStep2(t.Context(), loginToken, code)
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

	// newTestService's device.Service allows 3 failed PIN attempts before revoking.
	for i := 1; i <= 2; i++ {
		if _, _, _, err := svc.DeviceLogin(t.Context(), deviceID, deviceToken, "000000"); err != device.ErrInvalidPin {
			t.Fatalf("failed pin attempt %d: err = %v, want %v", i, err, device.ErrInvalidPin)
		}
	}
	if _, _, _, err := svc.DeviceLogin(t.Context(), deviceID, deviceToken, "000000"); err != device.ErrTooManyPinTries {
		t.Fatalf("failed pin attempt 3: err = %v, want %v", err, device.ErrTooManyPinTries)
	}
	// Trust was revoked — even the correct PIN is rejected now.
	if _, _, _, err := svc.DeviceLogin(t.Context(), deviceID, deviceToken, "123456"); err != device.ErrDeviceNotTrusted {
		t.Fatalf("correct pin after revocation: err = %v, want %v", err, device.ErrDeviceNotTrusted)
	}
}
