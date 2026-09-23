package auth_test

import (
	"net/url"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

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
	totpManager, err := auth.NewTOTPManager("test-issuer", testTOTPKey)
	if err != nil {
		t.Fatalf("NewTOTPManager: %v", err)
	}
	totpLogin := auth.NewTOTPLoginStore(rdb, 5*time.Minute)

	// twoFactorSetup deliberately nil here: with it wired in, every
	// freshly-registered test account's very first LoginStep1 call would
	// hit the new first-login "choose your method" branch instead of the
	// email path almost every existing test in this file assumes — unlike
	// totpManager/totpLogin above (dormant until an account explicitly
	// enrolls TOTP), TwoFactorMethodChosen defaults to false for every new
	// account, which is exactly the condition that flips LoginStep1's
	// behavior. See newTestServiceWithChoice for the few tests that
	// actually exercise this flow.
	svc = auth.NewService(users, otpStore, tokens, refresh, devices, passwordReset, emailVerification, loginAttempts, mailer, 5*time.Minute, 7*24*time.Hour, time.Hour, 24*time.Hour, totpManager, totpLogin, nil, nil, nil, nil, nil)
	return svc, tokens, mailer, client.ID
}

// newTestServiceWithChoice is newTestService but with the first-login
// "choose your method" flow actually enabled (see LoginStep1's doc
// comment) — only the tests exercising that flow need this; every other
// test uses newTestService, which deliberately leaves it disabled so
// existing accounts' first login keeps going straight to email as before.
func newTestServiceWithChoice(t *testing.T) (svc *auth.Service, tokens *auth.TokenManager, mailer *testutil.FakeMailer, apiClientID string) {
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
	totpManager, err := auth.NewTOTPManager("test-issuer", testTOTPKey)
	if err != nil {
		t.Fatalf("NewTOTPManager: %v", err)
	}
	totpLogin := auth.NewTOTPLoginStore(rdb, 5*time.Minute)
	twoFactorSetup := auth.NewTwoFactorSetupStore(rdb, 5*time.Minute)

	svc = auth.NewService(users, otpStore, tokens, refresh, devices, passwordReset, emailVerification, loginAttempts, mailer, 5*time.Minute, 7*24*time.Hour, time.Hour, 24*time.Hour, totpManager, totpLogin, twoFactorSetup, nil, nil, nil, nil)
	return svc, tokens, mailer, client.ID
}

// testTOTPKey is a fixed 32-byte AES-256 key used only in tests — real
// deployments generate their own via TOTP_ENCRYPTION_KEY (see
// config.Config's doc comment).
var testTOTPKey = []byte("0123456789abcdef0123456789abcdef")

// mustRegister creates a verified, ready-to-login user. Registering alone
// isn't enough anymore — Register now requires confirming the emailed
// verification code before the account can log in — so this immediately
// consumes that code off the fake mailer, mirroring what a real client does
// right after registering, for every test that just needs a working account
// rather than testing the verification flow itself.
func mustRegister(t *testing.T, svc *auth.Service, mailer *testutil.FakeMailer, apiClientID, email, password string) {
	t.Helper()
	mustRegisterFull(t, svc, mailer, apiClientID, email, password, "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t))
}

// mustRegisterWithUsername is mustRegister but with a caller-chosen
// username (a fresh rut is still generated) — for tests that care about a
// specific, possibly-colliding username.
func mustRegisterWithUsername(t *testing.T, svc *auth.Service, mailer *testutil.FakeMailer, apiClientID, email, password, username string) {
	t.Helper()
	mustRegisterFull(t, svc, mailer, apiClientID, email, password, username, testutil.UniqueRUT(t))
}

// mustRegisterFull is mustRegister but with a caller-chosen username and
// rut too — for tests asserting login by one of those identifiers.
func mustRegisterFull(t *testing.T, svc *auth.Service, mailer *testutil.FakeMailer, apiClientID, email, password, username, rut string) {
	t.Helper()
	if _, err := svc.Register(t.Context(), apiClientID, email, password, username, rut); err != nil {
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

	loginToken, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery")
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

	_, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "wrong-password")
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
		if _, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "wrong"); err != user.ErrInvalidCredentials {
			t.Fatalf("wrong password attempt %d: err = %v, want %v", i, err, user.ErrInvalidCredentials)
		}
	}
	if _, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "wrong"); err != user.ErrInvalidCredentials {
		t.Fatalf("wrong password attempt 3: err = %v, want %v", err, user.ErrInvalidCredentials)
	}

	// Locked out now — even the CORRECT password is rejected.
	if _, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery"); err != auth.ErrTooManyFailedLogins {
		t.Fatalf("correct password after lockout: err = %v, want %v", err, auth.ErrTooManyFailedLogins)
	}
}

// Failed attempts against the same account share one lockout counter
// regardless of which identifier (email/username/rut) was typed each
// time — alternating between them must not multiply the attempt budget.
func TestLoginStep1_LockoutSharedAcrossIdentifiers(t *testing.T) {
	svc, _, mailer, apiClientID := newTestService(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	username := "user-" + testutil.UniqueSuffix(t)
	rut := testutil.UniqueRUT(t)
	mustRegisterFull(t, svc, mailer, apiClientID, email, "correcthorsebattery", username, rut)

	// newTestService builds the limiter with maxFails=3. One failure each
	// via email, username and rut — three total, the shared limit.
	for _, identifier := range []string{email, username, rut} {
		if _, _, _, err := svc.LoginStep1(t.Context(), apiClientID, identifier, "wrong"); err != user.ErrInvalidCredentials {
			t.Fatalf("wrong password via %q: err = %v, want %v", identifier, err, user.ErrInvalidCredentials)
		}
	}

	// Locked out now, even via a fourth identifier (email again) with the
	// CORRECT password — if this were still three separate counters, each
	// would only be at 1 failure and none would be locked.
	if _, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery"); err != auth.ErrTooManyFailedLogins {
		t.Fatalf("correct password after 3 failures spread across identifiers: err = %v, want %v", err, auth.ErrTooManyFailedLogins)
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
		if _, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "whatever"); err != user.ErrInvalidCredentials {
			t.Fatalf("attempt %d against unknown account: err = %v, want %v", i, err, user.ErrInvalidCredentials)
		}
	}
	if _, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "whatever"); err != auth.ErrTooManyFailedLogins {
		t.Fatalf("err = %v, want %v", err, auth.ErrTooManyFailedLogins)
	}
}

// A successful login resets the counter, so past mistakes don't linger.
func TestLoginStep1_SuccessResetsFailureCount(t *testing.T) {
	svc, _, mailer, apiClientID := newTestService(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")

	if _, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "wrong"); err != user.ErrInvalidCredentials {
		t.Fatalf("wrong password attempt: err = %v, want %v", err, user.ErrInvalidCredentials)
	}
	if _, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery"); err != nil {
		t.Fatalf("correct password: unexpected error %v", err)
	}
	_, _ = mailer.Last() // drain, not asserted on here

	// Two more wrong guesses shouldn't be attempt 2-and-3-of-3 against the
	// pre-reset count — they're 1-and-2 of a fresh window.
	for i := 1; i <= 2; i++ {
		if _, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "wrong"); err != user.ErrInvalidCredentials {
			t.Fatalf("post-reset wrong attempt %d: err = %v, want %v", i, err, user.ErrInvalidCredentials)
		}
	}
	if _, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery"); err != nil {
		t.Fatalf("correct password (should not be locked out yet): unexpected error %v", err)
	}
}

func TestLoginStep2_WrongCodeExhaustsAttempts(t *testing.T) {
	svc, _, mailer, apiClientID := newTestService(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")

	loginToken, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery")
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

	if _, _, _, err := svc.LoginStep1(t.Context(), apiClientA, email, "passwordB456"); err != user.ErrInvalidCredentials {
		t.Fatalf("tenant A login with tenant B's password: err = %v, want %v", err, user.ErrInvalidCredentials)
	}
	if _, _, _, err := svc.LoginStep1(t.Context(), apiClientA, email, "passwordA123"); err != nil {
		t.Fatalf("tenant A login with its own password: unexpected error %v", err)
	}
}

func TestRefreshAndLogout(t *testing.T) {
	svc, _, mailer, apiClientID := newTestService(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")

	loginToken, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery")
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
	loginToken, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery")
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

// A banned account (user.Service.Ban) must lose the trusted-device
// shortcut too, not just password+OTP login (see LoginStep1's own test
// coverage in internal/user for that half) — DeviceLogin bypasses password
// entirely, so it never went through user.Service.VerifyPassword's
// is_active check on its own before this.
func TestDeviceLogin_BannedAccountIsRefused(t *testing.T) {
	pool := testutil.PostgresPool(t)
	rdb := testutil.RedisClient(t)
	client, _ := testutil.NewAPIClient(t, pool)
	apiClientID := client.ID

	users := user.NewService(user.NewRepository(pool))
	otpStore := auth.NewOTPStore(rdb, 5*time.Minute, 3, 6)
	tokens := auth.NewTokenManager(testutil.RSAKey(t), "test-key-1", "test-refresh-secret", 15*time.Minute, 7*24*time.Hour)
	refresh := auth.NewRefreshRepository(pool)
	devices := device.NewService(device.NewRepository(pool), 30*24*time.Hour, 3)
	passwordReset := auth.NewPasswordResetStore(rdb, time.Hour, 3, 6)
	emailVerification := auth.NewEmailVerificationStore(rdb, 24*time.Hour, 3, 6)
	loginAttempts := auth.NewLoginAttemptLimiter(rdb, 3, 15*time.Minute)
	mailer := testutil.NewFakeMailer()
	svc := auth.NewService(users, otpStore, tokens, refresh, devices, passwordReset, emailVerification, loginAttempts, mailer, 5*time.Minute, 7*24*time.Hour, time.Hour, 24*time.Hour, nil, nil, nil, nil, nil, nil, nil)

	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")

	loginToken, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery")
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

	// Trust was established before the ban — same as a real "account
	// compromised after the device was already trusted" scenario.
	if err := users.Ban(t.Context(), userID); err != nil {
		t.Fatalf("Ban: %v", err)
	}

	if _, _, _, err := svc.DeviceLogin(t.Context(), deviceID, deviceToken, "123456"); err != auth.ErrAccountBanned {
		t.Fatalf("DeviceLogin for a banned account: err = %v, want %v", err, auth.ErrAccountBanned)
	}

	// Unban restores password+OTP login (the trusted-device token itself
	// was already rotated server-side by the pin check inside the attempt
	// above — same pre-existing behavior as any other failure that happens
	// after a correct PIN, e.g. device.ErrTooManyPinTries — so re-trying
	// DeviceLogin with the original, now-stale token correctly still fails;
	// the client would need to re-register a device after this).
	if err := users.Unban(t.Context(), userID); err != nil {
		t.Fatalf("Unban: %v", err)
	}
	if _, err := users.VerifyPassword(t.Context(), apiClientID, email, "correcthorsebattery"); err != nil {
		t.Fatalf("VerifyPassword after Unban: unexpected error %v", err)
	}
}

func TestDeviceLogin_TooManyFailedPinsRevokesTrust(t *testing.T) {
	svc, tokens, mailer, apiClientID := newTestService(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")

	loginToken, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery")
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

// --- TOTP (authenticator app) ---

// mustLoginFull does a full password+OTP login (mustRegister must already
// have been called for email) and returns the resulting access/refresh
// tokens plus the account's user id, parsed off the access token — the
// starting point every TOTP enrollment test needs (enrollment requires an
// already-authenticated session).
func mustLoginFull(t *testing.T, svc *auth.Service, tokens *auth.TokenManager, mailer *testutil.FakeMailer, apiClientID, email, password string) (userID, access, refresh string) {
	t.Helper()
	loginToken, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, password)
	if err != nil {
		t.Fatalf("LoginStep1: %v", err)
	}
	sent, ok := mailer.Last()
	if !ok {
		t.Fatal("LoginStep1: no OTP email was sent")
	}
	code := testutil.ExtractOTPCode(sent.Body)
	access, refresh, err = svc.LoginStep2(t.Context(), loginToken, code)
	if err != nil {
		t.Fatalf("LoginStep2: %v", err)
	}
	claims, err := tokens.ParseAccessToken(access)
	if err != nil {
		t.Fatalf("parsing access token: %v", err)
	}
	return claims.Subject, access, refresh
}

// totpCodeFromOTPAuthURL extracts the secret embedded in an otpauth:// URL
// (what StartTOTPEnrollment returns, meant to be rendered as a QR code) and
// computes the code currently valid for it — standing in for "the user's
// authenticator app" in these tests.
func totpCodeFromOTPAuthURL(t *testing.T, otpauthURL string) string {
	t.Helper()
	u, err := url.Parse(otpauthURL)
	if err != nil {
		t.Fatalf("parsing otpauth url %q: %v", otpauthURL, err)
	}
	secret := u.Query().Get("secret")
	if secret == "" {
		t.Fatalf("otpauth url %q has no secret param", otpauthURL)
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("computing totp code: %v", err)
	}
	return code
}

func TestTOTPEnrollment_ThenLoginUsesTOTPInsteadOfEmail(t *testing.T) {
	svc, tokens, mailer, apiClientID := newTestService(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")
	userID, _, _ := mustLoginFull(t, svc, tokens, mailer, apiClientID, email, "correcthorsebattery")

	otpauthURL, err := svc.StartTOTPEnrollment(t.Context(), userID, email)
	if err != nil {
		t.Fatalf("StartTOTPEnrollment: %v", err)
	}
	code := totpCodeFromOTPAuthURL(t, otpauthURL)

	if err := svc.ConfirmTOTPEnrollment(t.Context(), userID, code); err != nil {
		t.Fatalf("ConfirmTOTPEnrollment: %v", err)
	}

	sentBefore := len(mailer.Sent())
	loginToken, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery")
	if err != nil {
		t.Fatalf("LoginStep1 after enabling TOTP: %v", err)
	}
	if len(mailer.Sent()) != sentBefore {
		t.Fatalf("LoginStep1 for a TOTP-enabled account sent an email (count %d -> %d) — it must not, that's the whole point of the TOTP path", sentBefore, len(mailer.Sent()))
	}

	// The client is expected to already have a fresh code from its
	// authenticator app — recompute one the same way.
	loginCode := totpCodeFromOTPAuthURL(t, otpauthURL)
	access, refresh, err := svc.LoginStep2(t.Context(), loginToken, loginCode)
	if err != nil {
		t.Fatalf("LoginStep2 with a TOTP code: %v", err)
	}
	if access == "" || refresh == "" {
		t.Fatal("LoginStep2: expected non-empty access and refresh tokens")
	}

	// Single-use, same as the email flow.
	if _, _, err := svc.LoginStep2(t.Context(), loginToken, loginCode); err == nil {
		t.Fatal("LoginStep2 a second time: want error (session already consumed), got nil")
	}
}

func TestConfirmTOTPEnrollment_WrongCodeDoesNotEnable(t *testing.T) {
	svc, tokens, mailer, apiClientID := newTestService(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")
	userID, _, _ := mustLoginFull(t, svc, tokens, mailer, apiClientID, email, "correcthorsebattery")

	if _, err := svc.StartTOTPEnrollment(t.Context(), userID, email); err != nil {
		t.Fatalf("StartTOTPEnrollment: %v", err)
	}

	if err := svc.ConfirmTOTPEnrollment(t.Context(), userID, "000000"); err != auth.ErrInvalidTOTPCode {
		t.Fatalf("ConfirmTOTPEnrollment with a wrong code: err = %v, want %v", err, auth.ErrInvalidTOTPCode)
	}

	// Never confirmed — login must still go through the email path.
	sentBefore := len(mailer.Sent())
	if _, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery"); err != nil {
		t.Fatalf("LoginStep1: %v", err)
	}
	if len(mailer.Sent()) != sentBefore+1 {
		t.Fatalf("LoginStep1 after an unconfirmed enrollment: want a new OTP email, got %d -> %d sent", sentBefore, len(mailer.Sent()))
	}
}

func TestLoginStep2_TOTP_WrongCodeExhaustsAttempts(t *testing.T) {
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
		t.Fatalf("LoginStep1: %v", err)
	}

	// newTestService's loginAttempts limiter allows 3 failures before
	// locking — same check-then-record shape as the password lockout (see
	// TestLoginStep1_LocksOutAfterTooManyFailures): the lock is only
	// enforced on the attempt AFTER the count reaches maxFails, not on the
	// failure that makes it reach maxFails.
	for i := 1; i <= 3; i++ {
		if _, _, err := svc.LoginStep2(t.Context(), loginToken, "000000"); err != auth.ErrInvalidTOTPCode {
			t.Fatalf("wrong-code attempt %d: err = %v, want %v", i, err, auth.ErrInvalidTOTPCode)
		}
	}
	if _, _, err := svc.LoginStep2(t.Context(), loginToken, "000000"); err != auth.ErrTooManyAttempts {
		t.Fatalf("wrong-code attempt 4: err = %v, want %v", err, auth.ErrTooManyAttempts)
	}

	// Locked out now — even the correct code is rejected, and the session
	// itself was consumed by the lockout.
	correctCode := totpCodeFromOTPAuthURL(t, otpauthURL)
	if _, _, err := svc.LoginStep2(t.Context(), loginToken, correctCode); err == nil {
		t.Fatal("LoginStep2 with the correct code after lockout: want an error, got nil")
	}
}

func TestDisableTOTP_LoginFallsBackToEmail(t *testing.T) {
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

	if err := svc.DisableTOTP(t.Context(), userID); err != nil {
		t.Fatalf("DisableTOTP: %v", err)
	}

	sentBefore := len(mailer.Sent())
	if _, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery"); err != nil {
		t.Fatalf("LoginStep1 after DisableTOTP: %v", err)
	}
	if len(mailer.Sent()) != sentBefore+1 {
		t.Fatalf("LoginStep1 after DisableTOTP: want a new OTP email, got %d -> %d sent", sentBefore, len(mailer.Sent()))
	}
}

// A Service built with a nil TOTPManager/TOTPLoginStore (TOTP_ENCRYPTION_KEY
// unset) must fail closed with a clear error, not panic — see
// TestDeviceLogin_BannedAccountIsRefused's Service construction for the
// nil,nil case this exercises.
func TestStartTOTPEnrollment_NotConfigured(t *testing.T) {
	pool := testutil.PostgresPool(t)
	rdb := testutil.RedisClient(t)
	client, _ := testutil.NewAPIClient(t, pool)
	apiClientID := client.ID

	users := user.NewService(user.NewRepository(pool))
	otpStore := auth.NewOTPStore(rdb, 5*time.Minute, 3, 6)
	tokens := auth.NewTokenManager(testutil.RSAKey(t), "test-key-1", "test-refresh-secret", 15*time.Minute, 7*24*time.Hour)
	refresh := auth.NewRefreshRepository(pool)
	devices := device.NewService(device.NewRepository(pool), 30*24*time.Hour, 3)
	passwordReset := auth.NewPasswordResetStore(rdb, time.Hour, 3, 6)
	emailVerification := auth.NewEmailVerificationStore(rdb, 24*time.Hour, 3, 6)
	loginAttempts := auth.NewLoginAttemptLimiter(rdb, 3, 15*time.Minute)
	mailer := testutil.NewFakeMailer()
	svc := auth.NewService(users, otpStore, tokens, refresh, devices, passwordReset, emailVerification, loginAttempts, mailer, 5*time.Minute, 7*24*time.Hour, time.Hour, 24*time.Hour, nil, nil, nil, nil, nil, nil, nil)

	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")
	userID, _, _ := mustLoginFull(t, svc, tokens, mailer, apiClientID, email, "correcthorsebattery")

	if _, err := svc.StartTOTPEnrollment(t.Context(), userID, email); err != auth.ErrTOTPNotConfigured {
		t.Fatalf("StartTOTPEnrollment with no TOTPManager configured: err = %v, want %v", err, auth.ErrTOTPNotConfigured)
	}
}

// --- First-login "choose email or authenticator" (see LoginStep1) ---

// When TOTP isn't configured on this deployment at all, there's nothing to
// choose between — LoginStep1 must behave exactly as it always did
// (needsSetup always false, straight to email). This is really what every
// other test in this file already assumes implicitly (newTestService wires
// twoFactorSetup as nil); this test just makes the contract explicit.
func TestLoginStep1_NoChoiceWhenTOTPNotConfigured(t *testing.T) {
	svc, _, mailer, apiClientID := newTestService(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")

	_, needsSetup, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery")
	if err != nil {
		t.Fatalf("LoginStep1: %v", err)
	}
	if needsSetup {
		t.Fatal("needsSetup = true with TOTP not configured on this deployment, want false")
	}
	if _, ok := mailer.Last(); !ok {
		t.Fatal("LoginStep1 with TOTP not configured must still email the OTP code, same as always")
	}
}

func TestLoginStep1_FirstLogin_NeedsSetup_NoEmailSentYet(t *testing.T) {
	svc, _, mailer, apiClientID := newTestServiceWithChoice(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")
	sentBefore := len(mailer.Sent()) // mustRegister itself already sent a verification email

	loginToken, needsSetup, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery")
	if err != nil {
		t.Fatalf("LoginStep1: %v", err)
	}
	if !needsSetup {
		t.Fatal("first-ever login: needsSetup = false, want true")
	}
	if loginToken == "" {
		t.Fatal("LoginStep1: empty login token")
	}
	if len(mailer.Sent()) != sentBefore {
		t.Fatal("first-ever login must NOT auto-send an OTP email — the client hasn't chosen a method yet")
	}
}

func TestSendLoginEmailCode_CompletesFirstLoginAndLocksInEmail(t *testing.T) {
	svc, _, mailer, apiClientID := newTestServiceWithChoice(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")

	loginToken, needsSetup, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery")
	if err != nil || !needsSetup {
		t.Fatalf("LoginStep1: needsSetup=%v err=%v, want true, nil", needsSetup, err)
	}

	if err := svc.SendLoginEmailCode(t.Context(), loginToken); err != nil {
		t.Fatalf("SendLoginEmailCode: %v", err)
	}
	sent, ok := mailer.Last()
	if !ok {
		t.Fatal("SendLoginEmailCode: no email was sent")
	}
	code := testutil.ExtractOTPCode(sent.Body)
	if code == "" {
		t.Fatalf("could not find an OTP code in email body: %q", sent.Body)
	}

	// Same login_token throughout — VerifyOTP/LoginStep2 just works.
	access, refresh, err := svc.LoginStep2(t.Context(), loginToken, code)
	if err != nil {
		t.Fatalf("LoginStep2: %v", err)
	}
	if access == "" || refresh == "" {
		t.Fatal("LoginStep2: expected non-empty access and refresh tokens")
	}

	// The choice is locked in now — next login skips the setup screen and
	// goes straight to email, exactly like every account that predates
	// this feature.
	sentBefore := len(mailer.Sent())
	_, needsSetup2, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery")
	if err != nil {
		t.Fatalf("LoginStep1 (second login): %v", err)
	}
	if needsSetup2 {
		t.Fatal("second login: needsSetup = true, want false (already chosen)")
	}
	if len(mailer.Sent()) != sentBefore+1 {
		t.Fatalf("second login: want a new OTP email sent automatically, got %d -> %d", sentBefore, len(mailer.Sent()))
	}
}

// A stale/unknown/already-consumed login_token must fail clearly, not
// panic or silently succeed.
func TestSendLoginEmailCode_UnknownToken(t *testing.T) {
	svc, _, _, _ := newTestServiceWithChoice(t)
	if err := svc.SendLoginEmailCode(t.Context(), "does-not-exist"); err != auth.ErrLoginSessionNotFound {
		t.Fatalf("err = %v, want %v", err, auth.ErrLoginSessionNotFound)
	}
}

func TestFirstLogin_TOTPBranch_EnrollAndConfirmCompletesLoginAndLocksInTOTP(t *testing.T) {
	svc, tokens, mailer, apiClientID := newTestServiceWithChoice(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")

	loginToken, needsSetup, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery")
	if err != nil || !needsSetup {
		t.Fatalf("LoginStep1: needsSetup=%v err=%v, want true, nil", needsSetup, err)
	}

	// EnrollTOTP's setup-flow path: resolve the account from the pending
	// login_token (no access_token exists yet at this point).
	peekedUserID, peekedEmail, err := svc.PeekTwoFactorSetup(t.Context(), loginToken)
	if err != nil {
		t.Fatalf("PeekTwoFactorSetup: %v", err)
	}
	if peekedEmail != email {
		t.Fatalf("PeekTwoFactorSetup email = %q, want %q", peekedEmail, email)
	}

	otpauthURL, err := svc.StartTOTPEnrollment(t.Context(), peekedUserID, peekedEmail)
	if err != nil {
		t.Fatalf("StartTOTPEnrollment: %v", err)
	}

	// Wrong code: doesn't consume the setup session or complete the login.
	if _, _, err := svc.ConfirmTOTPEnrollmentAndLogin(t.Context(), loginToken, "000000"); err != auth.ErrInvalidTOTPCode {
		t.Fatalf("ConfirmTOTPEnrollmentAndLogin with a wrong code: err = %v, want %v", err, auth.ErrInvalidTOTPCode)
	}

	code := totpCodeFromOTPAuthURL(t, otpauthURL)
	access, refresh, err := svc.ConfirmTOTPEnrollmentAndLogin(t.Context(), loginToken, code)
	if err != nil {
		t.Fatalf("ConfirmTOTPEnrollmentAndLogin: %v", err)
	}
	if access == "" || refresh == "" {
		t.Fatal("ConfirmTOTPEnrollmentAndLogin: expected non-empty access and refresh tokens")
	}
	if _, err := tokens.ParseAccessToken(access); err != nil {
		t.Fatalf("access token from ConfirmTOTPEnrollmentAndLogin doesn't parse: %v", err)
	}

	// Single-use: the setup session was consumed by the successful confirm.
	if _, _, err := svc.ConfirmTOTPEnrollmentAndLogin(t.Context(), loginToken, code); err != auth.ErrLoginSessionNotFound {
		t.Fatalf("ConfirmTOTPEnrollmentAndLogin a second time: err = %v, want %v", err, auth.ErrLoginSessionNotFound)
	}

	// Locked in — next login skips the setup screen and goes straight to
	// TOTP, no email at all.
	sentBefore := len(mailer.Sent())
	loginToken2, needsSetup2, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery")
	if err != nil {
		t.Fatalf("LoginStep1 (second login): %v", err)
	}
	if needsSetup2 {
		t.Fatal("second login: needsSetup = true, want false (already chosen)")
	}
	if len(mailer.Sent()) != sentBefore {
		t.Fatal("second login: must not send an email — TOTP is now this account's method")
	}
	loginCode := totpCodeFromOTPAuthURL(t, otpauthURL)
	if _, _, err := svc.LoginStep2(t.Context(), loginToken2, loginCode); err != nil {
		t.Fatalf("LoginStep2 (second login, TOTP code): %v", err)
	}
}
