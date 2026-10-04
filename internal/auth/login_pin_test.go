package auth_test

import (
	"errors"
	"testing"
	"time"

	"auth-2fa-api/internal/auth"
	"auth-2fa-api/internal/device"
	"auth-2fa-api/internal/testutil"
	"auth-2fa-api/internal/user"
)

// newTestServiceWithLoginPin is newTestService but with a real
// PinLoginStore wired in, and configurable account-PIN lockout limits —
// the mandatory login-pin step (see auth.LoginResult/LoginPinStep,
// PinRequiredAtLogin) needs both; every other test in this package uses
// newTestService, which deliberately leaves PinLoginStore nil since none of
// them ever set PinRequiredAtLogin.
func newTestServiceWithLoginPin(t *testing.T, pinMaxFailedTries int, pinLockDuration time.Duration) (svc *auth.Service, tokens *auth.TokenManager, mailer *testutil.FakeMailer, apiClientID string) {
	t.Helper()

	pool := testutil.PostgresPool(t)
	rdb := testutil.RedisClient(t)
	client, _ := testutil.NewAPIClient(t, pool)

	users := user.NewService(user.NewRepository(pool), pinMaxFailedTries, pinLockDuration)
	otpStore := auth.NewOTPStore(rdb, 5*time.Minute, 3, 6)
	tokens = auth.NewTokenManager(testutil.RSAKey(t), "test-key-1", "test-refresh-secret", 15*time.Minute, 7*24*time.Hour)
	refresh := auth.NewRefreshRepository(pool)
	devices := device.NewService(device.NewRepository(pool), 30*24*time.Hour)
	passwordReset := auth.NewPasswordResetStore(rdb, time.Hour, 3, 6)
	emailVerification := auth.NewEmailVerificationStore(rdb, 24*time.Hour, 3, 6)
	loginAttempts := auth.NewLoginAttemptLimiter(rdb, 3, 15*time.Minute)
	mailer = testutil.NewFakeMailer()
	totpManager, err := auth.NewTOTPManager("test-issuer", testTOTPKey)
	if err != nil {
		t.Fatalf("NewTOTPManager: %v", err)
	}
	totpLogin := auth.NewTOTPLoginStore(rdb, 5*time.Minute)
	loginPin := auth.NewPinLoginStore(rdb, time.Minute)

	svc = auth.NewService(users, otpStore, tokens, refresh, devices, passwordReset, emailVerification, nil, loginAttempts, mailer, 5*time.Minute, 7*24*time.Hour, time.Hour, 24*time.Hour, time.Hour, totpManager, totpLogin, nil, nil, nil, nil, nil, nil, nil, "", loginPin)
	return svc, tokens, mailer, client.ID
}

// TestLoginPinStep_FullFlow covers the core contract: an account with
// PinRequiredAtLogin set gets no tokens from LoginStep2 even after a
// correct password+OTP, only a pending pin_token — and only completing
// LoginPinStep with the account's existing PIN actually issues them. A
// normal refresh afterward keeps working, same as any other session.
func TestLoginPinStep_FullFlow(t *testing.T) {
	svc, tokens, mailer, apiClientID := newTestServiceWithLoginPin(t, 5, 15*time.Minute)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")
	userID, _, _ := mustLoginFull(t, svc, tokens, mailer, apiClientID, email, "correcthorsebattery")

	if err := svc.SetPin(t.Context(), userID, "123456", ""); err != nil {
		t.Fatalf("SetPin: %v", err)
	}
	if err := svc.AdminSetLoginPinRequired(t.Context(), apiClientID, userID, true); err != nil {
		t.Fatalf("AdminSetLoginPinRequired: %v", err)
	}

	loginToken, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery")
	if err != nil {
		t.Fatalf("LoginStep1: %v", err)
	}
	sent, ok := mailer.Last()
	if !ok {
		t.Fatal("LoginStep1: no OTP email was sent")
	}
	code := testutil.ExtractOTPCode(sent.Body)

	result, err := svc.LoginStep2(t.Context(), loginToken, code)
	if err != nil {
		t.Fatalf("LoginStep2: %v", err)
	}
	if !result.PinRequired {
		t.Fatal("LoginStep2: PinRequired = false, want true")
	}
	if result.AccessToken != "" || result.RefreshToken != "" {
		t.Fatal("LoginStep2: tokens were issued despite PinRequiredAtLogin")
	}
	if !result.PinSet {
		t.Fatal("LoginStep2: PinSet = false, want true (the account already has a pin)")
	}
	if result.PinToken == "" {
		t.Fatal("LoginStep2: PinToken is empty")
	}

	final, err := svc.LoginPinStep(t.Context(), result.PinToken, "123456", false)
	if err != nil {
		t.Fatalf("LoginPinStep: %v", err)
	}
	if final.AccessToken == "" || final.RefreshToken == "" {
		t.Fatal("LoginPinStep: expected a token pair")
	}

	if _, _, err := svc.Refresh(t.Context(), final.RefreshToken); err != nil {
		t.Fatalf("Refresh after the login-pin step: %v", err)
	}
}

// TestLoginPinStep_CreatesPinWhenNotSet covers the account-has-no-pin-yet
// branch: LoginStep2 reports PinSet false, and LoginPinStep with
// create: true both sets the account's PIN and completes the login in one
// call — same reuse of EnsurePin's dual meaning RegisterDevice already has.
func TestLoginPinStep_CreatesPinWhenNotSet(t *testing.T) {
	svc, tokens, mailer, apiClientID := newTestServiceWithLoginPin(t, 5, 15*time.Minute)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")
	userID, _, _ := mustLoginFull(t, svc, tokens, mailer, apiClientID, email, "correcthorsebattery")

	if err := svc.AdminSetLoginPinRequired(t.Context(), apiClientID, userID, true); err != nil {
		t.Fatalf("AdminSetLoginPinRequired: %v", err)
	}

	loginToken, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery")
	if err != nil {
		t.Fatalf("LoginStep1: %v", err)
	}
	sent, _ := mailer.Last()
	code := testutil.ExtractOTPCode(sent.Body)

	result, err := svc.LoginStep2(t.Context(), loginToken, code)
	if err != nil {
		t.Fatalf("LoginStep2: %v", err)
	}
	if !result.PinRequired {
		t.Fatal("LoginStep2: PinRequired = false, want true")
	}
	if result.PinSet {
		t.Fatal("LoginStep2: PinSet = true, want false (the account has no pin yet)")
	}

	final, err := svc.LoginPinStep(t.Context(), result.PinToken, "654321", true)
	if err != nil {
		t.Fatalf("LoginPinStep with create=true: %v", err)
	}
	if final.AccessToken == "" || final.RefreshToken == "" {
		t.Fatal("LoginPinStep with create=true: expected a token pair")
	}

	// The PIN really was created — a second login now requires IT, not a
	// fresh create.
	loginToken2, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery")
	if err != nil {
		t.Fatalf("second LoginStep1: %v", err)
	}
	sent2, _ := mailer.Last()
	code2 := testutil.ExtractOTPCode(sent2.Body)
	result2, err := svc.LoginStep2(t.Context(), loginToken2, code2)
	if err != nil {
		t.Fatalf("second LoginStep2: %v", err)
	}
	if !result2.PinSet {
		t.Fatal("second LoginStep2: PinSet = false, want true (the pin was created by the previous step)")
	}
	if _, err := svc.LoginPinStep(t.Context(), result2.PinToken, "654321", false); err != nil {
		t.Fatalf("second LoginPinStep with the newly created pin: %v", err)
	}
}

// TestLoginPinStep_WrongPinLocksOut covers that this step's failed attempts
// share the account PIN's own lockout counter (user.Service.VerifyPin), and
// that a wrong guess does NOT burn pin_token — the same token keeps working
// (modulo the lockout itself) across several attempts, same as a wrong
// email-OTP code doesn't burn login_token.
func TestLoginPinStep_WrongPinLocksOut(t *testing.T) {
	const maxTries = 2
	svc, tokens, mailer, apiClientID := newTestServiceWithLoginPin(t, maxTries, time.Minute)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")
	userID, _, _ := mustLoginFull(t, svc, tokens, mailer, apiClientID, email, "correcthorsebattery")

	if err := svc.SetPin(t.Context(), userID, "123456", ""); err != nil {
		t.Fatalf("SetPin: %v", err)
	}
	if err := svc.AdminSetLoginPinRequired(t.Context(), apiClientID, userID, true); err != nil {
		t.Fatalf("AdminSetLoginPinRequired: %v", err)
	}

	loginToken, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery")
	if err != nil {
		t.Fatalf("LoginStep1: %v", err)
	}
	sent, _ := mailer.Last()
	code := testutil.ExtractOTPCode(sent.Body)
	result, err := svc.LoginStep2(t.Context(), loginToken, code)
	if err != nil {
		t.Fatalf("LoginStep2: %v", err)
	}

	if _, err := svc.LoginPinStep(t.Context(), result.PinToken, "000000", false); !errors.As(err, new(*user.PinInvalidError)) {
		t.Fatalf("1st wrong pin: err = %v, want a *user.PinInvalidError", err)
	}

	var locked *user.PinLockedError
	if _, err := svc.LoginPinStep(t.Context(), result.PinToken, "000000", false); !errors.As(err, &locked) {
		t.Fatalf("2nd wrong pin (crosses threshold): err = %v, want a *user.PinLockedError", err)
	}

	// Still locked — even the correct PIN, with the SAME pin_token, is
	// refused, proving the token itself was never consumed by the failures.
	if _, err := svc.LoginPinStep(t.Context(), result.PinToken, "123456", false); !errors.As(err, new(*user.PinLockedError)) {
		t.Fatalf("correct pin while locked: err = %v, want a *user.PinLockedError", err)
	}
}

// TestLoginPinStep_ReusedOrExpiredToken covers pin_token's own single-use
// rule (on success only) and that an unknown/already-consumed token is
// reported the same way LoginStep2 reports an unknown login_token.
func TestLoginPinStep_ReusedOrExpiredToken(t *testing.T) {
	svc, tokens, mailer, apiClientID := newTestServiceWithLoginPin(t, 5, 15*time.Minute)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")
	userID, _, _ := mustLoginFull(t, svc, tokens, mailer, apiClientID, email, "correcthorsebattery")

	if err := svc.SetPin(t.Context(), userID, "123456", ""); err != nil {
		t.Fatalf("SetPin: %v", err)
	}
	if err := svc.AdminSetLoginPinRequired(t.Context(), apiClientID, userID, true); err != nil {
		t.Fatalf("AdminSetLoginPinRequired: %v", err)
	}

	if _, err := svc.LoginPinStep(t.Context(), "does-not-exist", "123456", false); err != auth.ErrLoginSessionNotFound {
		t.Fatalf("unknown pin_token: err = %v, want %v", err, auth.ErrLoginSessionNotFound)
	}

	loginToken, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery")
	if err != nil {
		t.Fatalf("LoginStep1: %v", err)
	}
	sent, _ := mailer.Last()
	code := testutil.ExtractOTPCode(sent.Body)
	result, err := svc.LoginStep2(t.Context(), loginToken, code)
	if err != nil {
		t.Fatalf("LoginStep2: %v", err)
	}

	if _, err := svc.LoginPinStep(t.Context(), result.PinToken, "123456", false); err != nil {
		t.Fatalf("LoginPinStep: %v", err)
	}
	// Reused — the session was consumed by the call above.
	if _, err := svc.LoginPinStep(t.Context(), result.PinToken, "123456", false); err != auth.ErrLoginSessionNotFound {
		t.Fatalf("reused pin_token: err = %v, want %v", err, auth.ErrLoginSessionNotFound)
	}
}

// TestVerifyTOTPLogin_RequiresPinStep covers that the login-pin step
// applies to the TOTP second factor too, not just the emailed OTP.
func TestVerifyTOTPLogin_RequiresPinStep(t *testing.T) {
	svc, tokens, mailer, apiClientID := newTestServiceWithLoginPin(t, 5, 15*time.Minute)
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
	if err := svc.SetPin(t.Context(), userID, "123456", ""); err != nil {
		t.Fatalf("SetPin: %v", err)
	}
	if err := svc.AdminSetLoginPinRequired(t.Context(), apiClientID, userID, true); err != nil {
		t.Fatalf("AdminSetLoginPinRequired: %v", err)
	}

	loginToken, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery")
	if err != nil {
		t.Fatalf("LoginStep1: %v", err)
	}
	result, err := svc.LoginStep2(t.Context(), loginToken, totpCodeFromOTPAuthURL(t, otpauthURL))
	if err != nil {
		t.Fatalf("LoginStep2 with a TOTP code: %v", err)
	}
	if !result.PinRequired || result.AccessToken != "" {
		t.Fatalf("LoginStep2 (TOTP path): PinRequired = %v, AccessToken = %q, want PinRequired=true and no tokens", result.PinRequired, result.AccessToken)
	}

	final, err := svc.LoginPinStep(t.Context(), result.PinToken, "123456", false)
	if err != nil {
		t.Fatalf("LoginPinStep: %v", err)
	}
	if final.AccessToken == "" {
		t.Fatal("LoginPinStep: expected a token pair")
	}
}

// TestDeviceLogin_RequiresFullLoginWhenPinRequired covers that the
// trusted-device shortcut (device_token + account pin, no second factor at
// all) can't satisfy an account that requires the full password + second
// factor + pin flow — it never even checked a second factor, so it can't be
// the thing that stands in for this step.
func TestDeviceLogin_RequiresFullLoginWhenPinRequired(t *testing.T) {
	svc, tokens, mailer, apiClientID := newTestServiceWithLoginPin(t, 5, 15*time.Minute)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")
	userID, _, _ := mustLoginFull(t, svc, tokens, mailer, apiClientID, email, "correcthorsebattery")

	deviceID := "device-" + testutil.UniqueSuffix(t)
	deviceToken, err := svc.RegisterDevice(t.Context(), userID, deviceID, "Test Phone", "123456")
	if err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}

	// Works before the switch is on — the baseline this test's real
	// assertion (right below) is contrasted against.
	if _, _, _, err := svc.DeviceLogin(t.Context(), deviceID, deviceToken, "123456"); err != nil {
		t.Fatalf("DeviceLogin before PinRequiredAtLogin: %v", err)
	}
	// DeviceLogin rotates the token on every call — re-register fresh so the
	// next call below uses one that's still valid.
	deviceToken, err = svc.RegisterDevice(t.Context(), userID, deviceID, "Test Phone", "123456")
	if err != nil {
		t.Fatalf("re-RegisterDevice: %v", err)
	}

	if err := svc.AdminSetLoginPinRequired(t.Context(), apiClientID, userID, true); err != nil {
		t.Fatalf("AdminSetLoginPinRequired: %v", err)
	}

	if _, _, _, err := svc.DeviceLogin(t.Context(), deviceID, deviceToken, "123456"); err != auth.ErrLoginPinStepRequired {
		t.Fatalf("DeviceLogin with PinRequiredAtLogin set: err = %v, want %v", err, auth.ErrLoginPinStepRequired)
	}
}
