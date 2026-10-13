package auth_test

import (
	"testing"
	"time"

	"auth-2fa-api/internal/auth"
	"auth-2fa-api/internal/device"
	"auth-2fa-api/internal/testutil"
	"auth-2fa-api/internal/user"
)

// newTestServiceWithPush wires a Service with a real PushLoginStore (no FCM
// client — SendLoginApproval is never exercised here, only the Redis-backed
// session that startPushLogin would have created) so RequestLoginEmailCode
// can be tested without touching Firebase at all.
func newTestServiceWithPush(t *testing.T) (svc *auth.Service, userSvc *user.Service, pushLogin *auth.PushLoginStore, mailer *testutil.FakeMailer, apiClientID string) {
	t.Helper()

	pool := testutil.PostgresPool(t)
	rdb := testutil.RedisClient(t)
	client, _ := testutil.NewAPIClient(t, pool)

	users := user.NewService(user.NewRepository(pool), 5, 15*time.Minute)
	otpStore := auth.NewOTPStore(rdb, 5*time.Minute, 3, 6)
	tokens := auth.NewTokenManager(testutil.RSAKey(t), "test-key-1", "test-refresh-secret", 15*time.Minute, 7*24*time.Hour)
	refresh := auth.NewRefreshRepository(pool)
	devices := device.NewService(device.NewRepository(pool), 30*24*time.Hour)
	passwordReset := auth.NewPasswordResetStore(rdb, time.Hour, 3, 6)
	emailVerification := auth.NewEmailVerificationStore(rdb, 24*time.Hour, 3, 6)
	loginAttempts := auth.NewLoginAttemptLimiter(rdb, 3, 15*time.Minute)
	mailer = testutil.NewFakeMailer()
	pushLogin = auth.NewPushLoginStore(rdb, time.Minute)

	svc = auth.NewService(users, otpStore, tokens, refresh, devices, passwordReset, emailVerification, nil, loginAttempts, mailer, 5*time.Minute, 7*24*time.Hour, time.Hour, 24*time.Hour, time.Hour, nil, nil, nil, nil, pushLogin, nil, nil, nil, nil, "", nil, nil, nil)
	return svc, users, pushLogin, mailer, client.ID
}

func TestRequestLoginEmailCode_SendsCodeUnderSameTokenAndCompletesLogin(t *testing.T) {
	svc, userSvc, pushLogin, mailer, apiClientID := newTestServiceWithPush(t)

	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")
	u, err := userSvc.FindByEmail(t.Context(), apiClientID, email)
	if err != nil {
		t.Fatalf("FindByEmail: %v", err)
	}

	const loginToken = "shared-login-token"
	if err := pushLogin.Start(t.Context(), loginToken, u.ID, apiClientID, email, 42); err != nil {
		t.Fatalf("seeding push session: %v", err)
	}

	if err := svc.RequestLoginEmailCode(t.Context(), loginToken); err != nil {
		t.Fatalf("RequestLoginEmailCode: %v", err)
	}

	sent, ok := mailer.Last()
	if !ok {
		t.Fatal("RequestLoginEmailCode: no email was sent")
	}
	if sent.To != email {
		t.Fatalf("email sent to %q, want %q", sent.To, email)
	}

	code := testutil.ExtractOTPCode(sent.Body)

	// The exact same loginToken must now work with the normal email login
	// step — no second token, no special-casing on the caller's side.
	access, refreshTok, err := loginStep2Tokens(t, svc, loginToken, code)
	if err != nil {
		t.Fatalf("LoginStep2 with the requested code: %v", err)
	}
	if access == "" || refreshTok == "" {
		t.Fatal("LoginStep2 returned empty tokens")
	}
}

func TestRequestLoginEmailCode_UnknownToken(t *testing.T) {
	svc, _, _, _, _ := newTestServiceWithPush(t)

	if err := svc.RequestLoginEmailCode(t.Context(), "does-not-exist"); err != auth.ErrLoginSessionNotFound {
		t.Fatalf("RequestLoginEmailCode with unknown token: err = %v, want ErrLoginSessionNotFound", err)
	}
}

func TestRequestLoginEmailCode_NotConfigured(t *testing.T) {
	pool := testutil.PostgresPool(t)
	rdb := testutil.RedisClient(t)
	client, _ := testutil.NewAPIClient(t, pool)

	users := user.NewService(user.NewRepository(pool), 5, 15*time.Minute)
	otpStore := auth.NewOTPStore(rdb, 5*time.Minute, 3, 6)
	tokens := auth.NewTokenManager(testutil.RSAKey(t), "test-key-1", "test-refresh-secret", 15*time.Minute, 7*24*time.Hour)
	refresh := auth.NewRefreshRepository(pool)
	devices := device.NewService(device.NewRepository(pool), 30*24*time.Hour)
	passwordReset := auth.NewPasswordResetStore(rdb, time.Hour, 3, 6)
	emailVerification := auth.NewEmailVerificationStore(rdb, 24*time.Hour, 3, 6)
	loginAttempts := auth.NewLoginAttemptLimiter(rdb, 3, 15*time.Minute)
	mailer := testutil.NewFakeMailer()

	// pushLogin deliberately nil — same "feature not configured" shape as
	// every other push method.
	svc := auth.NewService(users, otpStore, tokens, refresh, devices, passwordReset, emailVerification, nil, loginAttempts, mailer, 5*time.Minute, 7*24*time.Hour, time.Hour, 24*time.Hour, time.Hour, nil, nil, nil, nil, nil, nil, nil, nil, nil, "", nil, nil, nil)
	_ = client

	if err := svc.RequestLoginEmailCode(t.Context(), "whatever"); err != auth.ErrPushNotConfigured {
		t.Fatalf("RequestLoginEmailCode with push unconfigured: err = %v, want ErrPushNotConfigured", err)
	}
}
