package auth_test

// Covers that the login/password-reset/register paths actually write
// auth_events rows with the fields the design calls for — see
// internal/authevents for the package itself (already covered by its own
// unit tests) and internal/stats for how these rows get aggregated into
// GET /admin/stats. These tests are about the wiring: does the right kind/
// method/result/user_id/email_hash end up in the table for a given call.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/metric/noop"

	"auth-2fa-api/internal/auth"
	"auth-2fa-api/internal/authevents"
	"auth-2fa-api/internal/device"
	"auth-2fa-api/internal/testutil"
	"auth-2fa-api/internal/user"
)

// testEmailHashSecret is a fixed secret used only in tests — real
// deployments generate their own via AUTH_EVENTS_EMAIL_HASH_SECRET.
var testEmailHashSecret = []byte("test-auth-events-email-hash-secret")

// newTestServiceWithAuthEvents is newTestService but with a real
// authevents.Service wired in (against the same pool), so a test can
// query auth_events directly afterward to assert what got written. A
// separate helper rather than changing newTestService itself — most tests
// in this package don't care about auth_events and already pass against
// a nil *authevents.Service (see authevents.Service.Log's nil-safety).
func newTestServiceWithAuthEvents(t *testing.T) (svc *auth.Service, pool *pgxpool.Pool, mailer *testutil.FakeMailer, apiClientID string) {
	t.Helper()

	pool = testutil.PostgresPool(t)
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

	authEvents := authevents.NewService(authevents.NewRepository(pool), 90*24*time.Hour, testEmailHashSecret, noop.NewMeterProvider().Meter("test"), nil)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM auth_events WHERE api_client_id = $1`, client.ID)
	})

	svc = auth.NewService(users, otpStore, tokens, refresh, devices, passwordReset, emailVerification, nil, loginAttempts, mailer, 5*time.Minute, 7*24*time.Hour, time.Hour, 24*time.Hour, time.Hour, nil, nil, nil, nil, nil, nil, nil, nil, nil, "", nil, authEvents, nil)
	return svc, pool, mailer, client.ID
}

type authEventRow struct {
	Kind      string
	Method    string
	Result    string
	UserID    string
	EmailHash string
}

func lastAuthEvent(t *testing.T, pool *pgxpool.Pool, apiClientID, kind string) authEventRow {
	t.Helper()
	var row authEventRow
	err := pool.QueryRow(context.Background(), `
		SELECT kind, COALESCE(method, ''), result, COALESCE(user_id::text, ''), COALESCE(email_hash, '')
		FROM auth_events
		WHERE api_client_id = $1 AND kind = $2
		ORDER BY id DESC LIMIT 1`, apiClientID, kind).
		Scan(&row.Kind, &row.Method, &row.Result, &row.UserID, &row.EmailHash)
	if err != nil {
		t.Fatalf("querying last auth_events row (kind=%s): %v", kind, err)
	}
	return row
}

func mustRegisterWithEvents(t *testing.T, svc *auth.Service, mailer *testutil.FakeMailer, apiClientID, email string) *user.User {
	t.Helper()
	u, err := svc.Register(t.Context(), apiClientID, email, "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t), nil)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	sent, ok := mailer.Last()
	if !ok {
		t.Fatalf("Register(%q): no verification email was sent", email)
	}
	code := testutil.ExtractVerificationCode(sent.Body)
	if err := svc.ConfirmEmailVerification(t.Context(), apiClientID, email, code); err != nil {
		t.Fatalf("ConfirmEmailVerification: %v", err)
	}
	return u
}

func TestLoginStep1_Success_DoesNotLogIntermediateStep(t *testing.T) {
	svc, pool, mailer, apiClientID := newTestServiceWithAuthEvents(t)
	email := "events-login-ok-" + testutil.UniqueSuffix(t) + "@example.com"
	u := mustRegisterWithEvents(t, svc, mailer, apiClientID, email)

	// Password is correct — LoginStep1 only gets this far, never finishes
	// a login (the second factor is still pending) — see finishLogin's
	// own doc comment for why this must NOT log a success row yet.
	if _, _, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery", nil); err != nil {
		t.Fatalf("LoginStep1: %v", err)
	}

	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM auth_events WHERE api_client_id = $1 AND user_id = $2 AND kind = $3`,
		apiClientID, u.ID, authevents.KindLogin).Scan(&count); err != nil {
		t.Fatalf("counting auth_events: %v", err)
	}
	if count != 0 {
		t.Fatalf("auth_events login rows after a correct-password-but-pending-2FA LoginStep1 = %d, want 0 (not a completed login)", count)
	}
}

func TestLoginStep1_BadPassword_LogsBadCredentialsWithUserID(t *testing.T) {
	svc, pool, mailer, apiClientID := newTestServiceWithAuthEvents(t)
	email := "events-login-bad-" + testutil.UniqueSuffix(t) + "@example.com"
	u := mustRegisterWithEvents(t, svc, mailer, apiClientID, email)

	if _, _, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "wrong-password", nil); err == nil {
		t.Fatal("LoginStep1 with wrong password: want an error")
	}

	row := lastAuthEvent(t, pool, apiClientID, authevents.KindLogin)
	if row.Result != authevents.ResultBadCredentials {
		t.Fatalf("result = %q, want %q", row.Result, authevents.ResultBadCredentials)
	}
	if row.Method != authevents.MethodPassword {
		t.Fatalf("method = %q, want %q", row.Method, authevents.MethodPassword)
	}
	// user_id IS set — the identifier resolved to a real account, even
	// though the response stays the same generic "invalid credentials"
	// (see authevents.ResultBadCredentials' own doc comment).
	if row.UserID != u.ID {
		t.Fatalf("user_id = %q, want %q", row.UserID, u.ID)
	}
	if row.EmailHash != "" {
		t.Fatalf("email_hash = %q, want empty when user_id resolved", row.EmailHash)
	}
}

func TestLoginStep1_UnknownIdentifier_LogsEmailHashNoUserID(t *testing.T) {
	svc, pool, _, apiClientID := newTestServiceWithAuthEvents(t)
	identifier := "events-login-unknown-" + testutil.UniqueSuffix(t) + "@example.com"

	if _, _, _, _, err := svc.LoginStep1(t.Context(), apiClientID, identifier, "whatever-password", nil); err == nil {
		t.Fatal("LoginStep1 with unknown identifier: want an error")
	}

	row := lastAuthEvent(t, pool, apiClientID, authevents.KindLogin)
	if row.Result != authevents.ResultBadCredentials {
		t.Fatalf("result = %q, want %q", row.Result, authevents.ResultBadCredentials)
	}
	if row.UserID != "" {
		t.Fatalf("user_id = %q, want empty for an unresolved identifier", row.UserID)
	}
	if row.EmailHash == "" {
		t.Fatal("email_hash is empty, want a hash for an unresolved identifier")
	}
	if row.EmailHash == identifier {
		t.Fatal("email_hash equals the raw identifier — must be hashed, never stored in clear")
	}
}

func TestFinishLogin_Success_LogsSuccessWithMethod(t *testing.T) {
	svc, pool, mailer, apiClientID := newTestServiceWithAuthEvents(t)
	email := "events-login-success-" + testutil.UniqueSuffix(t) + "@example.com"
	u := mustRegisterWithEvents(t, svc, mailer, apiClientID, email)

	loginToken, _, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery", nil)
	if err != nil {
		t.Fatalf("LoginStep1: %v", err)
	}
	sent, ok := mailer.Last()
	if !ok {
		t.Fatal("LoginStep1: no OTP email was sent")
	}
	code := testutil.ExtractOTPCode(sent.Body)
	result, err := svc.LoginStep2(t.Context(), loginToken, code, nil)
	if err != nil {
		t.Fatalf("LoginStep2: %v", err)
	}
	if result.AccessToken == "" {
		t.Fatal("LoginStep2 succeeded but issued no access token")
	}

	row := lastAuthEvent(t, pool, apiClientID, authevents.KindLogin)
	if row.Result != authevents.ResultSuccess {
		t.Fatalf("result = %q, want %q", row.Result, authevents.ResultSuccess)
	}
	if row.Method != authevents.MethodEmailCode {
		t.Fatalf("method = %q, want %q", row.Method, authevents.MethodEmailCode)
	}
	if row.UserID != u.ID {
		t.Fatalf("user_id = %q, want %q", row.UserID, u.ID)
	}
}

func TestRequestPasswordReset_UnknownAccount_LogsAccountNotFoundNotCodeSent(t *testing.T) {
	svc, pool, _, apiClientID := newTestServiceWithAuthEvents(t)
	email := "events-reset-unknown-" + testutil.UniqueSuffix(t) + "@example.com"

	// RequestPasswordReset never returns an error for an unknown account
	// (see its own doc comment) — the HTTP response stays identical
	// either way, only the audit trail tells them apart.
	if err := svc.RequestPasswordReset(t.Context(), apiClientID, email, nil); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}

	row := lastAuthEvent(t, pool, apiClientID, authevents.KindPasswordResetRequest)
	if row.Result != authevents.ResultAccountNotFound {
		t.Fatalf("result = %q, want %q", row.Result, authevents.ResultAccountNotFound)
	}
	if row.EmailHash == "" {
		t.Fatal("email_hash is empty, want a hash for an unknown account")
	}
}

func TestRegister_DuplicateEmail_LogsEmailTaken(t *testing.T) {
	svc, pool, mailer, apiClientID := newTestServiceWithAuthEvents(t)
	email := "events-register-dup-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegisterWithEvents(t, svc, mailer, apiClientID, email)

	if _, err := svc.Register(t.Context(), apiClientID, email, "another-password", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t), nil); err == nil {
		t.Fatal("second Register with the same email: want an error")
	}

	row := lastAuthEvent(t, pool, apiClientID, authevents.KindRegister)
	if row.Result != authevents.ResultEmailTaken {
		t.Fatalf("result = %q, want %q", row.Result, authevents.ResultEmailTaken)
	}
}
