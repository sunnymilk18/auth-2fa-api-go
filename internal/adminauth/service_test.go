package adminauth_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"auth-2fa-api/internal/adminauth"
	"auth-2fa-api/internal/auth"
	"auth-2fa-api/internal/testutil"
)

var testTOTPKey = []byte("0123456789abcdef0123456789abcdef")

func newTestService(t *testing.T) (*adminauth.Service, *pgxpool.Pool) {
	t.Helper()
	pool := testutil.PostgresPool(t)
	rdb := testutil.RedisClient(t)

	totpManager, err := auth.NewTOTPManager("test-issuer", testTOTPKey)
	if err != nil {
		t.Fatalf("NewTOTPManager: %v", err)
	}
	limiter := auth.NewLoginAttemptLimiter(rdb, 3, time.Hour)

	svc := adminauth.NewService(
		adminauth.NewAccountRepository(pool),
		adminauth.NewSessionRepository(pool),
		totpManager,
		limiter,
		time.Hour,
	)
	return svc, pool
}

// createTestAccount creates an admin account under a unique, collision-free
// email (tests run against a real, persistent Postgres — see
// testutil.PostgresPool's doc comment — so a fixed literal email would
// collide with a leftover row from a previous run) and cleans it up
// afterward; admin_sessions rows cascade-delete with it.
func createTestAccount(t *testing.T, svc *adminauth.Service, pool *pgxpool.Pool, password string) (*adminauth.AdminAccount, string) {
	return createTestAccountWithRole(t, svc, pool, password, adminauth.RoleSuperAdmin)
}

func createTestAccountWithRole(t *testing.T, svc *adminauth.Service, pool *pgxpool.Pool, password string, role adminauth.Role) (*adminauth.AdminAccount, string) {
	t.Helper()
	email := "admin-" + testutil.UniqueSuffix(t) + "@example.com"

	account, otpauthURL, err := svc.CreateAccount(t.Context(), email, password, role)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM admin_accounts WHERE id = $1`, account.ID)
	})
	return account, otpauthSecret(t, otpauthURL)
}

// currentCode re-derives a valid TOTP code for secret the same way an
// authenticator app would — tests have no other way to produce one, since
// Service.CreateAccount only ever returns the secret encrypted.
func currentCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generating totp code: %v", err)
	}
	return code
}

// otpauthSecret extracts the raw base32 secret from the otpauth:// URL
// CreateAccount returns — the only place that secret is ever visible
// outside the encrypted column, mirroring exactly what a real admin's
// authenticator app would scan.
func otpauthSecret(t *testing.T, otpauthURL string) string {
	t.Helper()
	key, err := otp.NewKeyFromURL(otpauthURL)
	if err != nil {
		t.Fatalf("parsing otpauth url: %v", err)
	}
	return key.Secret()
}

func TestService_Login_WrongPasswordOrTOTP_ReturnsInvalidCredentials(t *testing.T) {
	svc, pool := newTestService(t)
	ctx := t.Context()

	account, secret := createTestAccount(t, svc, pool, "correct-horse-battery")

	if _, _, err := svc.Login(ctx, account.Email, "wrong-password", currentCode(t, secret)); !errors.Is(err, adminauth.ErrInvalidCredentials) {
		t.Fatalf("Login with wrong password: err = %v, want ErrInvalidCredentials", err)
	}
	if _, _, err := svc.Login(ctx, account.Email, "correct-horse-battery", "000000"); !errors.Is(err, adminauth.ErrInvalidCredentials) {
		t.Fatalf("Login with wrong TOTP: err = %v, want ErrInvalidCredentials", err)
	}
	if _, _, err := svc.Login(ctx, "nobody@example.com", "whatever12", "000000"); !errors.Is(err, adminauth.ErrInvalidCredentials) {
		t.Fatalf("Login with unknown email: err = %v, want ErrInvalidCredentials", err)
	}
}

func TestService_Login_Success_IssuesValidatableSession(t *testing.T) {
	svc, pool := newTestService(t)
	ctx := t.Context()

	account, secret := createTestAccount(t, svc, pool, "correct-horse-battery")

	token, expiresAt, err := svc.Login(ctx, account.Email, "correct-horse-battery", currentCode(t, secret))
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if token == "" || !expiresAt.After(time.Now()) {
		t.Fatalf("Login returned token=%q expiresAt=%v, want a non-empty future-expiring session", token, expiresAt)
	}

	email, role, ok, err := svc.ValidateSession(ctx, token)
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if !ok || email != account.Email {
		t.Fatalf("ValidateSession(valid token) = (%q, %v), want (%q, true)", email, ok, account.Email)
	}
	if role != string(adminauth.RoleSuperAdmin) {
		t.Fatalf("ValidateSession role = %q, want %q", role, adminauth.RoleSuperAdmin)
	}

	if _, _, ok, err := svc.ValidateSession(ctx, "not-a-real-token"); err != nil || ok {
		t.Fatalf("ValidateSession(garbage token) = (ok=%v, err=%v), want (false, nil)", ok, err)
	}
}

func TestService_Login_LocksOutAfterRepeatedFailures(t *testing.T) {
	svc, pool := newTestService(t)
	ctx := t.Context()

	account, _ := createTestAccount(t, svc, pool, "correct-horse-battery")

	for i := 0; i < 3; i++ {
		if _, _, err := svc.Login(ctx, account.Email, "wrong", "000000"); !errors.Is(err, adminauth.ErrInvalidCredentials) {
			t.Fatalf("Login failure #%d: err = %v, want ErrInvalidCredentials", i, err)
		}
	}

	_, _, err := svc.Login(ctx, account.Email, "wrong", "000000")
	var locked *auth.LockedOutError
	if !errors.As(err, &locked) {
		t.Fatalf("Login after 3 failures: err = %v, want *auth.LockedOutError", err)
	}
}

func TestService_RevokeAccount_InvalidatesExistingSessionImmediately(t *testing.T) {
	svc, pool := newTestService(t)
	ctx := t.Context()

	account, secret := createTestAccount(t, svc, pool, "correct-horse-battery")
	// A second active admin, purely so revoking the first doesn't also
	// trip the separate "can't revoke the last active admin" guardrail —
	// that one has its own dedicated test below.
	createTestAccount(t, svc, pool, "correct-horse-battery")

	token, _, err := svc.Login(ctx, account.Email, "correct-horse-battery", currentCode(t, secret))
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, _, ok, _ := svc.ValidateSession(ctx, token); !ok {
		t.Fatal("expected session to be valid right after login")
	}

	// actorEmail "" simulates the X-Admin-Token/script path — no "self" to
	// protect, see RevokeAccount's own doc comment.
	if err := svc.RevokeAccount(ctx, "", account.ID); err != nil {
		t.Fatalf("RevokeAccount: %v", err)
	}

	if _, _, ok, err := svc.ValidateSession(ctx, token); err != nil || ok {
		t.Fatalf("ValidateSession after RevokeAccount = (ok=%v, err=%v), want (false, nil)", ok, err)
	}
	// A revoked account can't log in again either, even with the right
	// password and a fresh TOTP code.
	if _, _, err := svc.Login(ctx, account.Email, "correct-horse-battery", currentCode(t, secret)); !errors.Is(err, adminauth.ErrInvalidCredentials) {
		t.Fatalf("Login after RevokeAccount: err = %v, want ErrInvalidCredentials", err)
	}
}

// An admin can never revoke their own account — even if other active
// admins exist — since that's exactly the kind of mistake that could
// strand the panel mid-session with no way back in for that person.
func TestService_RevokeAccount_CannotRevokeSelf(t *testing.T) {
	svc, pool := newTestService(t)
	ctx := t.Context()

	account, _ := createTestAccount(t, svc, pool, "correct-horse-battery")
	// A second active admin — proves the self-check fires on its own, not
	// as a side effect of the separate last-admin guardrail.
	createTestAccount(t, svc, pool, "correct-horse-battery")

	if err := svc.RevokeAccount(ctx, account.Email, account.ID); !errors.Is(err, adminauth.ErrCannotRevokeSelf) {
		t.Fatalf("RevokeAccount(self): err = %v, want ErrCannotRevokeSelf", err)
	}
}

// The only currently-active superadmin account can never be revoked, by
// anyone (including the X-Admin-Token/script path, actorEmail "") — doing
// so would leave no one able to manage admin accounts at all.
func TestService_RevokeAccount_CannotRevokeLastActiveSuperAdmin(t *testing.T) {
	svc, pool := newTestService(t)
	ctx := t.Context()

	account, _ := createTestAccount(t, svc, pool, "correct-horse-battery")

	if err := svc.RevokeAccount(ctx, "", account.ID); !errors.Is(err, adminauth.ErrLastSuperAdminAccount) {
		t.Fatalf("RevokeAccount(last superadmin): err = %v, want ErrLastSuperAdminAccount", err)
	}
}

// Revoking the last active *regular* admin, by contrast, is fine as long
// as a superadmin remains — only the superadmin tier is protected from
// hitting zero.
func TestService_RevokeAccount_CanRevokeLastRegularAdminIfSuperAdminRemains(t *testing.T) {
	svc, pool := newTestService(t)
	ctx := t.Context()

	createTestAccount(t, svc, pool, "correct-horse-battery") // a superadmin
	regularAdmin, _ := createTestAccountWithRole(t, svc, pool, "correct-horse-battery", adminauth.RoleAdmin)

	if err := svc.RevokeAccount(ctx, "", regularAdmin.ID); err != nil {
		t.Fatalf("RevokeAccount(last regular admin, superadmin remains): %v", err)
	}
}

func TestService_CreateAccount_DuplicateEmail(t *testing.T) {
	svc, pool := newTestService(t)
	ctx := t.Context()

	account, _ := createTestAccount(t, svc, pool, "correct-horse-battery")
	if _, _, err := svc.CreateAccount(ctx, account.Email, "another-password", adminauth.RoleSuperAdmin); !errors.Is(err, adminauth.ErrDuplicateEmail) {
		t.Fatalf("CreateAccount duplicate: err = %v, want ErrDuplicateEmail", err)
	}
}

func TestService_CreateAccount_InvalidRole(t *testing.T) {
	svc, _ := newTestService(t)

	if _, _, err := svc.CreateAccount(t.Context(), "role-"+testutil.UniqueSuffix(t)+"@example.com", "correct-horse-battery", adminauth.Role("owner")); !errors.Is(err, adminauth.ErrInvalidRole) {
		t.Fatalf("CreateAccount with invalid role: err = %v, want ErrInvalidRole", err)
	}
}

func TestService_Logout_RevokesOnlyThatSession(t *testing.T) {
	svc, pool := newTestService(t)
	ctx := t.Context()

	account, secret := createTestAccount(t, svc, pool, "correct-horse-battery")

	tokenA, _, err := svc.Login(ctx, account.Email, "correct-horse-battery", currentCode(t, secret))
	if err != nil {
		t.Fatalf("Login (session A): %v", err)
	}
	// A fresh TOTP code a second later (TOTP windows are 30s, so the same
	// code is still valid here — using the same code twice is fine, this
	// isn't exercising replay protection).
	tokenB, _, err := svc.Login(ctx, account.Email, "correct-horse-battery", currentCode(t, secret))
	if err != nil {
		t.Fatalf("Login (session B): %v", err)
	}

	if err := svc.Logout(ctx, tokenA); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	if _, _, ok, _ := svc.ValidateSession(ctx, tokenA); ok {
		t.Fatal("session A should be invalid after its own Logout")
	}
	if _, _, ok, err := svc.ValidateSession(ctx, tokenB); err != nil || !ok {
		t.Fatalf("session B should still be valid, got ok=%v err=%v", ok, err)
	}
}

// Email is normalized (lowercased/trimmed) the same way user.NormalizeEmail
// does for end users — otherwise a login typed in a different case than
// the account was created with would fail as "invalid credentials" even
// with the right password and TOTP code, which is confusing rather than
// any real security benefit.
func TestService_Login_IsCaseInsensitiveOnEmail(t *testing.T) {
	svc, pool := newTestService(t)
	ctx := t.Context()

	lowerEmail := "admin-" + testutil.UniqueSuffix(t) + "@example.com"
	account, otpauthURL, err := svc.CreateAccount(ctx, strings.ToUpper(lowerEmail), "correct-horse-battery", adminauth.RoleSuperAdmin)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM admin_accounts WHERE id = $1`, account.ID)
	})
	secret := otpauthSecret(t, otpauthURL)

	// Created with an UPPERCASE email, logging in with the lowercase form.
	token, _, err := svc.Login(ctx, lowerEmail, "correct-horse-battery", currentCode(t, secret))
	if err != nil {
		t.Fatalf("Login with a differently-cased email: %v", err)
	}
	if _, _, ok, err := svc.ValidateSession(ctx, token); err != nil || !ok {
		t.Fatalf("ValidateSession after case-insensitive login = (ok=%v, err=%v), want (true, nil)", ok, err)
	}
}
