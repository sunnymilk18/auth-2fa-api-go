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
		adminauth.NewTOTPRotationStore(rdb),
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

// A revoked account, reactivated with a new password, can log in with it
// using a code from its brand-new TOTP secret — and its old password and
// old secret are both dead, exactly the point of not bringing back the
// credentials it had before (see ReactivateAccount's own doc comment for
// why: if they leaked, that could be *why* it got revoked in the first
// place).
func TestService_ReactivateAccount_IssuesFreshCredentials(t *testing.T) {
	svc, pool := newTestService(t)
	ctx := t.Context()

	account, oldSecret := createTestAccount(t, svc, pool, "old-password-1")
	// A second active superadmin so revoking the first doesn't trip the
	// separate "can't revoke the last superadmin" guardrail.
	createTestAccount(t, svc, pool, "correct-horse-battery")

	if err := svc.RevokeAccount(ctx, "", account.ID); err != nil {
		t.Fatalf("RevokeAccount: %v", err)
	}

	reactivated, otpauthURL, err := svc.ReactivateAccount(ctx, account.ID, "new-password-1")
	if err != nil {
		t.Fatalf("ReactivateAccount: %v", err)
	}
	if reactivated.ID != account.ID || !reactivated.Active {
		t.Fatalf("ReactivateAccount returned %+v, want id=%q active=true", reactivated, account.ID)
	}
	newSecret := otpauthSecret(t, otpauthURL)
	if newSecret == oldSecret {
		t.Fatal("ReactivateAccount returned the same TOTP secret the account had before — want a freshly generated one")
	}

	// The new credentials work.
	token, _, err := svc.Login(ctx, account.Email, "new-password-1", currentCode(t, newSecret))
	if err != nil {
		t.Fatalf("Login with new credentials after reactivation: %v", err)
	}
	if _, _, ok, err := svc.ValidateSession(ctx, token); err != nil || !ok {
		t.Fatalf("ValidateSession after reactivation login = (ok=%v, err=%v), want (true, nil)", ok, err)
	}

	// Neither the old password nor the old TOTP secret works anymore.
	if _, _, err := svc.Login(ctx, account.Email, "old-password-1", currentCode(t, oldSecret)); !errors.Is(err, adminauth.ErrInvalidCredentials) {
		t.Fatalf("Login with old password+secret after reactivation: err = %v, want ErrInvalidCredentials", err)
	}
	if _, _, err := svc.Login(ctx, account.Email, "new-password-1", currentCode(t, oldSecret)); !errors.Is(err, adminauth.ErrInvalidCredentials) {
		t.Fatalf("Login with new password but old TOTP secret after reactivation: err = %v, want ErrInvalidCredentials", err)
	}
}

// Reactivating an account that was never revoked (or already reactivated)
// is refused outright — this endpoint's only meaning is "bring a revoked
// account back", not a side door to reset an active admin's password.
func TestService_ReactivateAccount_AlreadyActive(t *testing.T) {
	svc, pool := newTestService(t)
	ctx := t.Context()

	account, secret := createTestAccount(t, svc, pool, "correct-horse-battery")

	if _, _, err := svc.ReactivateAccount(ctx, account.ID, "another-password"); !errors.Is(err, adminauth.ErrAccountAlreadyActive) {
		t.Fatalf("ReactivateAccount(already active): err = %v, want ErrAccountAlreadyActive", err)
	}

	// Nothing changed — the original password and secret still work.
	if _, _, err := svc.Login(ctx, account.Email, "correct-horse-battery", currentCode(t, secret)); err != nil {
		t.Fatalf("Login with original credentials after a refused reactivation: %v", err)
	}
}

func TestService_ReactivateAccount_UnknownAccount(t *testing.T) {
	svc, _ := newTestService(t)

	if _, _, err := svc.ReactivateAccount(t.Context(), "00000000-0000-0000-0000-000000000000", "whatever-password"); !errors.Is(err, adminauth.ErrNotFound) {
		t.Fatalf("ReactivateAccount(unknown id): err = %v, want ErrNotFound", err)
	}
}

// Two superadmins reactivating the same revoked account at nearly the same
// moment both pass Service.ReactivateAccount's own "is it active" check
// (neither has written yet), so the real guard against one silently
// overwriting the other's brand-new credentials has to live in the UPDATE
// itself (AccountRepository.Reprovision's "AND active = FALSE") — this
// exercises that directly, since reproducing the race through two actual
// goroutines racing Service.ReactivateAccount would be non-deterministic.
func TestAccountRepository_Reprovision_RejectsSecondConcurrentCall(t *testing.T) {
	svc, pool := newTestService(t)
	ctx := t.Context()

	account, _ := createTestAccount(t, svc, pool, "correct-horse-battery")
	if err := svc.RevokeAccount(ctx, "", account.ID); err != nil {
		t.Fatalf("RevokeAccount: %v", err)
	}

	repo := adminauth.NewAccountRepository(pool)

	// First caller's write — as if it read the account as revoked and is
	// now reprovisioning it.
	if err := repo.Reprovision(ctx, account.ID, "hash-from-first-caller", "secret-from-first-caller"); err != nil {
		t.Fatalf("first Reprovision: %v", err)
	}

	// Second caller, which also read the account as revoked before the
	// first caller's write landed — must be refused, not allowed to
	// overwrite the first caller's credentials.
	if err := repo.Reprovision(ctx, account.ID, "hash-from-second-caller", "secret-from-second-caller"); !errors.Is(err, adminauth.ErrAccountAlreadyActive) {
		t.Fatalf("second concurrent Reprovision: err = %v, want ErrAccountAlreadyActive", err)
	}

	reloaded, err := repo.FindByID(ctx, account.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if reloaded.PasswordHash != "hash-from-first-caller" || reloaded.TOTPSecretEnc != "secret-from-first-caller" {
		t.Fatalf("account credentials after the race = (%q, %q), want the first caller's values — the second call overwrote them",
			reloaded.PasswordHash, reloaded.TOTPSecretEnc)
	}
}

func TestService_ChangeOwnPassword_Success(t *testing.T) {
	svc, pool := newTestService(t)
	ctx := t.Context()

	account, secret := createTestAccount(t, svc, pool, "old-password-1")
	code := currentCode(t, secret)

	// Two sessions — one is the "current" request, the other must be
	// revoked once the password changes.
	currentToken, _, err := svc.Login(ctx, account.Email, "old-password-1", code)
	if err != nil {
		t.Fatalf("Login (current session): %v", err)
	}
	otherToken, _, err := svc.Login(ctx, account.Email, "old-password-1", currentCode(t, secret))
	if err != nil {
		t.Fatalf("Login (other session): %v", err)
	}

	if err := svc.ChangeOwnPassword(ctx, account.Email, currentToken, "old-password-1", "new-password-1"); err != nil {
		t.Fatalf("ChangeOwnPassword: %v", err)
	}

	if _, _, ok, err := svc.ValidateSession(ctx, currentToken); err != nil || !ok {
		t.Fatalf("ValidateSession(current) after password change = (ok=%v, err=%v), want (true, nil) — the calling session must survive", ok, err)
	}
	if _, _, ok, err := svc.ValidateSession(ctx, otherToken); err != nil || ok {
		t.Fatalf("ValidateSession(other) after password change = (ok=%v, err=%v), want (false, nil) — every other session must be revoked", ok, err)
	}

	if _, _, err := svc.Login(ctx, account.Email, "old-password-1", currentCode(t, secret)); !errors.Is(err, adminauth.ErrInvalidCredentials) {
		t.Fatalf("Login with the old password after change: err = %v, want ErrInvalidCredentials", err)
	}
	if _, _, err := svc.Login(ctx, account.Email, "new-password-1", currentCode(t, secret)); err != nil {
		t.Fatalf("Login with the new password after change: %v", err)
	}
}

func TestService_ChangeOwnPassword_WrongCurrentPassword(t *testing.T) {
	svc, pool := newTestService(t)
	ctx := t.Context()

	account, secret := createTestAccount(t, svc, pool, "correct-horse-battery")

	err := svc.ChangeOwnPassword(ctx, account.Email, "whatever-token", "wrong-password", "new-password-1")
	if !errors.Is(err, adminauth.ErrCurrentPasswordIncorrect) {
		t.Fatalf("ChangeOwnPassword(wrong current password): err = %v, want ErrCurrentPasswordIncorrect", err)
	}

	// Nothing changed — the original password still works.
	if _, _, err := svc.Login(ctx, account.Email, "correct-horse-battery", currentCode(t, secret)); err != nil {
		t.Fatalf("Login with the original password after a refused change: %v", err)
	}
}

// A stolen session shouldn't be able to exhaust the LOGIN counter by
// spamming wrong current-password guesses here — see
// selfServiceLimiterNamespace's doc comment. This proves the two counters
// are actually separate, not just separately named.
func TestService_ChangeOwnPassword_TooManyFailures_DoesNotLockLogin(t *testing.T) {
	svc, pool := newTestService(t)
	ctx := t.Context()

	account, secret := createTestAccount(t, svc, pool, "correct-horse-battery")

	var lastErr error
	for i := 0; i < 5; i++ {
		lastErr = svc.ChangeOwnPassword(ctx, account.Email, "whatever-token", "wrong-password", "new-password-1")
	}
	var locked *auth.LockedOutError
	if !errors.As(lastErr, &locked) {
		t.Fatalf("ChangeOwnPassword after repeated failures: err = %v, want *auth.LockedOutError", lastErr)
	}

	// Login itself, a separate counter, must still work.
	if _, _, err := svc.Login(ctx, account.Email, "correct-horse-battery", currentCode(t, secret)); err != nil {
		t.Fatalf("Login after the self-service counter locked: %v, want it to still work (separate counter)", err)
	}
}

func TestService_StartAndConfirmTOTPRotation_Success(t *testing.T) {
	svc, pool := newTestService(t)
	ctx := t.Context()

	account, oldSecret := createTestAccount(t, svc, pool, "correct-horse-battery")
	currentToken, _, err := svc.Login(ctx, account.Email, "correct-horse-battery", currentCode(t, oldSecret))
	if err != nil {
		t.Fatalf("Login (current session): %v", err)
	}
	otherToken, _, err := svc.Login(ctx, account.Email, "correct-horse-battery", currentCode(t, oldSecret))
	if err != nil {
		t.Fatalf("Login (other session): %v", err)
	}

	otpauthURL, err := svc.StartTOTPRotation(ctx, account.Email, "correct-horse-battery")
	if err != nil {
		t.Fatalf("StartTOTPRotation: %v", err)
	}
	newSecret := otpauthSecret(t, otpauthURL)
	if newSecret == oldSecret {
		t.Fatal("StartTOTPRotation returned the same secret the account already had — want a freshly generated one")
	}

	// The old secret still logs in — nothing is active yet.
	if _, _, err := svc.Login(ctx, account.Email, "correct-horse-battery", currentCode(t, oldSecret)); err != nil {
		t.Fatalf("Login with the old (still active) secret before confirming: %v", err)
	}

	if err := svc.ConfirmTOTPRotation(ctx, account.Email, currentToken, currentCode(t, newSecret)); err != nil {
		t.Fatalf("ConfirmTOTPRotation: %v", err)
	}

	if _, _, ok, err := svc.ValidateSession(ctx, currentToken); err != nil || !ok {
		t.Fatalf("ValidateSession(current) after confirming rotation = (ok=%v, err=%v), want (true, nil)", ok, err)
	}
	if _, _, ok, err := svc.ValidateSession(ctx, otherToken); err != nil || ok {
		t.Fatalf("ValidateSession(other) after confirming rotation = (ok=%v, err=%v), want (false, nil) — every other session must be revoked", ok, err)
	}

	if _, _, err := svc.Login(ctx, account.Email, "correct-horse-battery", currentCode(t, oldSecret)); !errors.Is(err, adminauth.ErrInvalidCredentials) {
		t.Fatalf("Login with the old secret after confirming rotation: err = %v, want ErrInvalidCredentials", err)
	}
	if _, _, err := svc.Login(ctx, account.Email, "correct-horse-battery", currentCode(t, newSecret)); err != nil {
		t.Fatalf("Login with the new secret after confirming rotation: %v", err)
	}
}

func TestService_StartTOTPRotation_WrongPassword(t *testing.T) {
	svc, pool := newTestService(t)
	ctx := t.Context()

	account, _ := createTestAccount(t, svc, pool, "correct-horse-battery")

	if _, err := svc.StartTOTPRotation(ctx, account.Email, "wrong-password"); !errors.Is(err, adminauth.ErrCurrentPasswordIncorrect) {
		t.Fatalf("StartTOTPRotation(wrong password): err = %v, want ErrCurrentPasswordIncorrect", err)
	}
}

// A wrong confirmation code must not throw away the pending rotation —
// otherwise a simple typo would force restarting the whole enrollment
// (scan the QR again, etc.) instead of just retrying the code.
func TestService_ConfirmTOTPRotation_WrongCodeKeepsPendingForRetry(t *testing.T) {
	svc, pool := newTestService(t)
	ctx := t.Context()

	account, _ := createTestAccount(t, svc, pool, "correct-horse-battery")
	otpauthURL, err := svc.StartTOTPRotation(ctx, account.Email, "correct-horse-battery")
	if err != nil {
		t.Fatalf("StartTOTPRotation: %v", err)
	}
	newSecret := otpauthSecret(t, otpauthURL)

	if err := svc.ConfirmTOTPRotation(ctx, account.Email, "whatever-token", "000000"); !errors.Is(err, adminauth.ErrTOTPCodeIncorrect) {
		t.Fatalf("ConfirmTOTPRotation(wrong code): err = %v, want ErrTOTPCodeIncorrect", err)
	}

	// Retrying with the right code still works — the pending rotation
	// survived the earlier wrong attempt.
	if err := svc.ConfirmTOTPRotation(ctx, account.Email, "whatever-token", currentCode(t, newSecret)); err != nil {
		t.Fatalf("ConfirmTOTPRotation(correct code, after a prior wrong one): %v", err)
	}
}

func TestService_ConfirmTOTPRotation_NothingPending(t *testing.T) {
	svc, pool := newTestService(t)
	ctx := t.Context()

	account, secret := createTestAccount(t, svc, pool, "correct-horse-battery")

	if err := svc.ConfirmTOTPRotation(ctx, account.Email, "whatever-token", currentCode(t, secret)); !errors.Is(err, adminauth.ErrNoPendingTOTPRotation) {
		t.Fatalf("ConfirmTOTPRotation(nothing pending): err = %v, want ErrNoPendingTOTPRotation", err)
	}
}

// Starting a second rotation before confirming the first replaces it —
// only one pending rotation per account, matching what someone restarting
// the flow from scratch expects.
func TestService_StartTOTPRotation_RestartReplacesPending(t *testing.T) {
	svc, pool := newTestService(t)
	ctx := t.Context()

	account, _ := createTestAccount(t, svc, pool, "correct-horse-battery")

	firstURL, err := svc.StartTOTPRotation(ctx, account.Email, "correct-horse-battery")
	if err != nil {
		t.Fatalf("StartTOTPRotation (first): %v", err)
	}
	firstSecret := otpauthSecret(t, firstURL)

	secondURL, err := svc.StartTOTPRotation(ctx, account.Email, "correct-horse-battery")
	if err != nil {
		t.Fatalf("StartTOTPRotation (second): %v", err)
	}
	secondSecret := otpauthSecret(t, secondURL)

	// The first secret's code no longer confirms anything — only the
	// second (latest) pending rotation is live.
	if err := svc.ConfirmTOTPRotation(ctx, account.Email, "whatever-token", currentCode(t, firstSecret)); !errors.Is(err, adminauth.ErrTOTPCodeIncorrect) {
		t.Fatalf("ConfirmTOTPRotation with the FIRST (superseded) secret's code: err = %v, want ErrTOTPCodeIncorrect", err)
	}
	if err := svc.ConfirmTOTPRotation(ctx, account.Email, "whatever-token", currentCode(t, secondSecret)); err != nil {
		t.Fatalf("ConfirmTOTPRotation with the SECOND (current) secret's code: %v", err)
	}
}
