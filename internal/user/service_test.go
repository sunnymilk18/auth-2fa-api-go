package user_test

import (
	"testing"

	"auth-2fa-api/internal/testutil"
	"auth-2fa-api/internal/user"
)

func newTestUserService(t *testing.T) (*user.Service, string) {
	t.Helper()
	pool := testutil.PostgresPool(t)
	client, _ := testutil.NewAPIClient(t, pool)
	return user.NewService(user.NewRepository(pool)), client.ID
}

// Only a genuinely VERIFIED account blocks a duplicate registration — see
// TestRegister_ReclaimsUnverifiedDuplicate for the unverified case.
func TestRegister_DuplicateEmailWithinSameTenant(t *testing.T) {
	svc, apiClientID := newTestUserService(t)
	email := "dup-" + testutil.UniqueSuffix(t) + "@example.com"

	first, err := svc.Register(t.Context(), apiClientID, email, "correcthorsebattery")
	if err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if err := svc.MarkEmailVerified(t.Context(), first.ID); err != nil {
		t.Fatalf("MarkEmailVerified: %v", err)
	}

	if _, err := svc.Register(t.Context(), apiClientID, email, "anotherpassword"); err != user.ErrEmailTaken {
		t.Fatalf("second Register with same (verified) email: err = %v, want %v", err, user.ErrEmailTaken)
	}
}

// A registration that was never verified never proved its owner actually
// controls that email — so a fresh registration attempt reclaims the row
// (new password, fresh unverified state) instead of being blocked.
// Otherwise a single typo'd registration would permanently squat on that
// address, locking out its real owner forever.
func TestRegister_ReclaimsUnverifiedDuplicate(t *testing.T) {
	svc, apiClientID := newTestUserService(t)
	email := "reclaim-" + testutil.UniqueSuffix(t) + "@example.com"

	first, err := svc.Register(t.Context(), apiClientID, email, "old-password-123")
	if err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if first.EmailVerified {
		t.Fatal("first Register: want EmailVerified = false")
	}

	second, err := svc.Register(t.Context(), apiClientID, email, "new-password-456")
	if err != nil {
		t.Fatalf("second Register (reclaiming the unverified row): unexpected error %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("second Register: got a different user id (%s), want the same row reclaimed (%s)", second.ID, first.ID)
	}
	if second.EmailVerified {
		t.Fatal("second Register: want EmailVerified = false")
	}

	// The old password no longer works; the new one does.
	if _, err := svc.VerifyPassword(t.Context(), apiClientID, email, "old-password-123"); err != user.ErrInvalidCredentials {
		t.Fatalf("VerifyPassword with the reclaimed-over password: err = %v, want %v", err, user.ErrInvalidCredentials)
	}
	if _, err := svc.VerifyPassword(t.Context(), apiClientID, email, "new-password-456"); err != nil {
		t.Fatalf("VerifyPassword with the new password: unexpected error %v", err)
	}
}

func TestRegister_EmailIsNormalized(t *testing.T) {
	svc, apiClientID := newTestUserService(t)
	raw := "  User-" + testutil.UniqueSuffix(t) + "@Example.COM  "

	created, err := svc.Register(t.Context(), apiClientID, raw, "correcthorsebattery")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Trimmed and lowercased, so logging in with a differently-cased,
	// differently-spaced version of the same email must work.
	messy := " " + upper(created.Email) + " "
	if _, err := svc.VerifyPassword(t.Context(), apiClientID, messy, "correcthorsebattery"); err != nil {
		t.Fatalf("VerifyPassword with messy-cased email: %v", err)
	}
}

func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - ('a' - 'A')
		}
	}
	return string(b)
}

func TestVerifyPassword_WrongPassword(t *testing.T) {
	svc, apiClientID := newTestUserService(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	if _, err := svc.Register(t.Context(), apiClientID, email, "correcthorsebattery"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if _, err := svc.VerifyPassword(t.Context(), apiClientID, email, "wrong"); err != user.ErrInvalidCredentials {
		t.Fatalf("err = %v, want %v", err, user.ErrInvalidCredentials)
	}
}

func TestVerifyPassword_UnknownEmail(t *testing.T) {
	svc, apiClientID := newTestUserService(t)
	if _, err := svc.VerifyPassword(t.Context(), apiClientID, "nobody@example.com", "whatever"); err != user.ErrInvalidCredentials {
		t.Fatalf("unknown email: err = %v, want %v (must not leak whether the account exists)", err, user.ErrInvalidCredentials)
	}
}

func TestFindByID_NotFound(t *testing.T) {
	svc, _ := newTestUserService(t)
	if _, err := svc.FindByID(t.Context(), "00000000-0000-0000-0000-000000000000"); err != user.ErrNotFound {
		t.Fatalf("err = %v, want %v", err, user.ErrNotFound)
	}
}
