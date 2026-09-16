package user_test

import (
	"errors"
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

	first, err := svc.Register(t.Context(), apiClientID, email, "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t))
	if err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if err := svc.MarkEmailVerified(t.Context(), first.ID); err != nil {
		t.Fatalf("MarkEmailVerified: %v", err)
	}

	if _, err := svc.Register(t.Context(), apiClientID, email, "anotherpassword", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t)); err != user.ErrEmailTaken {
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

	first, err := svc.Register(t.Context(), apiClientID, email, "old-password-123", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t))
	if err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if first.EmailVerified {
		t.Fatal("first Register: want EmailVerified = false")
	}

	second, err := svc.Register(t.Context(), apiClientID, email, "new-password-456", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t))
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

	created, err := svc.Register(t.Context(), apiClientID, raw, "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t))
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
	if _, err := svc.Register(t.Context(), apiClientID, email, "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t)); err != nil {
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

// VerifyPassword must accept email, username or rut interchangeably — all
// three identify the same account.
func TestVerifyPassword_AcceptsEmailUsernameOrRUT(t *testing.T) {
	svc, apiClientID := newTestUserService(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	username := "user-" + testutil.UniqueSuffix(t)
	rut := testutil.UniqueRUT(t)
	if _, err := svc.Register(t.Context(), apiClientID, email, "correcthorsebattery", username, rut); err != nil {
		t.Fatalf("Register: %v", err)
	}

	dashedRUT := rut[:len(rut)-1] + "-" + rut[len(rut)-1:]
	for _, identifier := range []string{email, username, rut, dashedRUT} { // last one: same rut, dashed
		if _, err := svc.VerifyPassword(t.Context(), apiClientID, identifier, "correcthorsebattery"); err != nil {
			t.Errorf("VerifyPassword(%q): unexpected error %v", identifier, err)
		}
	}
}

func TestRegister_DuplicateUsername_SuggestsAlternative(t *testing.T) {
	svc, apiClientID := newTestUserService(t)
	username := "juan-" + testutil.UniqueSuffix(t)

	if _, err := svc.Register(t.Context(), apiClientID, "a-"+testutil.UniqueSuffix(t)+"@example.com", "correcthorsebattery", username, testutil.UniqueRUT(t)); err != nil {
		t.Fatalf("first Register: %v", err)
	}

	_, err := svc.Register(t.Context(), apiClientID, "b-"+testutil.UniqueSuffix(t)+"@example.com", "correcthorsebattery", username, testutil.UniqueRUT(t))
	var taken *user.UsernameTakenError
	if !errors.As(err, &taken) {
		t.Fatalf("second Register with the same username: err = %v, want a *user.UsernameTakenError", err)
	}
	if !errors.Is(err, user.ErrUsernameTaken) {
		t.Fatalf("errors.Is(err, ErrUsernameTaken) = false, want true (err = %v)", err)
	}
	want := username + "2"
	if taken.Suggested != want {
		t.Fatalf("suggested username = %q, want %q", taken.Suggested, want)
	}
}

// The shape rules are enforced by Register itself, not just by whatever
// HTTP handler happens to call it — calling the service directly, with no
// handler in the way, must still reject these.
func TestRegister_InvalidUsername(t *testing.T) {
	svc, apiClientID := newTestUserService(t)

	cases := []string{"short", "12345678", "123456785", "1234.5678", "12.345.678-5"} // too short, purely numeric, and digits+separators that still look like a rut
	for _, username := range cases {
		if _, err := svc.Register(t.Context(), apiClientID, "a-"+testutil.UniqueSuffix(t)+"@example.com", "correcthorsebattery", username, testutil.UniqueRUT(t)); !errors.Is(err, user.ErrInvalidUsername) {
			t.Errorf("Register(username=%q): err = %v, want %v", username, err, user.ErrInvalidUsername)
		}
	}
}

func TestRegister_InvalidRUT(t *testing.T) {
	svc, apiClientID := newTestUserService(t)

	if _, err := svc.Register(t.Context(), apiClientID, "a-"+testutil.UniqueSuffix(t)+"@example.com", "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), "11111111-2" /* wrong check digit, should be 1 */); !errors.Is(err, user.ErrInvalidRUT) {
		t.Fatalf("err = %v, want %v", err, user.ErrInvalidRUT)
	}
}

func TestRegister_InvalidEmail(t *testing.T) {
	svc, apiClientID := newTestUserService(t)

	cases := []string{"no-at-sign.example.com", "@example.com", "user@", "user@nodot", "has space@example.com"}
	for _, email := range cases {
		if _, err := svc.Register(t.Context(), apiClientID, email, "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t)); !errors.Is(err, user.ErrInvalidEmail) {
			t.Errorf("Register(email=%q): err = %v, want %v", email, err, user.ErrInvalidEmail)
		}
	}
}

// A suggested alternative must itself be something the caller could
// actually register with — never longer than the max username length.
func TestRegister_DuplicateUsername_SuggestionStaysWithinLengthLimit(t *testing.T) {
	svc, apiClientID := newTestUserService(t)
	// 32 chars exactly (the max) so any numeric suffix would overflow it
	// unless suggestUsername truncates the base to make room.
	username := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if len(username) != 32 {
		t.Fatalf("test setup: username length = %d, want 32", len(username))
	}

	if _, err := svc.Register(t.Context(), apiClientID, "a-"+testutil.UniqueSuffix(t)+"@example.com", "correcthorsebattery", username, testutil.UniqueRUT(t)); err != nil {
		t.Fatalf("first Register: %v", err)
	}

	_, err := svc.Register(t.Context(), apiClientID, "b-"+testutil.UniqueSuffix(t)+"@example.com", "correcthorsebattery", username, testutil.UniqueRUT(t))
	var taken *user.UsernameTakenError
	if !errors.As(err, &taken) {
		t.Fatalf("second Register with the same username: err = %v, want a *user.UsernameTakenError", err)
	}
	if len(taken.Suggested) > 32 {
		t.Fatalf("suggested username %q is %d chars, want <= 32", taken.Suggested, len(taken.Suggested))
	}
	if !user.ValidateUsername(taken.Suggested) {
		t.Fatalf("suggested username %q would itself fail ValidateUsername", taken.Suggested)
	}
}

func TestRegister_DuplicateRUT(t *testing.T) {
	svc, apiClientID := newTestUserService(t)
	rut := testutil.UniqueRUT(t)

	if _, err := svc.Register(t.Context(), apiClientID, "a-"+testutil.UniqueSuffix(t)+"@example.com", "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), rut); err != nil {
		t.Fatalf("first Register: %v", err)
	}

	if _, err := svc.Register(t.Context(), apiClientID, "b-"+testutil.UniqueSuffix(t)+"@example.com", "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), rut); !errors.Is(err, user.ErrRUTTaken) {
		t.Fatalf("second Register with the same rut: err = %v, want %v", err, user.ErrRUTTaken)
	}
}
