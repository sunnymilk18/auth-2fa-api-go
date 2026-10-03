package user_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"auth-2fa-api/internal/testutil"
	"auth-2fa-api/internal/user"
)

func newTestUserService(t *testing.T) (*user.Service, string) {
	t.Helper()
	return newTestUserServiceWithPinLimits(t, 5, 15*time.Minute)
}

func newTestUserServiceWithPinLimits(t *testing.T, pinMaxFailedTries int, pinLockDuration time.Duration) (*user.Service, string) {
	t.Helper()
	pool := testutil.PostgresPool(t)
	client, _ := testutil.NewAPIClient(t, pool)
	return user.NewService(user.NewRepository(pool), pinMaxFailedTries, pinLockDuration), client.ID
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

// Ban must block login the same way an already-inactive account does
// (VerifyPassword's own is_active check); Unban must restore it — see
// auth.Service.DeviceLogin's own test coverage for the trusted-device
// shortcut, which this same flag also gates.
func TestBan_ThenUnban(t *testing.T) {
	svc, apiClientID := newTestUserService(t)
	email := "ban-" + testutil.UniqueSuffix(t) + "@example.com"

	created, err := svc.Register(t.Context(), apiClientID, email, "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := svc.MarkEmailVerified(t.Context(), created.ID); err != nil {
		t.Fatalf("MarkEmailVerified: %v", err)
	}

	if err := svc.Ban(t.Context(), created.ID); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if _, err := svc.VerifyPassword(t.Context(), apiClientID, email, "correcthorsebattery"); err != user.ErrInvalidCredentials {
		t.Fatalf("VerifyPassword for a banned account: err = %v, want %v", err, user.ErrInvalidCredentials)
	}

	if err := svc.Unban(t.Context(), created.ID); err != nil {
		t.Fatalf("Unban: %v", err)
	}
	if _, err := svc.VerifyPassword(t.Context(), apiClientID, email, "correcthorsebattery"); err != nil {
		t.Fatalf("VerifyPassword after Unban: unexpected error %v", err)
	}
}

func TestBan_UnknownID(t *testing.T) {
	svc, _ := newTestUserService(t)
	if err := svc.Ban(t.Context(), "00000000-0000-0000-0000-000000000000"); err != user.ErrNotFound {
		t.Fatalf("err = %v, want %v", err, user.ErrNotFound)
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

func TestRegister_InvalidPassword(t *testing.T) {
	svc, apiClientID := newTestUserService(t)

	if _, err := svc.Register(t.Context(), apiClientID, "a-"+testutil.UniqueSuffix(t)+"@example.com", "short", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t)); !errors.Is(err, user.ErrInvalidPassword) {
		t.Fatalf("Register with a too-short password: err = %v, want %v", err, user.ErrInvalidPassword)
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

// ListByAPIClient must page correctly (newest first) and report the true
// total, not just the page's own length — the whole reason total is
// returned separately instead of len(users).
func TestListByAPIClient_PagesNewestFirstWithAccurateTotal(t *testing.T) {
	svc, apiClientID := newTestUserService(t)

	const n = 5
	var created []*user.User
	for i := 0; i < n; i++ {
		u, err := svc.Register(t.Context(), apiClientID, "page-"+testutil.UniqueSuffix(t)+"@example.com", "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t))
		if err != nil {
			t.Fatalf("Register #%d: %v", i, err)
		}
		created = append(created, u)
	}

	// Page size 2, first page — should be the two most recently created.
	page1, total, effPage, effPageSize, err := svc.ListByAPIClient(t.Context(), apiClientID, 1, 2, "")
	if err != nil {
		t.Fatalf("ListByAPIClient page 1: %v", err)
	}
	if total != n {
		t.Fatalf("total = %d, want %d", total, n)
	}
	if effPage != 1 || effPageSize != 2 {
		t.Fatalf("effPage/effPageSize = %d/%d, want 1/2", effPage, effPageSize)
	}
	if len(page1) != 2 {
		t.Fatalf("len(page1) = %d, want 2", len(page1))
	}
	if page1[0].ID != created[n-1].ID || page1[1].ID != created[n-2].ID {
		t.Fatal("page 1 isn't ordered newest-first")
	}

	// Page 3 of size 2 over 5 rows has exactly one leftover row.
	page3, total3, _, _, err := svc.ListByAPIClient(t.Context(), apiClientID, 3, 2, "")
	if err != nil {
		t.Fatalf("ListByAPIClient page 3: %v", err)
	}
	if total3 != n {
		t.Fatalf("page 3 total = %d, want %d", total3, n)
	}
	if len(page3) != 1 || page3[0].ID != created[0].ID {
		t.Fatalf("page 3: got %d rows, want exactly the oldest one", len(page3))
	}

	// A different tenant sees none of these.
	otherSvc, otherClientID := newTestUserService(t)
	otherPage, otherTotal, _, _, err := otherSvc.ListByAPIClient(t.Context(), otherClientID, 1, 10, "")
	if err != nil {
		t.Fatalf("ListByAPIClient other tenant: %v", err)
	}
	if otherTotal != 0 || len(otherPage) != 0 {
		t.Fatalf("other tenant: total=%d len=%d, want 0/0 (tenants must not see each other's users)", otherTotal, len(otherPage))
	}
}

// page<1 and pageSize<1/>maxPageSize are clamped to sane values rather than
// rejected — see ListByAPIClient's doc comment.
func TestListByAPIClient_ClampsOutOfRangePageParams(t *testing.T) {
	svc, apiClientID := newTestUserService(t)
	if _, err := svc.Register(t.Context(), apiClientID, "clamp-"+testutil.UniqueSuffix(t)+"@example.com", "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t)); err != nil {
		t.Fatalf("Register: %v", err)
	}

	_, _, effPage, effPageSize, err := svc.ListByAPIClient(t.Context(), apiClientID, 0, 0, "")
	if err != nil {
		t.Fatalf("ListByAPIClient page=0 pageSize=0: %v", err)
	}
	if effPage != 1 {
		t.Fatalf("page=0 was clamped to %d, want 1", effPage)
	}
	if effPageSize != 50 {
		t.Fatalf("pageSize=0 was clamped to %d, want the 50 default", effPageSize)
	}

	_, _, _, effPageSize2, err := svc.ListByAPIClient(t.Context(), apiClientID, 1, 10000, "")
	if err != nil {
		t.Fatalf("ListByAPIClient pageSize=10000: %v", err)
	}
	if effPageSize2 != 100 {
		t.Fatalf("pageSize=10000 was clamped to %d, want the 100 cap", effPageSize2)
	}
}

// q must match partially, case-insensitively, across email, username and
// rut — and a user from a different tenant must never show up even if its
// email would otherwise match.
func TestListByAPIClient_SearchMatchesEmailUsernameOrRUT(t *testing.T) {
	svc, apiClientID := newTestUserService(t)
	suffix := testutil.UniqueSuffix(t)

	byEmail, err := svc.Register(t.Context(), apiClientID, "findme-"+suffix+"@example.com", "correcthorsebattery", "unrelated-a-"+suffix, testutil.UniqueRUT(t))
	if err != nil {
		t.Fatalf("Register byEmail: %v", err)
	}
	byUsername, err := svc.Register(t.Context(), apiClientID, "unrelated-b-"+suffix+"@example.com", "correcthorsebattery", "findme-"+suffix, testutil.UniqueRUT(t))
	if err != nil {
		t.Fatalf("Register byUsername: %v", err)
	}
	if _, err := svc.Register(t.Context(), apiClientID, "nomatch-"+suffix+"@example.com", "correcthorsebattery", "nomatch-"+suffix, testutil.UniqueRUT(t)); err != nil {
		t.Fatalf("Register nomatch: %v", err)
	}

	// Uppercased on purpose: ILIKE must still match.
	results, total, _, _, err := svc.ListByAPIClient(t.Context(), apiClientID, 1, 50, "FINDME-"+suffix)
	if err != nil {
		t.Fatalf("ListByAPIClient with q: %v", err)
	}
	if total != 2 {
		t.Fatalf("total = %d, want 2 (byEmail + byUsername, not the unrelated one)", total)
	}
	gotIDs := map[string]bool{}
	for _, u := range results {
		gotIDs[u.ID] = true
	}
	if !gotIDs[byEmail.ID] || !gotIDs[byUsername.ID] {
		t.Fatalf("results missing expected matches: got %v, want %s and %s", gotIDs, byEmail.ID, byUsername.ID)
	}

	// A different tenant's matching user never leaks in.
	otherSvc, otherClientID := newTestUserService(t)
	if _, err := otherSvc.Register(t.Context(), otherClientID, "findme-"+suffix+"-other@example.com", "correcthorsebattery", "other-"+suffix, testutil.UniqueRUT(t)); err != nil {
		t.Fatalf("Register in other tenant: %v", err)
	}
	otherTenantResults, _, _, _, err := svc.ListByAPIClient(t.Context(), apiClientID, 1, 50, "findme-"+suffix)
	if err != nil {
		t.Fatalf("ListByAPIClient (checking tenant isolation with q): %v", err)
	}
	for _, u := range otherTenantResults {
		if u.APIClientID != apiClientID {
			t.Fatalf("search leaked a user from another tenant: %+v", u)
		}
	}
}

// A literal "%" or "_" in q must be matched as a literal character, not
// treated as an ILIKE wildcard — see Repository.escapeLikePattern.
func TestListByAPIClient_SearchEscapesLikeWildcards(t *testing.T) {
	svc, apiClientID := newTestUserService(t)
	suffix := testutil.UniqueSuffix(t)

	if _, err := svc.Register(t.Context(), apiClientID, "percent-"+suffix+"@example.com", "correcthorsebattery", "no_percent_here-"+suffix, testutil.UniqueRUT(t)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := svc.Register(t.Context(), apiClientID, "other-"+suffix+"@example.com", "correcthorsebattery", "other-"+suffix, testutil.UniqueRUT(t)); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// A literal "%" shouldn't match every username — only one that actually
	// contains a "%" character (none of them do).
	_, total, _, _, err := svc.ListByAPIClient(t.Context(), apiClientID, 1, 50, "%")
	if err != nil {
		t.Fatalf("ListByAPIClient q=%%: %v", err)
	}
	if total != 0 {
		t.Fatalf("q=%%: total = %d, want 0 (no username actually contains a literal %%)", total)
	}

	// A literal "_" must match only a username with that literal character —
	// not stand in for "any character" and match everything.
	_, total, _, _, err = svc.ListByAPIClient(t.Context(), apiClientID, 1, 50, "no_percent")
	if err != nil {
		t.Fatalf("ListByAPIClient q=no_percent: %v", err)
	}
	if total != 1 {
		t.Fatalf("q=no_percent: total = %d, want 1 (exact literal match only)", total)
	}
}

// An empty apiClientID means "every tenant" — the /admin/users case (the
// operator's own unscoped token). This is the one place the tenant-scoping
// rule every other ListByAPIClient test relies on is deliberately not
// applied, so it's covered as its own test rather than folded into the
// scoped ones above.
func TestListByAPIClient_EmptyAPIClientIDSpansEveryTenant(t *testing.T) {
	svcA, apiClientA := newTestUserService(t)
	// A second tenant — its own *pgxpool.Pool, but pointed at the same
	// test database as svcA's, so both tenants' rows are visible to an
	// unscoped query through either service.
	svcB, apiClientB := newTestUserService(t)

	userA, err := svcA.Register(t.Context(), apiClientA, "spanA-"+testutil.UniqueSuffix(t)+"@example.com", "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t))
	if err != nil {
		t.Fatalf("Register in tenant A: %v", err)
	}
	userB, err := svcB.Register(t.Context(), apiClientB, "spanB-"+testutil.UniqueSuffix(t)+"@example.com", "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t))
	if err != nil {
		t.Fatalf("Register in tenant B: %v", err)
	}

	results, _, _, _, err := svcA.ListByAPIClient(t.Context(), "", 1, 200, "")
	if err != nil {
		t.Fatalf("ListByAPIClient with apiClientID=\"\": %v", err)
	}
	found := map[string]bool{}
	for _, u := range results {
		found[u.ID] = true
	}
	if !found[userA.ID] || !found[userB.ID] {
		t.Fatalf("unscoped listing missing users from one or both tenants: found=%v, want %s and %s", found, userA.ID, userB.ID)
	}
}

// --- Account PIN ---

func TestVerifyPin_LockoutAfterMaxFailedAttempts(t *testing.T) {
	svc, apiClientID := newTestUserServiceWithPinLimits(t, 3, 50*time.Millisecond)
	u, err := svc.Register(t.Context(), apiClientID, "pin-"+testutil.UniqueSuffix(t)+"@example.com", "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := svc.SetPin(t.Context(), u.ID, "123456", ""); err != nil {
		t.Fatalf("SetPin: %v", err)
	}

	for i := 1; i <= 2; i++ {
		if err := svc.VerifyPin(t.Context(), u.ID, "000000"); !errors.As(err, new(*user.PinInvalidError)) {
			t.Fatalf("failed attempt %d: err = %v, want a *user.PinInvalidError", i, err)
		}
	}
	// 3rd failure crosses the threshold.
	var locked *user.PinLockedError
	if err := svc.VerifyPin(t.Context(), u.ID, "000000"); !errors.As(err, &locked) {
		t.Fatalf("3rd failed attempt: err = %v, want a *user.PinLockedError", err)
	}

	// Locked: even the correct PIN is refused, and doesn't touch the counter.
	if err := svc.VerifyPin(t.Context(), u.ID, "123456"); !errors.As(err, new(*user.PinLockedError)) {
		t.Fatalf("correct pin while locked: err = %v, want a *user.PinLockedError", err)
	}

	time.Sleep(60 * time.Millisecond) // past the 50ms lock
	if err := svc.VerifyPin(t.Context(), u.ID, "123456"); err != nil {
		t.Fatalf("correct pin after lock expired: unexpected error %v", err)
	}
}

func TestVerifyPin_SuccessResetsFailedAttempts(t *testing.T) {
	svc, apiClientID := newTestUserServiceWithPinLimits(t, 3, time.Minute)
	u, err := svc.Register(t.Context(), apiClientID, "pin-"+testutil.UniqueSuffix(t)+"@example.com", "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := svc.SetPin(t.Context(), u.ID, "123456", ""); err != nil {
		t.Fatalf("SetPin: %v", err)
	}

	// One failure, then a success — the counter must reset, so two more
	// failures afterward shouldn't trip the maxFailedTries=3 limit on their
	// own (1 + 2 = 3 total, but not consecutive since a success happened
	// in between).
	if err := svc.VerifyPin(t.Context(), u.ID, "000000"); !errors.As(err, new(*user.PinInvalidError)) {
		t.Fatalf("first failed attempt: err = %v, want a *user.PinInvalidError", err)
	}
	if err := svc.VerifyPin(t.Context(), u.ID, "123456"); err != nil {
		t.Fatalf("successful attempt: unexpected error %v", err)
	}
	for i := 1; i <= 2; i++ {
		if err := svc.VerifyPin(t.Context(), u.ID, "000000"); !errors.As(err, new(*user.PinInvalidError)) {
			t.Fatalf("failed attempt %d after success: err = %v, want a *user.PinInvalidError (not locked — counter should have reset)", i, err)
		}
	}
}

func TestVerifyPin_NotSet(t *testing.T) {
	svc, apiClientID := newTestUserService(t)
	u, err := svc.Register(t.Context(), apiClientID, "pin-"+testutil.UniqueSuffix(t)+"@example.com", "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := svc.VerifyPin(t.Context(), u.ID, "123456"); err != user.ErrPinNotSet {
		t.Fatalf("err = %v, want %v", err, user.ErrPinNotSet)
	}
}

func TestSetPin_ChangeRequiresCorrectCurrentPin(t *testing.T) {
	svc, apiClientID := newTestUserService(t)
	u, err := svc.Register(t.Context(), apiClientID, "pin-"+testutil.UniqueSuffix(t)+"@example.com", "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// First PIN ever: no current_pin needed, even a wrong-looking one is ignored.
	if err := svc.SetPin(t.Context(), u.ID, "111111", "whatever"); err != nil {
		t.Fatalf("create: unexpected error %v", err)
	}

	if err := svc.SetPin(t.Context(), u.ID, "222222", "000000"); !errors.As(err, new(*user.PinInvalidError)) {
		t.Fatalf("change with wrong current_pin: err = %v, want a *user.PinInvalidError", err)
	}
	// The old PIN must still work — the failed change attempt didn't corrupt it.
	if err := svc.VerifyPin(t.Context(), u.ID, "111111"); err != nil {
		t.Fatalf("verify old pin after a failed change: unexpected error %v", err)
	}

	if err := svc.SetPin(t.Context(), u.ID, "222222", "111111"); err != nil {
		t.Fatalf("change with correct current_pin: unexpected error %v", err)
	}
	if err := svc.VerifyPin(t.Context(), u.ID, "222222"); err != nil {
		t.Fatalf("verify new pin: unexpected error %v", err)
	}
}

func TestSetPin_RejectsMalformedPin(t *testing.T) {
	svc, apiClientID := newTestUserService(t)
	u, err := svc.Register(t.Context(), apiClientID, "pin-"+testutil.UniqueSuffix(t)+"@example.com", "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	for _, pin := range []string{"", "12345", "1234567", "abcdef", "12 345"} {
		if err := svc.SetPin(t.Context(), u.ID, pin, ""); err != user.ErrInvalidPinFormat {
			t.Errorf("SetPin with pin %q: err = %v, want %v", pin, err, user.ErrInvalidPinFormat)
		}
	}
}

func TestEnsurePin_FirstDeviceSetsItSecondDeviceMustMatch(t *testing.T) {
	svc, apiClientID := newTestUserService(t)
	u, err := svc.Register(t.Context(), apiClientID, "pin-"+testutil.UniqueSuffix(t)+"@example.com", "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if err := svc.EnsurePin(t.Context(), u.ID, "123456"); err != nil {
		t.Fatalf("EnsurePin (no pin yet): unexpected error %v", err)
	}
	hasPin, err := svc.HasPin(t.Context(), u.ID)
	if err != nil || !hasPin {
		t.Fatalf("HasPin after EnsurePin: hasPin=%v err=%v, want true", hasPin, err)
	}

	// A second "device" with a different pin must fail — it has to match
	// the account's existing one now.
	if err := svc.EnsurePin(t.Context(), u.ID, "654321"); !errors.As(err, new(*user.PinInvalidError)) {
		t.Fatalf("EnsurePin with a different pin (account already has one): err = %v, want a *user.PinInvalidError", err)
	}
	// The matching pin succeeds, and changes nothing.
	if err := svc.EnsurePin(t.Context(), u.ID, "123456"); err != nil {
		t.Fatalf("EnsurePin with the matching pin: unexpected error %v", err)
	}
}

// A burst of concurrent wrong guesses must not get more total tries than
// pinMaxFailedTries — the race ReserveFailedPinAttempt closes: each
// concurrent call used to read "not locked" and compare its own guess with
// bcrypt before any of them had actually counted against the lockout, so
// the real per-burst budget was however many requests arrived at once, not
// pinMaxFailedTries.
func TestVerifyPin_ConcurrentGuessesDontExceedTheBudget(t *testing.T) {
	const maxTries = 5
	const burst = 20
	svc, apiClientID := newTestUserServiceWithPinLimits(t, maxTries, time.Minute)
	u, err := svc.Register(t.Context(), apiClientID, "pin-"+testutil.UniqueSuffix(t)+"@example.com", "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := svc.SetPin(t.Context(), u.ID, "123456", ""); err != nil {
		t.Fatalf("SetPin: %v", err)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var invalidCount, lockedCount, otherCount int
	for i := 0; i < burst; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := svc.VerifyPin(t.Context(), u.ID, "000000")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case errors.As(err, new(*user.PinInvalidError)):
				invalidCount++
			case errors.As(err, new(*user.PinLockedError)):
				lockedCount++
			default:
				otherCount++
			}
		}()
	}
	wg.Wait()

	if otherCount != 0 {
		t.Fatalf("otherCount = %d, want 0 (every call should resolve to either pin_invalid or pin_locked)", otherCount)
	}
	// The attempt that reaches maxTries locks immediately instead of
	// returning "invalid" (same as the single-threaded case — see
	// TestVerifyPin_LockoutAfterMaxFailedAttempts), so only maxTries-1
	// guesses ever see pin_invalid; everything else, including the one
	// that crossed the threshold, sees pin_locked.
	const wantInvalid = maxTries - 1
	if invalidCount != wantInvalid {
		t.Fatalf("invalidCount = %d, want exactly %d (the budget), got %d locked instead", invalidCount, wantInvalid, lockedCount)
	}
	if lockedCount != burst-wantInvalid {
		t.Fatalf("lockedCount = %d, want %d", lockedCount, burst-wantInvalid)
	}

	// The account must actually be locked now — a correct guess right
	// after the burst still fails.
	if err := svc.VerifyPin(t.Context(), u.ID, "123456"); !errors.As(err, new(*user.PinLockedError)) {
		t.Fatalf("correct pin immediately after the burst: err = %v, want a *user.PinLockedError", err)
	}
}

// Once an account is locked, a burst of concurrent requests — including
// ones with the CORRECT pin — must never erase that lock early.
// ResetPinFailedAttemptsIfUnchanged's whole reason to exist: an
// unconditional reset after any success would let a correct guess that
// slips in during a lockout clear it ahead of time.
func TestVerifyPin_ConcurrentActivityDuringLockoutNeverUnlocksEarly(t *testing.T) {
	const maxTries = 3
	svc, apiClientID := newTestUserServiceWithPinLimits(t, maxTries, time.Minute)
	u, err := svc.Register(t.Context(), apiClientID, "pin-"+testutil.UniqueSuffix(t)+"@example.com", "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := svc.SetPin(t.Context(), u.ID, "123456", ""); err != nil {
		t.Fatalf("SetPin: %v", err)
	}

	// Drive it to locked, sequentially, so the lock is unambiguously in
	// place before the concurrent burst starts.
	for i := 0; i < maxTries-1; i++ {
		if err := svc.VerifyPin(t.Context(), u.ID, "000000"); !errors.As(err, new(*user.PinInvalidError)) {
			t.Fatalf("priming attempt %d: err = %v, want a *user.PinInvalidError", i, err)
		}
	}
	if err := svc.VerifyPin(t.Context(), u.ID, "000000"); !errors.As(err, new(*user.PinLockedError)) {
		t.Fatalf("attempt that crosses the threshold: err = %v, want a *user.PinLockedError", err)
	}

	// Now race a mix of correct and wrong guesses against the already-locked
	// account — every single one must come back locked, correct pin included.
	const burst = 10
	var wg sync.WaitGroup
	results := make([]error, burst)
	for i := 0; i < burst; i++ {
		wg.Add(1)
		pin := "000000"
		if i%2 == 0 {
			pin = "123456" // the real one
		}
		go func(i int, pin string) {
			defer wg.Done()
			results[i] = svc.VerifyPin(t.Context(), u.ID, pin)
		}(i, pin)
	}
	wg.Wait()

	for i, err := range results {
		if !errors.As(err, new(*user.PinLockedError)) {
			t.Fatalf("result %d (pin %q): err = %v, want a *user.PinLockedError — the lockout must hold even against the correct pin", i, map[bool]string{true: "123456", false: "000000"}[i%2 == 0], err)
		}
	}

	if err := svc.VerifyPin(t.Context(), u.ID, "123456"); !errors.As(err, new(*user.PinLockedError)) {
		t.Fatalf("after the burst, account should still be locked: err = %v, want a *user.PinLockedError", err)
	}
}
