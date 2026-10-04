package user

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// maxUsernameLen mirrors ValidateUsername's own upper bound — suggestUsername
// needs it too, to make sure a suggested candidate is never itself too long
// to register with (see its doc comment).
const maxUsernameLen = 32

var ErrInvalidCredentials = errors.New("invalid email or password")

// ErrInvalidUsername and ErrInvalidRUT guard the domain invariant, not just
// the HTTP boundary — enforced here (not only in the handler) so no future
// caller of Register (an admin endpoint, a seed script, a test) can slip
// past the rule by construction. Same pattern this project already uses
// for device.ErrInvalidPinFormat: the domain owns its own shape rules,
// the handler just translates the error to a status code.
var ErrInvalidUsername = errors.New("invalid username")
var ErrInvalidRUT = errors.New("invalid rut")

// ErrInvalidEmail: Register previously only checked email for emptiness —
// see ValidateEmail's doc comment for why that's not enough on its own.
var ErrInvalidEmail = errors.New("invalid email")

// ErrInvalidPassword guards the same invariant the others do — the minimum
// length used to be checked only in the HTTP handler, so any other future
// caller of Register could slip past it. Same fix as ErrInvalidUsername.
var ErrInvalidPassword = errors.New("invalid password")

const minPasswordLen = 8

// ValidatePassword is exported so callers with an ordering constraint
// Register/UpdatePassword don't have — auth.Service.ResetPassword needs to
// know a new password is long enough *before* it consumes the one-time
// reset code, otherwise a too-short password would burn the code and force
// requesting a whole new one just for a length mistake — can check it
// without duplicating the rule.
func ValidatePassword(password string) bool {
	return len(password) >= minPasswordLen
}

type Service struct {
	repo              *Repository
	pinMaxFailedTries int
	pinLockDuration   time.Duration
}

func NewService(repo *Repository, pinMaxFailedTries int, pinLockDuration time.Duration) *Service {
	return &Service{repo: repo, pinMaxFailedTries: pinMaxFailedTries, pinLockDuration: pinLockDuration}
}

// UsernameTakenError wraps ErrUsernameTaken with a suggested alternative
// (the requested username plus the smallest free numeric suffix) — so the
// 409 a caller gets back is actionable on its own, without needing a
// separate "check availability" round trip. errors.Is(err, ErrUsernameTaken)
// still works against it (see Is below), so existing error-checking code
// doesn't need to know this type exists.
type UsernameTakenError struct {
	Requested string
	Suggested string
}

func (e *UsernameTakenError) Error() string {
	return fmt.Sprintf("username %q already registered, try %q", e.Requested, e.Suggested)
}

func (e *UsernameTakenError) Is(target error) bool { return target == ErrUsernameTaken }

// Register creates a new user with a bcrypt-hashed password, scoped to the
// given api client (tenant). email, username and rut are each unique per
// api client — email conflicts return ErrEmailTaken, rut conflicts return
// ErrRUTTaken, and username conflicts return a *UsernameTakenError carrying
// a ready-to-suggest alternative (see suggestUsername).
func (s *Service) Register(ctx context.Context, apiClientID, email, password, username, rut string) (*User, error) {
	email = NormalizeEmail(email)
	username = NormalizeUsername(username)
	rut = NormalizeRUT(rut)

	// Checked here, not just at the HTTP boundary — see ErrInvalidUsername's
	// doc comment. Before hashing the password too: no point paying bcrypt's
	// cost for a request that's going to fail anyway.
	if !ValidateEmail(email) {
		return nil, ErrInvalidEmail
	}
	if !ValidateUsername(username) {
		return nil, ErrInvalidUsername
	}
	if !ValidateRUT(rut) {
		return nil, ErrInvalidRUT
	}
	if !ValidatePassword(password) {
		return nil, ErrInvalidPassword
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}

	u, err := s.repo.Create(ctx, apiClientID, email, string(hash), username, rut)
	if err != nil {
		if errors.Is(err, ErrUsernameTaken) {
			suggested, sugErr := s.suggestUsername(ctx, apiClientID, username)
			if sugErr == nil {
				return nil, &UsernameTakenError{Requested: username, Suggested: suggested}
			}
		}
		return nil, err
	}
	return u, nil
}

// suggestUsername finds the smallest free "base2", "base3", ... — used
// only to build a helpful error message; it never gets written anywhere on
// its own, the caller still has to actually register with whatever they
// pick. Capped well above any realistic amount of real collisions so a
// pathological case can't turn one failed registration into hundreds of
// queries.
func (s *Service) suggestUsername(ctx context.Context, apiClientID, base string) (string, error) {
	const maxAttempts = 1000
	for n := 2; n <= maxAttempts; n++ {
		suffix := strconv.Itoa(n)
		// Truncate, never grow past maxUsernameLen — a candidate the
		// caller couldn't actually register with (because it's too long)
		// isn't a useful suggestion.
		trimmedBase := base
		if maxBaseLen := maxUsernameLen - len(suffix); len(trimmedBase) > maxBaseLen {
			trimmedBase = trimmedBase[:maxBaseLen]
		}
		candidate := trimmedBase + suffix
		_, err := s.repo.FindByUsername(ctx, apiClientID, candidate)
		if errors.Is(err, ErrNotFound) {
			return candidate, nil
		}
		if err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("no free username suffix found for %q after %d attempts", base, maxAttempts)
}

// VerifyPassword checks credentials within one api client (tenant) and
// returns the user on success. It does not issue tokens or trigger OTP —
// that's the auth package's job. identifier accepts an email, a username or
// a RUT — see findByIdentifier — since all three are unique per tenant, at
// most one account can ever match.
func (s *Service) VerifyPassword(ctx context.Context, apiClientID, identifier, password string) (*User, error) {
	u, err := s.findByIdentifier(ctx, apiClientID, identifier)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			// Same error as a wrong password: don't leak which part was wrong.
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	if !u.IsActive {
		return nil, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	return u, nil
}

// FindByIdentifier resolves email, username or rut to the account it
// belongs to — same resolution VerifyPassword does internally, exported so
// callers that need the account *before* checking the password (the login
// lockout counter, keyed by account id rather than by whichever identifier
// string was typed — see auth.Service.LoginStep1) can reuse it.
func (s *Service) FindByIdentifier(ctx context.Context, apiClientID, identifier string) (*User, error) {
	return s.findByIdentifier(ctx, apiClientID, identifier)
}

// findByIdentifier resolves a login identifier — email, username or rut,
// whichever it turns out to be — in one query rather than guessing which
// one first: identifier gets normalized all three ways (only one of which
// will ever actually be "correct" for it), and the query matches on
// whichever column agrees. No shape-detection step to get subtly wrong —
// the two bugs that bit this project's earlier "guess the type, then look
// in one column" version (a numeric-ish username misread as a rut; one
// with dots misread as a rut too) can't recur, because there's no guess
// left to get wrong. Safe from cross-column ambiguity (someone's username
// accidentally matching a stranger's rut) because ValidateUsername already
// refuses any username shaped like a rut or an email — see its doc
// comment; FindByIdentifier's own LIMIT 1 is a second line of defense on
// top of that, not the only thing preventing it.
func (s *Service) findByIdentifier(ctx context.Context, apiClientID, identifier string) (*User, error) {
	return s.repo.FindByIdentifier(ctx, apiClientID,
		NormalizeEmail(identifier), NormalizeUsername(identifier), NormalizeRUT(identifier),
	)
}

func (s *Service) FindByID(ctx context.Context, id string) (*User, error) {
	return s.repo.FindByID(ctx, id)
}

// FindByEmail looks up a user scoped to one api client (tenant) — used by
// the password reset flow, which needs the account without also verifying
// a password.
func (s *Service) FindByEmail(ctx context.Context, apiClientID, email string) (*User, error) {
	return s.repo.FindByEmail(ctx, apiClientID, NormalizeEmail(email))
}

// UpdatePassword bcrypt-hashes newPassword and replaces userID's stored
// hash.
// UpdateEmail replaces userID's email (normalized) and marks it verified —
// see Repository.UpdateEmail's doc comment. The format itself is validated
// earlier, by auth.Service.AdminChangeEmail, before a code is ever sent;
// this is only ever reached once that code comes back correct.
func (s *Service) UpdateEmail(ctx context.Context, userID, newEmail string) error {
	return s.repo.UpdateEmail(ctx, userID, NormalizeEmail(newEmail))
}

func (s *Service) UpdatePassword(ctx context.Context, userID, newPassword string) error {
	// Same invariant as Register's — the password-reset flow (auth.Service.
	// ResetPassword) used to only check this in the handler too. ResetPassword
	// itself also checks ValidatePassword before this, earlier, so its
	// one-time reset code isn't burned on a too-short password — this check
	// stays too, as a backstop for any other caller of UpdatePassword.
	if !ValidatePassword(newPassword) {
		return ErrInvalidPassword
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}
	return s.repo.UpdatePassword(ctx, userID, string(hash))
}

// MarkEmailVerified flips userID's email_verified to true — see
// auth.Service.ConfirmEmailVerification.
func (s *Service) MarkEmailVerified(ctx context.Context, userID string) error {
	return s.repo.MarkEmailVerified(ctx, userID)
}

// SetPendingTOTPSecret, GetTOTPSecret, EnableTOTP and DisableTOTP are thin
// passthroughs to the repository — the actual secret generation/encryption
// and code validation live in auth.TOTPManager (this package only persists
// the already-encrypted value, it never sees a plaintext secret or a code).
func (s *Service) SetPendingTOTPSecret(ctx context.Context, userID, encryptedSecret string) error {
	return s.repo.SetPendingTOTPSecret(ctx, userID, encryptedSecret)
}

func (s *Service) GetTOTPSecret(ctx context.Context, userID string) (encryptedSecret string, enabled bool, err error) {
	return s.repo.GetTOTPSecret(ctx, userID)
}

func (s *Service) EnableTOTP(ctx context.Context, userID string) error {
	return s.repo.EnableTOTP(ctx, userID)
}

func (s *Service) DisableTOTP(ctx context.Context, userID string) error {
	return s.repo.DisableTOTP(ctx, userID)
}

// MarkTwoFactorMethodChosen is a thin passthrough — see
// Repository.MarkTwoFactorMethodChosen's doc comment.
func (s *Service) MarkTwoFactorMethodChosen(ctx context.Context, userID string) error {
	return s.repo.MarkTwoFactorMethodChosen(ctx, userID)
}

// Ban deactivates an account: VerifyPassword refuses it from then on (same
// path an already-deactivated account takes today), and auth.Service.
// DeviceLogin refuses its trusted devices too. Deliberately manual only —
// never triggered automatically by failed login attempts, unlike the IP
// blacklist (see middleware.Blacklist) — an automatic account-level ban
// keyed off failed passwords would itself be a denial-of-service tool:
// anyone who knows a victim's email/username/rut could lock them out on
// purpose just by guessing wrong on purpose.
func (s *Service) Ban(ctx context.Context, userID string) error {
	return s.repo.SetActive(ctx, userID, false)
}

// Unban reverses a previous Ban.
func (s *Service) Unban(ctx context.Context, userID string) error {
	return s.repo.SetActive(ctx, userID, true)
}

// SetLoginPinRequired is a thin passthrough — see
// Repository.SetPinRequiredAtLogin's doc comment.
func (s *Service) SetLoginPinRequired(ctx context.Context, userID string, required bool) error {
	return s.repo.SetPinRequiredAtLogin(ctx, userID, required)
}

// defaultPageSize and maxPageSize bound ListByAPIClient's page parameter —
// see its doc comment.
const (
	defaultPageSize = 50
	maxPageSize     = 100
)

// ListByAPIClient returns one page of apiClientID's users (see
// Repository.ListByAPIClient) along with the total number of users that
// tenant has. page is 1-indexed; page<1 is treated as 1. pageSize<1 falls
// back to defaultPageSize; pageSize>maxPageSize is capped there instead of
// refused outright — a caller asking for too much gets a smaller page, not
// an error, same reasoning as every other clamped-not-rejected limit in
// this project. q, when non-empty (after trimming), restricts results to
// users whose email, username or rut contains it — trimmed only, not
// lowercased, since ILIKE is already case-insensitive on its own.
func (s *Service) ListByAPIClient(ctx context.Context, apiClientID string, page, pageSize int, q string) (users []*User, total, effectivePage, effectivePageSize int, err error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = defaultPageSize
	}
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}
	q = strings.TrimSpace(q)

	offset := (page - 1) * pageSize
	users, total, err = s.repo.ListByAPIClient(ctx, apiClientID, offset, pageSize, q)
	return users, total, page, pageSize, err
}

// --- Account PIN ---
//
// One PIN per account (not per device, unlike the old trusted_devices.pin_hash)
// — it unlocks a trusted device (device.Service no longer knows about PINs
// at all, see auth.Service.DeviceLogin/RegisterDevice) and confirms
// sensitive actions from any client. A single failed-attempt counter and
// lock are shared across every use (PUT /auth/pin's current_pin check,
// POST /auth/pin/verify, device register/login) — it's one secret, so
// guesses against it share one budget regardless of which endpoint checked
// it; otherwise an attacker could exhaust one endpoint's budget and switch
// to another for a fresh one.

var (
	ErrPinNotSet        = errors.New("account has no pin set")
	ErrPinInvalid       = errors.New("invalid pin")
	ErrPinLocked        = errors.New("pin locked")
	ErrInvalidPinFormat = errors.New("pin must be exactly 6 digits")
	pinPattern          = regexp.MustCompile(`^\d{6}$`)
)

// PinInvalidError wraps ErrPinInvalid with how many attempts are left
// before the account's PIN locks — same errors.Is-still-works pattern as
// UsernameTakenError above, so existing error-checking code doesn't need to
// know this type exists.
type PinInvalidError struct {
	AttemptsLeft int
}

func (e *PinInvalidError) Error() string        { return ErrPinInvalid.Error() }
func (e *PinInvalidError) Is(target error) bool { return target == ErrPinInvalid }

// PinLockedError wraps ErrPinLocked with how long the lock actually has
// left — same pattern as auth.LockedOutError.
type PinLockedError struct {
	RetryAfter time.Duration
}

func (e *PinLockedError) Error() string { return ErrPinLocked.Error() }
func (e *PinLockedError) Unwrap() error { return ErrPinLocked }

// HasPin reports whether userID has ever set an account PIN — exposed as
// pin_set on GET /me.
func (s *Service) HasPin(ctx context.Context, userID string) (bool, error) {
	pinHash, _, _, err := s.repo.PinState(ctx, userID)
	if err != nil {
		return false, err
	}
	return pinHash != "", nil
}

// VerifyPin checks pin against userID's account PIN, applying the shared
// failed-attempt lockout: maxFailedTries consecutive wrong guesses lock the
// PIN for pinLockDuration. While locked, every verification (even a correct
// PIN) returns a *PinLockedError without touching the counter — guessing
// during a lockout can't extend it, and a correct-but-still-locked PIN
// can't be used to skip the wait (see the project's standing reasoning
// against letting repeated attempts punish anyone but the attacker,
// e.g. Ban's doc comment on why failed logins never auto-ban an account).
//
// The attempt is reserved atomically (ReserveFailedPinAttempt) before pin
// is ever compared — see its doc comment for the race this closes: without
// it, a burst of concurrent calls could each get a full bcrypt compare in
// before any of them actually counted against the lockout.
func (s *Service) VerifyPin(ctx context.Context, userID, pin string) error {
	pinHash, attempts, ok, err := s.repo.ReserveFailedPinAttempt(ctx, userID)
	if err != nil {
		return err
	}
	if !ok {
		// No PIN set, or currently locked — tell those two apart with a
		// plain (non-atomic) read; fine here, since no attempt was
		// reserved and the security decision already happened above.
		_, _, lockedUntil, stateErr := s.repo.PinState(ctx, userID)
		if stateErr != nil {
			return stateErr
		}
		if lockedUntil != nil && lockedUntil.After(time.Now()) {
			return &PinLockedError{RetryAfter: time.Until(*lockedUntil)}
		}
		return ErrPinNotSet
	}

	// attempts > max means a different, concurrent guess already crossed
	// the threshold between our reservation and now — reject without ever
	// touching bcrypt. attempts == max is this request's own last chance:
	// it still gets compared below, same as single-threaded behavior
	// always has.
	//
	// This still (defensively) calls LockPin even though some other
	// request "should" have already locked it: that other request might
	// have been a correct guess, which never locks on its own (see the
	// success path below) — without this, attempts could keep climbing
	// past max with pin_locked_until never actually set, leaving the
	// account stuck rejecting every request forever with no real lock to
	// eventually expire. LockPin itself is idempotent/first-writer-wins
	// (see its doc comment), so this never re-extends a lock that's
	// already in place.
	if attempts > s.pinMaxFailedTries {
		if lockErr := s.repo.LockPin(ctx, userID, time.Now().Add(s.pinLockDuration)); lockErr != nil {
			return lockErr
		}
		return &PinLockedError{RetryAfter: s.pinLockDuration}
	}

	if err := bcrypt.CompareHashAndPassword([]byte(pinHash), []byte(pin)); err != nil {
		if attempts >= s.pinMaxFailedTries {
			until := time.Now().Add(s.pinLockDuration)
			if lockErr := s.repo.LockPin(ctx, userID, until); lockErr != nil {
				return lockErr
			}
			return &PinLockedError{RetryAfter: s.pinLockDuration}
		}
		return &PinInvalidError{AttemptsLeft: s.pinMaxFailedTries - attempts}
	}

	return s.repo.ResetPinFailedAttemptsIfUnchanged(ctx, userID, attempts)
}

// SetPin creates (first PIN ever) or changes userID's account PIN.
// Creating requires no currentPin; changing requires the correct current
// one (checked via VerifyPin, so a wrong currentPin counts against the
// same shared lockout as everything else). Resets the failed-attempt
// counter on success — the PIN itself just changed, so failures against
// the old one are moot.
func (s *Service) SetPin(ctx context.Context, userID, newPin, currentPin string) error {
	if !pinPattern.MatchString(newPin) {
		return ErrInvalidPinFormat
	}

	hasPin, err := s.HasPin(ctx, userID)
	if err != nil {
		return err
	}
	if hasPin {
		if err := s.VerifyPin(ctx, userID, currentPin); err != nil {
			return err
		}
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(newPin), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hashing pin: %w", err)
	}
	return s.repo.SetPin(ctx, userID, string(newHash))
}

// EnsurePin backs RegisterDevice's dual meaning for its pin field (see
// auth.Service.RegisterDevice): when the account has no PIN yet, pin
// becomes the new account PIN; when it already has one, pin must match it
// (checked via VerifyPin, same shared lockout). Unlike SetPin, there's
// never a separate "new" vs "current" value here — pin plays whichever
// role the account's current state calls for.
func (s *Service) EnsurePin(ctx context.Context, userID, pin string) error {
	// Checked first, with no DB call — same reasoning as Register's old
	// format check in package device: a malformed guess is a client bug,
	// not worth a database round trip (or, once an account PIN exists, a
	// wasted attempt against its lockout) to reject.
	if !pinPattern.MatchString(pin) {
		return ErrInvalidPinFormat
	}

	hasPin, err := s.HasPin(ctx, userID)
	if err != nil {
		return err
	}
	if hasPin {
		return s.VerifyPin(ctx, userID, pin)
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(pin), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hashing pin: %w", err)
	}
	return s.repo.SetPin(ctx, userID, string(newHash))
}

// ClearPin removes userID's account PIN entirely — see
// auth.Service.AdminResetPin, which also revokes their trusted devices and
// sessions alongside this.
func (s *Service) ClearPin(ctx context.Context, userID string) error {
	return s.repo.ClearPin(ctx, userID)
}

// NormalizeEmail trims and lowercases — the only form ever stored or
// looked up, same reasoning as NormalizeUsername/NormalizeRUT. Exported so
// auth.Service can apply the same rule where it builds Redis keys directly
// from a raw email input instead of an already-normalized *User (see
// ResetPassword/ConfirmEmailVerification).
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
