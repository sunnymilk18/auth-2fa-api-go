package user

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

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
	repo *Repository
}

func NewService(repo *Repository) *Service {
	return &Service{repo: repo}
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

// NormalizeEmail trims and lowercases — the only form ever stored or
// looked up, same reasoning as NormalizeUsername/NormalizeRUT. Exported so
// auth.Service can apply the same rule where it builds Redis keys directly
// from a raw email input instead of an already-normalized *User (see
// ResetPassword/ConfirmEmailVerification).
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
