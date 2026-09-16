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
// a value with no "@" was accepted and stored, then became permanently
// unreachable as a login identifier (classifyIdentifier only tries an
// email lookup when "@" is present). See ValidateEmail's doc comment.
var ErrInvalidEmail = errors.New("invalid email")

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
	email = normalizeEmail(email)
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
// a RUT — see classifyIdentifier — since all three are unique per tenant, at
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

// findByIdentifier resolves a login identifier to a user, dispatching to
// the matching lookup and normalizing it the same way registration did.
func (s *Service) findByIdentifier(ctx context.Context, apiClientID, identifier string) (*User, error) {
	switch classifyIdentifier(identifier) {
	case identifierEmail:
		return s.repo.FindByEmail(ctx, apiClientID, normalizeEmail(identifier))
	case identifierRUT:
		return s.repo.FindByRUT(ctx, apiClientID, NormalizeRUT(identifier))
	default:
		return s.repo.FindByUsername(ctx, apiClientID, NormalizeUsername(identifier))
	}
}

func (s *Service) FindByID(ctx context.Context, id string) (*User, error) {
	return s.repo.FindByID(ctx, id)
}

// FindByEmail looks up a user scoped to one api client (tenant) — used by
// the password reset flow, which needs the account without also verifying
// a password.
func (s *Service) FindByEmail(ctx context.Context, apiClientID, email string) (*User, error) {
	return s.repo.FindByEmail(ctx, apiClientID, normalizeEmail(email))
}

// UpdatePassword bcrypt-hashes newPassword and replaces userID's stored
// hash.
func (s *Service) UpdatePassword(ctx context.Context, userID, newPassword string) error {
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

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
