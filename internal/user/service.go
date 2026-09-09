package user

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

var ErrInvalidCredentials = errors.New("invalid email or password")

type Service struct {
	repo *Repository
}

func NewService(repo *Repository) *Service {
	return &Service{repo: repo}
}

// Register creates a new user with a bcrypt-hashed password, scoped to the
// given api client (tenant).
func (s *Service) Register(ctx context.Context, apiClientID, email, password string) (*User, error) {
	email = normalizeEmail(email)

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}

	return s.repo.Create(ctx, apiClientID, email, string(hash))
}

// VerifyPassword checks credentials within one api client (tenant) and
// returns the user on success. It does not issue tokens or trigger OTP —
// that's the auth package's job.
func (s *Service) VerifyPassword(ctx context.Context, apiClientID, email, password string) (*User, error) {
	email = normalizeEmail(email)

	u, err := s.repo.FindByEmail(ctx, apiClientID, email)
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

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
