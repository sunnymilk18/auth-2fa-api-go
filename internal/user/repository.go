package user

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotFound = errors.New("user not found")
var ErrEmailTaken = errors.New("email already registered")

// Repository persists users in PostgreSQL.
type Repository struct {
	pool *pgxpool.Pool
}

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

// Create inserts a new user, or — if api_client_id+email already names an
// existing row that was never verified — reclaims that row for the new
// attempt instead of refusing it. An unverified account never proved its
// owner actually controls that address, so there's nothing legitimate to
// protect by rejecting the new attempt; without this, a single typo'd
// registration would permanently squat on that email, blocking its real
// owner from ever registering (email is unique per api_client_id, and
// nothing else expires or reclaims an abandoned unverified row). Only a
// genuinely VERIFIED existing account still blocks a new registration —
// the UPDATE's WHERE clause then never matches, ON CONFLICT DO UPDATE is
// skipped for that row, and RETURNING yields zero rows, read below as
// ErrEmailTaken.
func (r *Repository) Create(ctx context.Context, apiClientID, email, passwordHash string) (*User, error) {
	const q = `
		INSERT INTO users (api_client_id, email, password_hash)
		VALUES ($1, $2, $3)
		ON CONFLICT (api_client_id, email) DO UPDATE
			SET password_hash = EXCLUDED.password_hash, email_verified = FALSE, updated_at = now()
			WHERE users.email_verified = FALSE
		RETURNING id, api_client_id, email, password_hash, is_active, email_verified, created_at, updated_at`

	u := &User{}
	err := r.pool.QueryRow(ctx, q, apiClientID, email, passwordHash).Scan(
		&u.ID, &u.APIClientID, &u.Email, &u.PasswordHash, &u.IsActive, &u.EmailVerified, &u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrEmailTaken
	}
	if err != nil {
		return nil, fmt.Errorf("inserting user: %w", err)
	}
	return u, nil
}

// FindByEmail looks up a user scoped to a single api client — the same
// email may exist as a different account under a different client.
func (r *Repository) FindByEmail(ctx context.Context, apiClientID, email string) (*User, error) {
	const q = `
		SELECT id, api_client_id, email, password_hash, is_active, email_verified, created_at, updated_at
		FROM users WHERE api_client_id = $1 AND email = $2`

	u := &User{}
	err := r.pool.QueryRow(ctx, q, apiClientID, email).Scan(
		&u.ID, &u.APIClientID, &u.Email, &u.PasswordHash, &u.IsActive, &u.EmailVerified, &u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("querying user by email: %w", err)
	}
	return u, nil
}

// FindByID looks up a user by their globally-unique id — no api client
// scoping needed here, since the id alone already identifies one user.
func (r *Repository) FindByID(ctx context.Context, id string) (*User, error) {
	const q = `
		SELECT id, api_client_id, email, password_hash, is_active, email_verified, created_at, updated_at
		FROM users WHERE id = $1`

	u := &User{}
	err := r.pool.QueryRow(ctx, q, id).Scan(
		&u.ID, &u.APIClientID, &u.Email, &u.PasswordHash, &u.IsActive, &u.EmailVerified, &u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("querying user by id: %w", err)
	}
	return u, nil
}

// MarkEmailVerified flips email_verified to true — called once, when the
// user confirms the code emailed at registration. Unblocks login (see
// auth.Service.LoginStep1).
func (r *Repository) MarkEmailVerified(ctx context.Context, id string) error {
	const q = `UPDATE users SET email_verified = TRUE, updated_at = now() WHERE id = $1`
	tag, err := r.pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("marking email verified: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdatePassword replaces id's stored password hash — used by the password
// reset flow (the hash is already computed by the caller; this repository
// never sees a plaintext password).
func (r *Repository) UpdatePassword(ctx context.Context, id, passwordHash string) error {
	const q = `UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1`
	tag, err := r.pool.Exec(ctx, q, id, passwordHash)
	if err != nil {
		return fmt.Errorf("updating password: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
