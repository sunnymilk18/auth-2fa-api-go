package user

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotFound = errors.New("user not found")
var ErrEmailTaken = errors.New("email already registered")
var ErrUsernameTaken = errors.New("username already registered")
var ErrRUTTaken = errors.New("rut already registered")

// uniqueViolationErr maps a unique-constraint violation on username or rut
// to the matching sentinel, by index name — everything else (including a
// nil error) passes through unchanged. The email conflict has its own path
// (see Create's ON CONFLICT / RETURNING-zero-rows handling below) since it
// needs the "reclaim an unverified row" special case; username and rut
// never do, so a plain unique violation is the whole story for them.
func uniqueViolationErr(err error) error {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		return err
	}
	switch pgErr.ConstraintName {
	case "idx_users_api_client_username":
		return ErrUsernameTaken
	case "idx_users_api_client_rut":
		return ErrRUTTaken
	default:
		return err
	}
}

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
func (r *Repository) Create(ctx context.Context, apiClientID, email, passwordHash, username, rut string) (*User, error) {
	const q = `
		INSERT INTO users (api_client_id, email, password_hash, username, rut)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (api_client_id, email) DO UPDATE
			SET password_hash = EXCLUDED.password_hash, username = EXCLUDED.username, rut = EXCLUDED.rut,
				email_verified = FALSE, updated_at = now()
			WHERE users.email_verified = FALSE
		RETURNING id, api_client_id, email, username, rut, password_hash, is_active, email_verified, created_at, updated_at`

	u := &User{}
	err := r.pool.QueryRow(ctx, q, apiClientID, email, passwordHash, username, rut).Scan(
		&u.ID, &u.APIClientID, &u.Email, &u.Username, &u.RUT, &u.PasswordHash, &u.IsActive, &u.EmailVerified, &u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrEmailTaken
	}
	if err != nil {
		if mapped := uniqueViolationErr(err); mapped != err {
			return nil, mapped
		}
		return nil, fmt.Errorf("inserting user: %w", err)
	}
	return u, nil
}

const selectUserColumns = "id, api_client_id, email, username, rut, password_hash, is_active, email_verified, created_at, updated_at"

func scanUser(row pgx.Row) (*User, error) {
	u := &User{}
	err := row.Scan(
		&u.ID, &u.APIClientID, &u.Email, &u.Username, &u.RUT, &u.PasswordHash, &u.IsActive, &u.EmailVerified, &u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

// findOne runs q, wraps a genuine query error with context, and leaves
// ErrNotFound untouched for callers to check with errors.Is.
func findOne(ctx context.Context, pool *pgxpool.Pool, q, by string, args ...any) (*User, error) {
	u, err := scanUser(pool.QueryRow(ctx, q, args...))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, fmt.Errorf("querying user by %s: %w", by, err)
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

// FindByEmail looks up a user scoped to a single api client — the same
// email may exist as a different account under a different client.
func (r *Repository) FindByEmail(ctx context.Context, apiClientID, email string) (*User, error) {
	q := "SELECT " + selectUserColumns + " FROM users WHERE api_client_id = $1 AND email = $2"
	return findOne(ctx, r.pool, q, "email", apiClientID, email)
}

// FindByUsername looks up a user scoped to a single api client — see
// FindByEmail; same per-tenant scoping, different identifying column.
func (r *Repository) FindByUsername(ctx context.Context, apiClientID, username string) (*User, error) {
	q := "SELECT " + selectUserColumns + " FROM users WHERE api_client_id = $1 AND username = $2"
	return findOne(ctx, r.pool, q, "username", apiClientID, username)
}

// FindByRUT looks up a user scoped to a single api client — see FindByEmail;
// same per-tenant scoping, different identifying column. rut must already
// be normalized (see NormalizeRUT) — this does no normalization itself.
func (r *Repository) FindByRUT(ctx context.Context, apiClientID, rut string) (*User, error) {
	q := "SELECT " + selectUserColumns + " FROM users WHERE api_client_id = $1 AND rut = $2"
	return findOne(ctx, r.pool, q, "rut", apiClientID, rut)
}

// FindByIdentifier looks up a user scoped to a single api client, matching
// ANY of the three normalized forms in one query — no upfront guess about
// which one the caller actually typed. emailCandidate/usernameCandidate/
// rutCandidate are the same raw identifier normalized three different ways
// (see user.Service.findByIdentifier) — at most one of the three OR
// clauses can ever be true for a real row, since ValidateUsername already
// refuses any username that could collide with an email or rut shape (see
// its doc comment), so this can't return an ambiguous match. LIMIT 1 is a
// second layer of defense on top of that, not a substitute for it.
func (r *Repository) FindByIdentifier(ctx context.Context, apiClientID, emailCandidate, usernameCandidate, rutCandidate string) (*User, error) {
	q := "SELECT " + selectUserColumns + ` FROM users
		WHERE api_client_id = $1 AND (email = $2 OR username = $3 OR rut = $4)
		LIMIT 1`
	return findOne(ctx, r.pool, q, "identifier", apiClientID, emailCandidate, usernameCandidate, rutCandidate)
}

// FindByID looks up a user by their globally-unique id — no api client
// scoping needed here, since the id alone already identifies one user.
func (r *Repository) FindByID(ctx context.Context, id string) (*User, error) {
	q := "SELECT " + selectUserColumns + " FROM users WHERE id = $1"
	return findOne(ctx, r.pool, q, "id", id)
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
