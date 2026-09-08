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

func (r *Repository) Create(ctx context.Context, apiClientID, email, passwordHash string) (*User, error) {
	const q = `
		INSERT INTO users (api_client_id, email, password_hash)
		VALUES ($1, $2, $3)
		RETURNING id, api_client_id, email, password_hash, is_active, created_at, updated_at`

	u := &User{}
	err := r.pool.QueryRow(ctx, q, apiClientID, email, passwordHash).Scan(
		&u.ID, &u.APIClientID, &u.Email, &u.PasswordHash, &u.IsActive, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrEmailTaken
		}
		return nil, fmt.Errorf("inserting user: %w", err)
	}
	return u, nil
}

// FindByEmail looks up a user scoped to a single api client — the same
// email may exist as a different account under a different client.
func (r *Repository) FindByEmail(ctx context.Context, apiClientID, email string) (*User, error) {
	const q = `
		SELECT id, api_client_id, email, password_hash, is_active, created_at, updated_at
		FROM users WHERE api_client_id = $1 AND email = $2`

	u := &User{}
	err := r.pool.QueryRow(ctx, q, apiClientID, email).Scan(
		&u.ID, &u.APIClientID, &u.Email, &u.PasswordHash, &u.IsActive, &u.CreatedAt, &u.UpdatedAt,
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
		SELECT id, api_client_id, email, password_hash, is_active, created_at, updated_at
		FROM users WHERE id = $1`

	u := &User{}
	err := r.pool.QueryRow(ctx, q, id).Scan(
		&u.ID, &u.APIClientID, &u.Email, &u.PasswordHash, &u.IsActive, &u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("querying user by id: %w", err)
	}
	return u, nil
}

// isUniqueViolation checks for Postgres SQLSTATE 23505 without importing
// pgconn directly in callers.
func isUniqueViolation(err error) bool {
	type pgError interface{ SQLState() string }
	var pgErr pgError
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23505"
	}
	return false
}
