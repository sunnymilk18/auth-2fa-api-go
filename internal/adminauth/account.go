// Package adminauth backs the operator's own admin panel: individual
// login (email + password + mandatory TOTP) and the session it grants,
// kept deliberately separate from the shared X-Admin-Token that
// middleware.RequireAdminToken checks. The token stays the credential for
// scripts/automation; this package is what a human using the panel itself
// authenticates with, so destructive /admin/* actions can be attributed to
// the specific person who took them instead of just "the operator".
package adminauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound       = errors.New("admin account not found")
	ErrDuplicateEmail = errors.New("an admin account with this email already exists")
)

// AdminAccount is one operator-level administrator — cross-tenant, distinct
// from the tenant-scoped user.User.
type AdminAccount struct {
	ID            string
	Email         string
	PasswordHash  string
	TOTPSecretEnc string
	Active        bool
	CreatedAt     time.Time
}

// AccountRepository persists AdminAccount rows in Postgres.
type AccountRepository struct {
	pool *pgxpool.Pool
}

func NewAccountRepository(pool *pgxpool.Pool) *AccountRepository {
	return &AccountRepository{pool: pool}
}

const selectAccountColumns = "id, email, password_hash, totp_secret_enc, active, created_at"

func scanAccount(row pgx.Row) (*AdminAccount, error) {
	a := &AdminAccount{}
	err := row.Scan(&a.ID, &a.Email, &a.PasswordHash, &a.TOTPSecretEnc, &a.Active, &a.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return a, nil
}

// Create provisions a new admin account. email is case-sensitively unique
// at the DB level; callers normalize beforehand the same way user.Service
// does for end users.
func (r *AccountRepository) Create(ctx context.Context, email, passwordHash, totpSecretEnc string) (*AdminAccount, error) {
	const q = `
		INSERT INTO admin_accounts (email, password_hash, totp_secret_enc)
		VALUES ($1, $2, $3)
		RETURNING ` + selectAccountColumns

	a, err := scanAccount(r.pool.QueryRow(ctx, q, email, passwordHash, totpSecretEnc))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrDuplicateEmail
		}
		return nil, fmt.Errorf("inserting admin account: %w", err)
	}
	return a, nil
}

func (r *AccountRepository) FindByEmail(ctx context.Context, email string) (*AdminAccount, error) {
	const q = "SELECT " + selectAccountColumns + " FROM admin_accounts WHERE email = $1"
	a, err := scanAccount(r.pool.QueryRow(ctx, q, email))
	if errors.Is(err, ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("querying admin account by email: %w", err)
	}
	return a, nil
}

func (r *AccountRepository) FindByID(ctx context.Context, id string) (*AdminAccount, error) {
	const q = "SELECT " + selectAccountColumns + " FROM admin_accounts WHERE id = $1"
	a, err := scanAccount(r.pool.QueryRow(ctx, q, id))
	if errors.Is(err, ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("querying admin account by id: %w", err)
	}
	return a, nil
}

// List returns every admin account, oldest first — active and revoked
// alike, so the panel can show a revoked admin's history rather than
// making it disappear.
func (r *AccountRepository) List(ctx context.Context) ([]*AdminAccount, error) {
	const q = "SELECT " + selectAccountColumns + " FROM admin_accounts ORDER BY created_at"

	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("listing admin accounts: %w", err)
	}
	defer rows.Close()

	var out []*AdminAccount
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning admin account: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// SetActive flips an account's active flag — false (the only thing
// Service.RevokeAccount calls this with) makes Login reject it immediately
// and revokes every session it currently holds, same shape as
// apiclient.Repository.SetActive.
func (r *AccountRepository) SetActive(ctx context.Context, id string, active bool) error {
	const q = `UPDATE admin_accounts SET active = $2, updated_at = now() WHERE id = $1`
	tag, err := r.pool.Exec(ctx, q, id, active)
	if err != nil {
		return fmt.Errorf("updating admin account active state: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// CountActive counts currently-active admin accounts — Service.
// RevokeAccount checks this before deactivating one, to keep at least one
// admin always able to log in.
func (r *AccountRepository) CountActive(ctx context.Context) (int64, error) {
	const q = `SELECT count(*) FROM admin_accounts WHERE active = TRUE`
	var n int64
	if err := r.pool.QueryRow(ctx, q).Scan(&n); err != nil {
		return 0, fmt.Errorf("counting active admin accounts: %w", err)
	}
	return n, nil
}
