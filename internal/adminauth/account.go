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
	ErrInvalidRole    = errors.New("role must be \"admin\" or \"superadmin\"")
	// ErrAccountAlreadyActive means Service.ReactivateAccount was called on
	// an account that was never revoked — see that method's own doc
	// comment for why it refuses outright rather than treating the call as
	// "just set a new password".
	ErrAccountAlreadyActive = errors.New("admin account is already active")
)

// Role is an admin account's permission tier — see migration
// 0016_admin_account_role.sql's doc comment and router.go's
// RequireSuperAdmin wiring for exactly which routes each tier can reach.
// RoleSuperAdmin can do everything; RoleAdmin is limited to day-to-day
// moderation (user actions, lifting an individual IP ban) and can't touch
// other admin accounts, tenants/api_clients, or the IP allowlist — the
// three categories that affect "who has access at all" or "which
// systems/IPs are trusted platform-wide".
type Role string

const (
	RoleAdmin      Role = "admin"
	RoleSuperAdmin Role = "superadmin"
)

// Valid reports whether r is one of the two defined roles — Service.
// CreateAccount rejects anything else rather than silently accepting a
// typo as some unintended third tier.
func (r Role) Valid() bool {
	return r == RoleAdmin || r == RoleSuperAdmin
}

// AdminAccount is one operator-level administrator — cross-tenant, distinct
// from the tenant-scoped user.User.
type AdminAccount struct {
	ID            string
	Email         string
	PasswordHash  string
	TOTPSecretEnc string
	Role          Role
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

const selectAccountColumns = "id, email, password_hash, totp_secret_enc, role, active, created_at"

func scanAccount(row pgx.Row) (*AdminAccount, error) {
	a := &AdminAccount{}
	err := row.Scan(&a.ID, &a.Email, &a.PasswordHash, &a.TOTPSecretEnc, &a.Role, &a.Active, &a.CreatedAt)
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
// does for end users. role must already be validated (Role.Valid) —
// Service.CreateAccount is the only real caller and does that before
// reaching here.
func (r *AccountRepository) Create(ctx context.Context, email, passwordHash, totpSecretEnc string, role Role) (*AdminAccount, error) {
	const q = `
		INSERT INTO admin_accounts (email, password_hash, totp_secret_enc, role)
		VALUES ($1, $2, $3, $4)
		RETURNING ` + selectAccountColumns

	a, err := scanAccount(r.pool.QueryRow(ctx, q, email, passwordHash, totpSecretEnc, role))
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

// SetActive flips an account's active flag — false (the only thing it's
// ever called with: Service.RevokeAccount) makes Login reject it
// immediately and revokes every session it currently holds, same shape as
// apiclient.Repository.SetActive. Reactivating a revoked account never
// goes through this — see Reprovision, which sets active = TRUE together
// with fresh credentials in one statement, since a password/TOTP reset is
// the whole point of reactivating, not an optional extra step.
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

// Reprovision replaces a revoked account's credentials and reactivates it
// in one statement — password, TOTP secret, and active all change
// together, so there's no window where the row is active with stale
// credentials or reactivated-but-still-locked-out. Used only by
// Service.ReactivateAccount, which checks Active itself first and refuses
// early with ErrAccountAlreadyActive before ever reaching here — but that
// check and this UPDATE aren't atomic with each other, so the WHERE clause
// below also requires active = FALSE: without it, two concurrent
// reactivations of the same account would both pass the early check and
// then both write here, the second silently overwriting the first's
// brand-new password/TOTP secret with its own — exactly the kind of
// "whoever wrote last wins, unnoticed" bug ReactivateAccount's whole
// contract (fresh, exclusive credentials) depends on not happening.
func (r *AccountRepository) Reprovision(ctx context.Context, id, passwordHash, totpSecretEnc string) error {
	const q = `
		UPDATE admin_accounts
		SET password_hash = $2, totp_secret_enc = $3, active = TRUE, updated_at = now()
		WHERE id = $1 AND active = FALSE`
	tag, err := r.pool.Exec(ctx, q, id, passwordHash, totpSecretEnc)
	if err != nil {
		return fmt.Errorf("reprovisioning admin account: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Ambiguous on its own (id doesn't exist, or exists but is already
		// active) — but Service.ReactivateAccount always calls FindByID
		// right before this, so by the time execution reaches here the
		// account is known to exist; 0 rows affected can only mean someone
		// else reactivated it in the window between that check and this
		// statement. ErrAccountAlreadyActive, not ErrNotFound.
		return ErrAccountAlreadyActive
	}
	return nil
}

// UpdatePasswordHash replaces an account's password hash alone — used by
// Service.ChangeOwnPassword (self-service, the account is already active
// and the caller already proved the current password), unlike Reprovision
// which changes password+TOTP+active together as part of reactivating a
// revoked account.
func (r *AccountRepository) UpdatePasswordHash(ctx context.Context, id, passwordHash string) error {
	const q = `UPDATE admin_accounts SET password_hash = $2, updated_at = now() WHERE id = $1`
	tag, err := r.pool.Exec(ctx, q, id, passwordHash)
	if err != nil {
		return fmt.Errorf("updating admin account password: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateTOTPSecret replaces an account's TOTP secret alone, leaving
// password/active untouched — used by Service.ConfirmTOTPRotation once the
// caller has proven control of the new secret, unlike Reprovision which
// only ever runs as part of reactivating a revoked account.
func (r *AccountRepository) UpdateTOTPSecret(ctx context.Context, id, totpSecretEnc string) error {
	const q = `UPDATE admin_accounts SET totp_secret_enc = $2, updated_at = now() WHERE id = $1`
	tag, err := r.pool.Exec(ctx, q, id, totpSecretEnc)
	if err != nil {
		return fmt.Errorf("updating admin account totp secret: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// CountActiveByRole counts currently-active admin accounts of one role —
// Service.RevokeAccount uses this with RoleSuperAdmin to keep at least one
// superadmin always able to log in and manage other accounts; a regular
// admin being the "last" one of its tier isn't a problem the same way,
// since any remaining superadmin already has full access regardless.
func (r *AccountRepository) CountActiveByRole(ctx context.Context, role Role) (int64, error) {
	const q = `SELECT count(*) FROM admin_accounts WHERE active = TRUE AND role = $1`
	var n int64
	if err := r.pool.QueryRow(ctx, q, role).Scan(&n); err != nil {
		return 0, fmt.Errorf("counting active admin accounts by role: %w", err)
	}
	return n, nil
}
