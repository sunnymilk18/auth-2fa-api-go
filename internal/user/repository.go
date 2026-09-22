package user

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"

	mssql "github.com/microsoft/go-mssqldb"
)

var ErrNotFound = errors.New("user not found")
var ErrEmailTaken = errors.New("email already registered")
var ErrUsernameTaken = errors.New("username already registered")
var ErrRUTTaken = errors.New("rut already registered")

// uniqueIndexName extracts the violated index's name from a SQL Server
// unique-violation error message, e.g. `Cannot insert duplicate key row in
// object 'dbo.users' with unique index 'idx_users_api_client_username'.` —
// unlike pgx's structured ConstraintName, the mssql driver only exposes
// this as free text on mssql.Error.Message, so this is a best-effort parse
// rather than a guaranteed structured field.
var uniqueIndexNameRe = regexp.MustCompile(`unique index '([^']+)'`)

// uniqueViolationErr maps a unique-constraint/index violation on username or
// rut to the matching sentinel, by index name — everything else (including
// a nil error) passes through unchanged. The email conflict has its own
// path (see Create's MERGE / zero-rows handling below) since it needs the
// "reclaim an unverified row" special case; username and rut never do, so a
// plain unique violation is the whole story for them.
func uniqueViolationErr(err error) error {
	var mssqlErr mssql.Error
	if !errors.As(err, &mssqlErr) || (mssqlErr.Number != 2601 && mssqlErr.Number != 2627) {
		return err
	}
	m := uniqueIndexNameRe.FindStringSubmatch(mssqlErr.Message)
	if m == nil {
		return err
	}
	switch m[1] {
	case "idx_users_api_client_username":
		return ErrUsernameTaken
	case "idx_users_api_client_rut":
		return ErrRUTTaken
	default:
		return err
	}
}

// Repository persists users in SQL Server.
type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

// Create inserts a new user, or — if api_client_id+email already names an
// existing row that was never verified — reclaims that row for the new
// attempt instead of refusing it. An unverified account never proved its
// owner actually controls that address, so there's nothing legitimate to
// protect by rejecting the new attempt; without this, a single typo'd
// registration would permanently squat on that email, blocking its real
// owner from ever registering (email is unique per api_client_id, and
// nothing else expires or reclaims an abandoned unverified row). Only a
// genuinely VERIFIED existing account still blocks a new registration — the
// MERGE's WHEN MATCHED guard then never fires (and WHEN NOT MATCHED can't
// either, since a row DOES exist), so OUTPUT yields zero rows, read below
// as ErrEmailTaken.
func (r *Repository) Create(ctx context.Context, apiClientID, email, passwordHash, username, rut string) (*User, error) {
	const q = `
		MERGE INTO users AS target
		USING (SELECT ? AS api_client_id, ? AS email, ? AS password_hash, ? AS username, ? AS rut) AS src
		ON target.api_client_id = src.api_client_id AND target.email = src.email
		WHEN MATCHED AND target.email_verified = 0 THEN
			UPDATE SET password_hash = src.password_hash, username = src.username, rut = src.rut,
				email_verified = 0, two_factor_method_chosen = 0, updated_at = SYSDATETIMEOFFSET()
		WHEN NOT MATCHED THEN
			INSERT (api_client_id, email, password_hash, username, rut)
			VALUES (src.api_client_id, src.email, src.password_hash, src.username, src.rut)
		OUTPUT INSERTED.id, INSERTED.api_client_id, INSERTED.email, INSERTED.username, INSERTED.rut,
			INSERTED.password_hash, INSERTED.is_active, INSERTED.email_verified, INSERTED.totp_enabled,
			INSERTED.two_factor_method_chosen, INSERTED.created_at, INSERTED.updated_at;`

	u := &User{}
	err := r.db.QueryRowContext(ctx, q, apiClientID, email, passwordHash, username, rut).Scan(
		&u.ID, &u.APIClientID, &u.Email, &u.Username, &u.RUT, &u.PasswordHash, &u.IsActive, &u.EmailVerified, &u.TOTPEnabled, &u.TwoFactorMethodChosen, &u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
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

const selectUserColumns = "id, api_client_id, email, username, rut, password_hash, is_active, email_verified, totp_enabled, two_factor_method_chosen, created_at, updated_at"

func scanUser(row *sql.Row) (*User, error) {
	u := &User{}
	err := row.Scan(
		&u.ID, &u.APIClientID, &u.Email, &u.Username, &u.RUT, &u.PasswordHash, &u.IsActive, &u.EmailVerified, &u.TOTPEnabled, &u.TwoFactorMethodChosen, &u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

// findOne runs q, wraps a genuine query error with context, and leaves
// ErrNotFound untouched for callers to check with errors.Is.
func findOne(ctx context.Context, db *sql.DB, q, by string, args ...any) (*User, error) {
	u, err := scanUser(db.QueryRowContext(ctx, q, args...))
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
	q := "SELECT " + selectUserColumns + " FROM users WHERE api_client_id = ? AND email = ?"
	return findOne(ctx, r.db, q, "email", apiClientID, email)
}

// FindByUsername looks up a user scoped to a single api client — see
// FindByEmail; same per-tenant scoping, different identifying column.
func (r *Repository) FindByUsername(ctx context.Context, apiClientID, username string) (*User, error) {
	q := "SELECT " + selectUserColumns + " FROM users WHERE api_client_id = ? AND username = ?"
	return findOne(ctx, r.db, q, "username", apiClientID, username)
}

// FindByRUT looks up a user scoped to a single api client — see FindByEmail;
// same per-tenant scoping, different identifying column. rut must already
// be normalized (see NormalizeRUT) — this does no normalization itself.
func (r *Repository) FindByRUT(ctx context.Context, apiClientID, rut string) (*User, error) {
	q := "SELECT " + selectUserColumns + " FROM users WHERE api_client_id = ? AND rut = ?"
	return findOne(ctx, r.db, q, "rut", apiClientID, rut)
}

// FindByIdentifier looks up a user scoped to a single api client, matching
// ANY of the three normalized forms in one query — no upfront guess about
// which one the caller actually typed. emailCandidate/usernameCandidate/
// rutCandidate are the same raw identifier normalized three different ways
// (see user.Service.findByIdentifier) — at most one of the three OR
// clauses can ever be true for a real row, since ValidateUsername already
// refuses any username that could collide with an email or rut shape (see
// its doc comment), so this can't return an ambiguous match. TOP 1 is a
// second layer of defense on top of that, not a substitute for it.
func (r *Repository) FindByIdentifier(ctx context.Context, apiClientID, emailCandidate, usernameCandidate, rutCandidate string) (*User, error) {
	q := "SELECT TOP 1 " + selectUserColumns + ` FROM users
		WHERE api_client_id = ? AND (email = ? OR username = ? OR rut = ?)`
	return findOne(ctx, r.db, q, "identifier", apiClientID, emailCandidate, usernameCandidate, rutCandidate)
}

// FindByID looks up a user by their globally-unique id — no api client
// scoping needed here, since the id alone already identifies one user.
func (r *Repository) FindByID(ctx context.Context, id string) (*User, error) {
	q := "SELECT " + selectUserColumns + " FROM users WHERE id = ?"
	return findOne(ctx, r.db, q, "id", id)
}

// MarkEmailVerified flips email_verified to true — called once, when the
// user confirms the code emailed at registration. Unblocks login (see
// auth.Service.LoginStep1).
func (r *Repository) MarkEmailVerified(ctx context.Context, id string) error {
	const q = `UPDATE users SET email_verified = 1, updated_at = SYSDATETIMEOFFSET() WHERE id = ?`
	res, err := r.db.ExecContext(ctx, q, id)
	if err != nil {
		return fmt.Errorf("marking email verified: %w", err)
	}
	return errIfNoRowsAffected(res)
}

// SetActive flips is_active — used to manually ban (false) or unban (true)
// an account. VerifyPassword already refuses login for an inactive user
// (see its own doc comment); this is what actually lets an operator flip
// that switch, via user.Service.Ban/Unban.
func (r *Repository) SetActive(ctx context.Context, id string, active bool) error {
	const q = `UPDATE users SET is_active = ?, updated_at = SYSDATETIMEOFFSET() WHERE id = ?`
	res, err := r.db.ExecContext(ctx, q, active, id)
	if err != nil {
		return fmt.Errorf("updating user active state: %w", err)
	}
	return errIfNoRowsAffected(res)
}

// SetPendingTOTPSecret stores a newly generated (encrypted) TOTP secret and
// resets totp_enabled to FALSE — a fresh enrollment (or re-enrollment)
// always has to be confirmed with a real code before it's trusted for
// login, even if the account had a previously-confirmed secret.
func (r *Repository) SetPendingTOTPSecret(ctx context.Context, id, encryptedSecret string) error {
	const q = `UPDATE users SET totp_secret_enc = ?, totp_enabled = 0, updated_at = SYSDATETIMEOFFSET() WHERE id = ?`
	res, err := r.db.ExecContext(ctx, q, encryptedSecret, id)
	if err != nil {
		return fmt.Errorf("storing pending totp secret: %w", err)
	}
	return errIfNoRowsAffected(res)
}

// GetTOTPSecret returns the account's encrypted secret (empty if none) and
// whether it's confirmed/enabled — used at login time to decide whether to
// expect a TOTP code, and to actually validate one.
func (r *Repository) GetTOTPSecret(ctx context.Context, id string) (encryptedSecret string, enabled bool, err error) {
	const q = `SELECT COALESCE(totp_secret_enc, ''), totp_enabled FROM users WHERE id = ?`
	err = r.db.QueryRowContext(ctx, q, id).Scan(&encryptedSecret, &enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, ErrNotFound
	}
	if err != nil {
		return "", false, fmt.Errorf("querying totp secret: %w", err)
	}
	return encryptedSecret, enabled, nil
}

// EnableTOTP flips totp_enabled to TRUE — called once a freshly generated
// secret's first code has been verified (see ConfirmTOTPEnrollment).
func (r *Repository) EnableTOTP(ctx context.Context, id string) error {
	const q = `UPDATE users SET totp_enabled = 1, updated_at = SYSDATETIMEOFFSET() WHERE id = ?`
	res, err := r.db.ExecContext(ctx, q, id)
	if err != nil {
		return fmt.Errorf("enabling totp: %w", err)
	}
	return errIfNoRowsAffected(res)
}

// DisableTOTP clears the stored secret entirely and turns totp_enabled
// off — login falls back to the email OTP flow from then on. Clearing the
// secret (not just the flag) means a stale encrypted value never lingers
// for a later re-enrollment to accidentally trust.
func (r *Repository) DisableTOTP(ctx context.Context, id string) error {
	const q = `UPDATE users SET totp_secret_enc = NULL, totp_enabled = 0, updated_at = SYSDATETIMEOFFSET() WHERE id = ?`
	res, err := r.db.ExecContext(ctx, q, id)
	if err != nil {
		return fmt.Errorf("disabling totp: %w", err)
	}
	return errIfNoRowsAffected(res)
}

// MarkTwoFactorMethodChosen flips two_factor_method_chosen to TRUE —
// idempotent (a no-op once already true), so callers can call this
// unconditionally after any successful login/enrollment without needing to
// check the current value first. See User.TwoFactorMethodChosen's doc
// comment for what this gates.
func (r *Repository) MarkTwoFactorMethodChosen(ctx context.Context, id string) error {
	const q = `UPDATE users SET two_factor_method_chosen = 1, updated_at = SYSDATETIMEOFFSET() WHERE id = ? AND two_factor_method_chosen = 0`
	_, err := r.db.ExecContext(ctx, q, id)
	if err != nil {
		return fmt.Errorf("marking two-factor method chosen: %w", err)
	}
	return nil
}

// UpdatePassword replaces id's stored password hash — used by the password
// reset flow (the hash is already computed by the caller; this repository
// never sees a plaintext password).
func (r *Repository) UpdatePassword(ctx context.Context, id, passwordHash string) error {
	const q = `UPDATE users SET password_hash = ?, updated_at = SYSDATETIMEOFFSET() WHERE id = ?`
	res, err := r.db.ExecContext(ctx, q, passwordHash, id)
	if err != nil {
		return fmt.Errorf("updating password: %w", err)
	}
	return errIfNoRowsAffected(res)
}

func errIfNoRowsAffected(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
