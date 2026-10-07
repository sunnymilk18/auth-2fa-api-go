package user

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

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
	case "idx_users_api_client_email":
		return ErrEmailTaken
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
				email_verified = FALSE, two_factor_method_chosen = FALSE, updated_at = now()
			WHERE users.email_verified = FALSE
		RETURNING id, api_client_id, email, username, rut, password_hash, is_active, email_verified, totp_enabled, two_factor_method_chosen, pin_required_at_login, created_at, updated_at`

	u := &User{}
	err := r.pool.QueryRow(ctx, q, apiClientID, email, passwordHash, username, rut).Scan(
		&u.ID, &u.APIClientID, &u.Email, &u.Username, &u.RUT, &u.PasswordHash, &u.IsActive, &u.EmailVerified, &u.TOTPEnabled, &u.TwoFactorMethodChosen, &u.PinRequiredAtLogin, &u.CreatedAt, &u.UpdatedAt,
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

const selectUserColumns = "id, api_client_id, email, username, rut, password_hash, is_active, email_verified, totp_enabled, two_factor_method_chosen, pin_required_at_login, created_at, updated_at"

func scanUser(row pgx.Row) (*User, error) {
	u := &User{}
	err := row.Scan(
		&u.ID, &u.APIClientID, &u.Email, &u.Username, &u.RUT, &u.PasswordHash, &u.IsActive, &u.EmailVerified, &u.TOTPEnabled, &u.TwoFactorMethodChosen, &u.PinRequiredAtLogin, &u.CreatedAt, &u.UpdatedAt,
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

// escapeLikePattern escapes the three characters that mean something
// special to LIKE/ILIKE (%, _ and the escape character itself, \) so a
// caller's search text is matched literally — without this, a search for
// an email containing a literal "%" or "_" would silently behave like a
// wildcard instead of matching that character. The escaped value still
// needs to be wrapped in its own "%...%" by the caller; only the escape
// character itself is fixed here (backslash, Postgres's default).
func escapeLikePattern(s string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return replacer.Replace(s)
}

// ListByAPIClient returns one page of users, newest first, plus the total
// row count for the same filter (COUNT(*) OVER() — computed in the same
// query as the page itself, not a separate round trip) so a caller can page
// through without a second request just to know how many pages there are.
// offset/limit are the caller's responsibility to keep sane (see
// user.Service.ListByAPIClient); this method applies them as-is. q, when
// non-empty, restricts the results to rows where email, username or rut
// contains it (ILIKE, so case-insensitive) — see escapeLikePattern for why
// the value is escaped before being wrapped in "%...%". apiClientID, when
// non-empty, restricts the results to that one tenant — when empty, this
// lists across every tenant instead (see auth.Service.AdminListUsers's
// caller: this is only ever reached with apiClientID == "" through
// /admin/users, gated by the operator's own unscoped X-Admin-Token, never
// through /system-admin/users, which always has a real tenant id). Each
// row also carries its tenant's name (ListedUser.APIClientName), resolved
// via a LEFT JOIN rather than a lookup per row or a second round trip —
// LEFT, not JOIN, so a user is never dropped from the listing over a
// tenant that can't be resolved (there's no such tenant today, but
// nothing enforces it can never happen); APIClientName is "" in that case.
// This is a separate, fully-qualified column list from selectUserColumns
// (used elsewhere for single-table lookups with no join and no ambiguity)
// rather than a change to it — both `users` and `api_clients` have `id`,
// `created_at` and `updated_at`, so every column referenced here (SELECT,
// WHERE, ORDER BY alike) must be qualified with `users.` or it's ambiguous
// the moment the join is in play.
func (r *Repository) ListByAPIClient(ctx context.Context, apiClientID string, offset, limit int, q string) ([]*ListedUser, int, error) {
	query := `
		SELECT users.id, users.api_client_id, users.email, users.username, users.rut, users.password_hash,
			users.is_active, users.email_verified, users.totp_enabled, users.two_factor_method_chosen,
			users.pin_required_at_login, users.created_at, users.updated_at,
			COALESCE(api_clients.name, '') AS api_client_name,
			COUNT(*) OVER() AS total
		FROM users
		LEFT JOIN api_clients ON api_clients.id = users.api_client_id`
	var args []any
	var conditions []string

	if apiClientID != "" {
		args = append(args, apiClientID)
		conditions = append(conditions, fmt.Sprintf("users.api_client_id = $%d", len(args)))
	}
	if q != "" {
		args = append(args, "%"+escapeLikePattern(q)+"%")
		conditions = append(conditions, fmt.Sprintf("(users.email ILIKE $%d OR users.username ILIKE $%d OR users.rut ILIKE $%d)", len(args), len(args), len(args)))
	}
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += fmt.Sprintf(" ORDER BY users.created_at DESC OFFSET $%d LIMIT $%d", len(args)+1, len(args)+2)
	args = append(args, offset, limit)

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("listing users: %w", err)
	}
	defer rows.Close()

	var users []*ListedUser
	total := 0
	for rows.Next() {
		u := &ListedUser{}
		if err := rows.Scan(
			&u.ID, &u.APIClientID, &u.Email, &u.Username, &u.RUT, &u.PasswordHash, &u.IsActive, &u.EmailVerified, &u.TOTPEnabled, &u.TwoFactorMethodChosen, &u.PinRequiredAtLogin, &u.CreatedAt, &u.UpdatedAt,
			&u.APIClientName,
			&total,
		); err != nil {
			return nil, 0, fmt.Errorf("scanning user row: %w", err)
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("listing users: %w", err)
	}
	return users, total, nil
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

// SetActive flips is_active — used to manually ban (false) or unban (true)
// an account. VerifyPassword already refuses login for an inactive user
// (see its own doc comment); this is what actually lets an operator flip
// that switch, via user.Service.Ban/Unban.
func (r *Repository) SetActive(ctx context.Context, id string, active bool) error {
	const q = `UPDATE users SET is_active = $2, updated_at = now() WHERE id = $1`
	tag, err := r.pool.Exec(ctx, q, id, active)
	if err != nil {
		return fmt.Errorf("updating user active state: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetPendingTOTPSecret stores a newly generated (encrypted) TOTP secret and
// resets totp_enabled to FALSE — a fresh enrollment (or re-enrollment)
// always has to be confirmed with a real code before it's trusted for
// login, even if the account had a previously-confirmed secret.
func (r *Repository) SetPendingTOTPSecret(ctx context.Context, id, encryptedSecret string) error {
	const q = `UPDATE users SET totp_secret_enc = $2, totp_enabled = FALSE, updated_at = now() WHERE id = $1`
	tag, err := r.pool.Exec(ctx, q, id, encryptedSecret)
	if err != nil {
		return fmt.Errorf("storing pending totp secret: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// GetTOTPSecret returns the account's encrypted secret (empty if none) and
// whether it's confirmed/enabled — used at login time to decide whether to
// expect a TOTP code, and to actually validate one.
func (r *Repository) GetTOTPSecret(ctx context.Context, id string) (encryptedSecret string, enabled bool, err error) {
	const q = `SELECT COALESCE(totp_secret_enc, ''), totp_enabled FROM users WHERE id = $1`
	err = r.pool.QueryRow(ctx, q, id).Scan(&encryptedSecret, &enabled)
	if errors.Is(err, pgx.ErrNoRows) {
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
	const q = `UPDATE users SET totp_enabled = TRUE, updated_at = now() WHERE id = $1`
	tag, err := r.pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("enabling totp: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DisableTOTP clears the stored secret entirely and turns totp_enabled
// off — login falls back to the email OTP flow from then on. Clearing the
// secret (not just the flag) means a stale encrypted value never lingers
// for a later re-enrollment to accidentally trust.
func (r *Repository) DisableTOTP(ctx context.Context, id string) error {
	const q = `UPDATE users SET totp_secret_enc = NULL, totp_enabled = FALSE, updated_at = now() WHERE id = $1`
	tag, err := r.pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("disabling totp: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkTwoFactorMethodChosen flips two_factor_method_chosen to TRUE —
// idempotent (a no-op once already true), so callers can call this
// unconditionally after any successful login/enrollment without needing to
// check the current value first. See User.TwoFactorMethodChosen's doc
// comment for what this gates.
func (r *Repository) MarkTwoFactorMethodChosen(ctx context.Context, id string) error {
	const q = `UPDATE users SET two_factor_method_chosen = TRUE, updated_at = now() WHERE id = $1 AND two_factor_method_chosen = FALSE`
	_, err := r.pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("marking two-factor method chosen: %w", err)
	}
	return nil
}

// SetPinRequiredAtLogin flips pin_required_at_login — see
// auth.Service.AdminSetLoginPinRequired. Doesn't touch sessions, trusted
// devices or the PIN itself either way: turning the switch on doesn't
// revoke what already exists, and turning it off just stops asking for the
// extra step going forward.
func (r *Repository) SetPinRequiredAtLogin(ctx context.Context, id string, required bool) error {
	const q = `UPDATE users SET pin_required_at_login = $2, updated_at = now() WHERE id = $1`
	tag, err := r.pool.Exec(ctx, q, id, required)
	if err != nil {
		return fmt.Errorf("updating pin_required_at_login: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// PinState returns id's current account PIN state: the bcrypt hash (empty
// if never set), the failed-attempt counter, and the lock expiry (nil if
// not locked) — everything Service.VerifyPin needs in one round trip.
func (r *Repository) PinState(ctx context.Context, id string) (pinHash string, failedAttempts int, lockedUntil *time.Time, err error) {
	const q = `SELECT COALESCE(pin_hash, ''), pin_failed_attempts, pin_locked_until FROM users WHERE id = $1`
	err = r.pool.QueryRow(ctx, q, id).Scan(&pinHash, &failedAttempts, &lockedUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", 0, nil, ErrNotFound
	}
	if err != nil {
		return "", 0, nil, fmt.Errorf("querying pin state: %w", err)
	}
	return pinHash, failedAttempts, lockedUntil, nil
}

// SetPin replaces id's account PIN and clears any failed-attempt/lock state
// — a fresh PIN means past failures against the old one are moot.
func (r *Repository) SetPin(ctx context.Context, id, pinHash string) error {
	const q = `UPDATE users SET pin_hash = $2, pin_set_at = now(), pin_failed_attempts = 0, pin_locked_until = NULL, updated_at = now() WHERE id = $1`
	tag, err := r.pool.Exec(ctx, q, id, pinHash)
	if err != nil {
		return fmt.Errorf("setting pin: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ReserveFailedPinAttempt atomically reserves one "attempt slot" against
// id's account PIN — BEFORE the caller compares the guess with bcrypt. This
// is what closes a race a batch of concurrent VerifyPin calls could
// otherwise exploit: reading "not locked", then each comparing its own
// guess with bcrypt independently, and only incrementing afterward, let N
// simultaneous wrong guesses each get a full bcrypt compare before any of
// them actually counted against the lockout — so the real budget was N
// attempts per burst, not pinMaxFailedTries. Reserving the slot first,
// atomically, means a guess that arrives once the budget's already spent
// never reaches bcrypt at all — same pattern as RefreshRepository.
// ConsumeIfValid's atomic consume-then-check.
//
// ok is false when the row didn't match — either no PIN is set yet, or
// it's currently locked; the caller falls back to a plain PinState read to
// tell those two apart for the error message (fine to be non-atomic there,
// since the security decision already happened above).
func (r *Repository) ReserveFailedPinAttempt(ctx context.Context, id string) (pinHash string, attempts int, ok bool, err error) {
	const q = `
		UPDATE users
		SET pin_failed_attempts = CASE
				WHEN pin_locked_until IS NOT NULL AND pin_locked_until <= now() THEN 1
				ELSE pin_failed_attempts + 1
			END,
			-- A naturally-expired lock is cleared here, not just ignored by
			-- the WHERE below — otherwise pin_failed_attempts resets to 1
			-- (new window) but a stale pin_locked_until would still be
			-- sitting there, doing nothing (it's already in the past) but
			-- leaving the row in a confusing half-expired state.
			pin_locked_until = CASE
				WHEN pin_locked_until IS NOT NULL AND pin_locked_until <= now() THEN NULL
				ELSE pin_locked_until
			END,
			updated_at = now()
		WHERE id = $1 AND pin_hash IS NOT NULL AND (pin_locked_until IS NULL OR pin_locked_until <= now())
		RETURNING pin_hash, pin_failed_attempts`
	err = r.pool.QueryRow(ctx, q, id).Scan(&pinHash, &attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", 0, false, nil
	}
	if err != nil {
		return "", 0, false, fmt.Errorf("reserving pin attempt: %w", err)
	}
	return pinHash, attempts, true, nil
}

// LockPin sets id's pin_locked_until — called once pin_failed_attempts
// crosses the configured threshold (see user.Service.VerifyPin). Only
// writes when not already locked (pin_locked_until NULL or already past) —
// first writer wins, and repeated calls (a defensive re-lock after
// observing attempts already past the threshold, or continued guessing
// during an active lockout) never push the expiry further out. Without
// that guard, an attacker could keep an account locked indefinitely just
// by continuing to guess — exactly the kind of self-inflicted-on-the-victim
// denial-of-service this project already avoids elsewhere (see Ban's doc
// comment on why failed logins never auto-ban an account).
func (r *Repository) LockPin(ctx context.Context, id string, until time.Time) error {
	const q = `UPDATE users SET pin_locked_until = $2, updated_at = now() WHERE id = $1 AND (pin_locked_until IS NULL OR pin_locked_until <= now())`
	_, err := r.pool.Exec(ctx, q, id, until)
	if err != nil {
		return fmt.Errorf("locking pin: %w", err)
	}
	return nil
}

// ResetPinFailedAttemptsIfUnchanged clears the counter and any lock after a
// correct PIN — but only if pin_failed_attempts still matches expected (the
// value ReserveFailedPinAttempt returned for this same call). Without that
// guard, a correct guess racing against a separate wrong one that just
// crossed the threshold could silently clear the lock the wrong guess just
// set — this account really did just get a bad guess, even though a
// different, legitimate request also happened to succeed around the same
// moment. A no-op (not an error) when the guard doesn't match: the counter
// is simply left as whatever the interleaving request left it at.
func (r *Repository) ResetPinFailedAttemptsIfUnchanged(ctx context.Context, id string, expected int) error {
	const q = `UPDATE users SET pin_failed_attempts = 0, pin_locked_until = NULL, updated_at = now() WHERE id = $1 AND pin_failed_attempts = $2`
	_, err := r.pool.Exec(ctx, q, id, expected)
	if err != nil {
		return fmt.Errorf("resetting pin failed attempts: %w", err)
	}
	return nil
}

// ClearPinLockout resets id's PIN failed-attempt counter and lifts any
// active lock, without touching the PIN itself — see auth.Service.
// AdminClearLockouts. Unlike ResetPinFailedAttemptsIfUnchanged, this is an
// explicit admin action: there's no concurrent "correct guess" to race
// against, so it doesn't need the optimistic-concurrency guard. Distinct
// from ClearPin (which also deletes the PIN, the "I forgot my PIN" reset).
func (r *Repository) ClearPinLockout(ctx context.Context, id string) error {
	const q = `UPDATE users SET pin_failed_attempts = 0, pin_locked_until = NULL, updated_at = now() WHERE id = $1`
	_, err := r.pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("clearing pin lockout: %w", err)
	}
	return nil
}

// ClearPin removes id's account PIN entirely (admin reset) — see
// auth.Service.AdminResetPin, which also revokes the account's trusted
// devices and sessions alongside this.
func (r *Repository) ClearPin(ctx context.Context, id string) error {
	const q = `UPDATE users SET pin_hash = NULL, pin_set_at = NULL, pin_failed_attempts = 0, pin_locked_until = NULL, updated_at = now() WHERE id = $1`
	_, err := r.pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("clearing pin: %w", err)
	}
	return nil
}

// UpdateEmail replaces id's email and marks it verified — used once an
// admin-initiated email correction is confirmed (see auth.Service.
// ConfirmChangeEmail): the account just proved control of the new address
// by returning the code sent to it, so there's no reason to leave
// email_verified false afterward — getting an account unstuck that could
// never confirm its original, typo'd email is the whole point of that
// flow. The unique index on (api_client_id, email) is the actual guard
// against a race where someone else registered this email in the meantime
// — mapped to ErrEmailTaken via uniqueViolationErr, same as Register's
// username/rut conflicts.
func (r *Repository) UpdateEmail(ctx context.Context, id, newEmail string) error {
	const q = `UPDATE users SET email = $2, email_verified = TRUE, updated_at = now() WHERE id = $1`
	tag, err := r.pool.Exec(ctx, q, id, newEmail)
	if err != nil {
		if mapped := uniqueViolationErr(err); mapped != err {
			return mapped
		}
		return fmt.Errorf("updating email: %w", err)
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
