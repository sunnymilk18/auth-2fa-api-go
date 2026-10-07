package adminauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SessionRepository persists session-token hashes the same way
// auth.RefreshRepository persists refresh tokens: only a sha256 hash of
// the raw token is ever stored, so a database leak alone never yields a
// usable session — the raw token only ever exists in the httpOnly cookie
// on the admin's own browser and in the single response that set it.
type SessionRepository struct {
	pool *pgxpool.Pool
}

func NewSessionRepository(pool *pgxpool.Pool) *SessionRepository {
	return &SessionRepository{pool: pool}
}

func (r *SessionRepository) Store(ctx context.Context, adminAccountID, token string, expiresAt time.Time) error {
	const q = `
		INSERT INTO admin_sessions (admin_account_id, token_hash, expires_at)
		VALUES ($1, $2, $3)`
	_, err := r.pool.Exec(ctx, q, adminAccountID, hashSessionToken(token), expiresAt)
	if err != nil {
		return fmt.Errorf("storing admin session: %w", err)
	}
	return nil
}

// FindValidAccountID returns the admin_account_id a session token
// currently resolves to, or ("", false) if it's unknown, revoked, or
// expired — Service.ValidateSession also checks the account itself is
// still active, which this alone doesn't cover (a revoked account's old
// sessions are explicitly revoked by Service.RevokeAccount, but this
// method exists to check the session row in isolation).
func (r *SessionRepository) FindValidAccountID(ctx context.Context, token string) (adminAccountID string, ok bool, err error) {
	const q = `
		SELECT admin_account_id FROM admin_sessions
		WHERE token_hash = $1 AND revoked = FALSE AND expires_at > now()`
	err = r.pool.QueryRow(ctx, q, hashSessionToken(token)).Scan(&adminAccountID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("looking up admin session: %w", err)
	}
	return adminAccountID, true, nil
}

// Revoke invalidates a single session (logout).
func (r *SessionRepository) Revoke(ctx context.Context, token string) error {
	const q = `UPDATE admin_sessions SET revoked = TRUE, revoked_at = now() WHERE token_hash = $1`
	_, err := r.pool.Exec(ctx, q, hashSessionToken(token))
	if err != nil {
		return fmt.Errorf("revoking admin session: %w", err)
	}
	return nil
}

// RevokeAllForAccount invalidates every session an account currently
// holds — used when that account is itself revoked, so a stolen/leftover
// cookie stops working immediately rather than waiting out its TTL.
func (r *SessionRepository) RevokeAllForAccount(ctx context.Context, adminAccountID string) error {
	const q = `UPDATE admin_sessions SET revoked = TRUE, revoked_at = now() WHERE admin_account_id = $1 AND revoked = FALSE`
	_, err := r.pool.Exec(ctx, q, adminAccountID)
	if err != nil {
		return fmt.Errorf("revoking admin sessions for account: %w", err)
	}
	return nil
}

// RevokeAllForAccountExcept invalidates every session an account holds
// except exceptToken — used by self-service actions (password change,
// TOTP rotation) that deliberately keep the caller's own current session
// alive while killing every other one, unlike RevokeAllForAccount (used
// when an account is revoked or reactivated outright, where nothing
// should survive).
func (r *SessionRepository) RevokeAllForAccountExcept(ctx context.Context, adminAccountID, exceptToken string) error {
	const q = `UPDATE admin_sessions SET revoked = TRUE, revoked_at = now() WHERE admin_account_id = $1 AND revoked = FALSE AND token_hash != $2`
	_, err := r.pool.Exec(ctx, q, adminAccountID, hashSessionToken(exceptToken))
	if err != nil {
		return fmt.Errorf("revoking other admin sessions for account: %w", err)
	}
	return nil
}

// DeleteExpired removes rows that no longer serve any purpose — same
// retention shape as auth.RefreshRepository.DeleteExpired, meant to be
// called from the same periodic cleanup job.
func (r *SessionRepository) DeleteExpired(ctx context.Context) (int64, error) {
	const q = `DELETE FROM admin_sessions WHERE expires_at < now() OR revoked = TRUE`
	tag, err := r.pool.Exec(ctx, q)
	if err != nil {
		return 0, fmt.Errorf("deleting expired admin sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}

func hashSessionToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
