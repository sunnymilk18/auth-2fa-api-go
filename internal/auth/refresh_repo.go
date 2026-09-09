package auth

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

var ErrRefreshTokenInvalid = errors.New("refresh token invalid, expired or revoked")

// RefreshRepository persists refresh-token hashes so they can be revoked
// (logout, password reset, compromise) without waiting for JWT expiry.
type RefreshRepository struct {
	pool *pgxpool.Pool
}

func NewRefreshRepository(pool *pgxpool.Pool) *RefreshRepository {
	return &RefreshRepository{pool: pool}
}

func (r *RefreshRepository) Store(ctx context.Context, userID, token string, expiresAt time.Time) error {
	const q = `
		INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)`
	_, err := r.pool.Exec(ctx, q, userID, hashToken(token), expiresAt)
	if err != nil {
		return fmt.Errorf("storing refresh token: %w", err)
	}
	return nil
}

// IsValid checks the token hash exists, is not revoked and not expired.
func (r *RefreshRepository) IsValid(ctx context.Context, token string) (bool, error) {
	const q = `
		SELECT revoked, expires_at FROM refresh_tokens WHERE token_hash = $1`

	var revoked bool
	var expiresAt time.Time
	err := r.pool.QueryRow(ctx, q, hashToken(token)).Scan(&revoked, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("checking refresh token: %w", err)
	}
	if revoked || time.Now().After(expiresAt) {
		return false, nil
	}
	return true, nil
}

// Revoke invalidates a single refresh token (e.g. after it's used once, or on logout).
func (r *RefreshRepository) Revoke(ctx context.Context, token string) error {
	const q = `UPDATE refresh_tokens SET revoked = TRUE WHERE token_hash = $1`
	_, err := r.pool.Exec(ctx, q, hashToken(token))
	if err != nil {
		return fmt.Errorf("revoking refresh token: %w", err)
	}
	return nil
}

// RevokeAllForUser invalidates every refresh token userID currently holds —
// used by the password reset flow to force re-authentication everywhere,
// in case the reset was triggered by a compromised session.
func (r *RefreshRepository) RevokeAllForUser(ctx context.Context, userID string) error {
	const q = `UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1 AND revoked = FALSE`
	_, err := r.pool.Exec(ctx, q, userID)
	if err != nil {
		return fmt.Errorf("revoking all refresh tokens for user: %w", err)
	}
	return nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
