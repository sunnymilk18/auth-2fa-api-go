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

// revokedRetentionWindow is how long a revoked-but-not-yet-expired
// refresh_tokens row is kept around before DeleteExpired purges it —
// deliberately not instant (see ConsumeIfValid's doc comment on why a
// revoked row still needs to exist for a little while) and deliberately
// much shorter than REFRESH_TOKEN_TTL (up to 7 days by default): a stolen
// token being replayed is almost always tried within hours, not a week
// later, so this keeps the table from carrying dead rows far longer than
// that signal is actually useful for.
const revokedRetentionWindow = 48 * time.Hour

// reuseDetectionGracePeriod is how long after a token is revoked its reuse
// is still treated as harmless — several browser tabs on one account
// racing to refresh the same token, or a client retrying a request whose
// response got dropped, both resolve within milliseconds, well inside
// this window. A real stolen token essentially never gets replayed inside
// the same few seconds an entirely unrelated legitimate rotation already
// happened — it's used later, by someone who obtained a copy some other
// way — so only a reuse *past* this window is treated as suspicious (see
// CheckReuse). Without this grace period, that same benign multi-tab race
// would look identical to a real theft and needlessly log a real user out
// of every device.
const reuseDetectionGracePeriod = 10 * time.Second

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

// ConsumeIfValid atomically checks a token is valid (exists, not revoked,
// not expired) and marks it revoked in the same statement — used by
// Service.Refresh's rotation instead of a separate check-then-revoke pair,
// which had a real race: two near-simultaneous requests with the same
// token (several browser tabs open on the same account, a client retrying
// after a dropped response) could otherwise both pass the check before
// either one's revoke landed, letting the same refresh token mint two
// token pairs. The UPDATE's WHERE clause is the entire check — only the
// request that actually flips revoked=FALSE to TRUE gets true back, so at
// most one of any concurrent callers ever succeeds.
//
// Returns false (no error) for a token that's unknown, expired, or already
// revoked — same "not valid" signal the old separate IsValid gave, just
// atomic with the revoke. Deliberately still revokes-in-place rather than
// deleting the row outright: keeping it (briefly — see revokedRetentionWindow)
// is what would let a reused/stolen copy of this exact token be recognized
// as "already used" instead of indistinguishable from "never existed".
func (r *RefreshRepository) ConsumeIfValid(ctx context.Context, token string) (bool, error) {
	const q = `
		UPDATE refresh_tokens
		SET revoked = TRUE, revoked_at = now()
		WHERE token_hash = $1 AND revoked = FALSE AND expires_at > now()`
	tag, err := r.pool.Exec(ctx, q, hashToken(token))
	if err != nil {
		return false, fmt.Errorf("consuming refresh token: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// CheckReuse looks up token regardless of its current state — called only
// once ConsumeIfValid has already failed, to tell a completely harmless
// "not valid" (an unknown token, or one that's simply expired) apart from
// a genuinely suspicious one: a token that exists, is revoked, and was
// revoked more than reuseDetectionGracePeriod ago (see its own doc comment
// for why that grace period exists — a benign near-simultaneous double-use
// of the same token must never be mistaken for a stolen one being
// replayed). suspicious == true means Service.Refresh should treat this as
// a likely account compromise and revoke everything for userID, not just
// reject this one request.
func (r *RefreshRepository) CheckReuse(ctx context.Context, token string) (userID string, suspicious bool, err error) {
	const q = `SELECT user_id, revoked, revoked_at FROM refresh_tokens WHERE token_hash = $1`

	var revoked bool
	var revokedAt *time.Time
	err = r.pool.QueryRow(ctx, q, hashToken(token)).Scan(&userID, &revoked, &revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("checking refresh token reuse: %w", err)
	}
	if !revoked || revokedAt == nil {
		// Not revoked at all (only reachable here if it was expired, since
		// ConsumeIfValid already ruled out "still valid") — nothing
		// suspicious, expiry isn't a sign of theft.
		return "", false, nil
	}
	return userID, time.Since(*revokedAt) > reuseDetectionGracePeriod, nil
}

// Revoke invalidates a single refresh token (e.g. on logout) — unlike
// ConsumeIfValid, the caller here already knows the token belongs to the
// session being logged out and isn't relying on the result to decide
// anything, so a plain unconditional update is enough.
func (r *RefreshRepository) Revoke(ctx context.Context, token string) error {
	const q = `UPDATE refresh_tokens SET revoked = TRUE, revoked_at = now() WHERE token_hash = $1`
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
	const q = `UPDATE refresh_tokens SET revoked = TRUE, revoked_at = now() WHERE user_id = $1 AND revoked = FALSE`
	_, err := r.pool.Exec(ctx, q, userID)
	if err != nil {
		return fmt.Errorf("revoking all refresh tokens for user: %w", err)
	}
	return nil
}

// DeleteExpired removes every refresh_tokens row that no longer serves any
// purpose: one whose expires_at has already passed (expired rows are
// otherwise never removed — ConsumeIfValid just rejects them, it doesn't
// clean up), or one that was revoked more than revokedRetentionWindow ago
// (see its own doc comment for why that's a short window, not instant).
// Returns how many rows were deleted, for logging.
func (r *RefreshRepository) DeleteExpired(ctx context.Context) (int64, error) {
	const q = `
		DELETE FROM refresh_tokens
		WHERE expires_at < now()
		   OR (revoked = TRUE AND revoked_at < $1)`
	tag, err := r.pool.Exec(ctx, q, time.Now().Add(-revokedRetentionWindow))
	if err != nil {
		return 0, fmt.Errorf("deleting expired refresh tokens: %w", err)
	}
	return tag.RowsAffected(), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
