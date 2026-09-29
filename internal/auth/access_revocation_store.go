package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// AccessRevocationStore closes a gap plain JWT verification can't:
// revoking a refresh token (or banning an account) never touches any
// access token already issued — it's a stateless RS256 JWT, good on its
// signature and expiry alone until it lapses on its own, up to
// ACCESS_TOKEN_TTL later (see middleware.RequireAuth, which only checked
// that before this existed). This is what makes a ban/revoke-sessions/
// password-reset take effect on an already-issued access token
// immediately, not just on the next refresh.
//
// Keyed by user, not by individual token: a single "nothing issued before
// this instant is trusted anymore" marker per account, not a per-token
// blocklist — every access token already carries its own IssuedAt, so
// comparing against one cutoff is all a check needs, and it's one Redis
// key regardless of how many tokens/devices the account has.
type AccessRevocationStore struct {
	rdb *redis.Client
	ttl time.Duration
}

// NewAccessRevocationStore — ttl should match ACCESS_TOKEN_TTL: once that
// much time has passed since a marker was set, every token issued before
// it has already expired under its own steam anyway, so the marker has
// nothing left to protect against and can be forgotten. Redis expires it
// on its own; nothing else needs to clean this up.
func NewAccessRevocationStore(rdb *redis.Client, ttl time.Duration) *AccessRevocationStore {
	return &AccessRevocationStore{rdb: rdb, ttl: ttl}
}

func (s *AccessRevocationStore) key(userID string) string {
	return "access-revoked-since:" + userID
}

// MarkRevoked records that every access token userID currently holds
// should no longer be trusted, from this instant on — call alongside
// wherever refresh tokens are also revoked wholesale (AdminBanUser,
// AdminRevokeAllSessions, ResetPassword), never for a single-token
// action like Logout: Logout only revokes the one refresh token behind
// it, and burning every other access token the account has open on
// every other device just because one session logged out would be a
// regression, not a feature.
func (s *AccessRevocationStore) MarkRevoked(ctx context.Context, userID string) error {
	if err := s.rdb.Set(ctx, s.key(userID), time.Now().UnixMilli(), s.ttl).Err(); err != nil {
		return fmt.Errorf("marking access tokens revoked: %w", err)
	}
	return nil
}

// IsRevoked reports whether a token issued at issuedAt should be rejected
// — true only when userID has a marker and issuedAt is at or before it. No
// marker (by far the common case: this account was never force-revoked,
// or its marker already expired) means nothing to check, so this returns
// false without treating a Redis miss as an error.
func (s *AccessRevocationStore) IsRevoked(ctx context.Context, userID string, issuedAt time.Time) (bool, error) {
	revokedSinceMillis, err := s.rdb.Get(ctx, s.key(userID)).Int64()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("checking access token revocation: %w", err)
	}
	revokedSince := time.UnixMilli(revokedSinceMillis)
	return !issuedAt.After(revokedSince), nil
}
