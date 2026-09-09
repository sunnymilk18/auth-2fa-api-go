package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var ErrPasswordResetTokenInvalid = errors.New("password reset token invalid or expired")

// passwordResetSession is what we keep in Redis between "reset requested"
// and "reset confirmed".
type passwordResetSession struct {
	UserID      string `json:"user_id"`
	APIClientID string `json:"api_client_id"`
}

// PasswordResetStore manages short-lived, single-use password reset tokens
// in Redis — same rationale as OTPStore: high-churn, short-lived data that
// doesn't belong in the durable DB.
type PasswordResetStore struct {
	rdb *redis.Client
	ttl time.Duration
}

func NewPasswordResetStore(rdb *redis.Client, ttl time.Duration) *PasswordResetStore {
	return &PasswordResetStore{rdb: rdb, ttl: ttl}
}

// StartReset generates a fresh, high-entropy reset token and stores it,
// scoped to userID/apiClientID, for ttl. Unlike the OTP login code, this
// token IS the entire secret — there's no separate low-entropy code plus a
// session pointer, since a 256-bit random value is already infeasible to
// brute-force, so it doubles as both directly (mirroring how
// login_token/device_token are already used elsewhere in this package).
func (s *PasswordResetStore) StartReset(ctx context.Context, userID, apiClientID string) (token string, err error) {
	token, err = generateToken(32)
	if err != nil {
		return "", fmt.Errorf("generating password reset token: %w", err)
	}

	data, err := json.Marshal(passwordResetSession{UserID: userID, APIClientID: apiClientID})
	if err != nil {
		return "", fmt.Errorf("marshaling password reset session: %w", err)
	}

	if err := s.rdb.Set(ctx, resetKey(token), data, s.ttl).Err(); err != nil {
		return "", fmt.Errorf("storing password reset session: %w", err)
	}

	return token, nil
}

// ConsumeToken atomically fetches and deletes the reset session for token —
// single-use: a second call with the same token always fails, even if the
// caller's subsequent password update fails for some unrelated reason
// (fails closed rather than leaving a reusable token around).
func (s *PasswordResetStore) ConsumeToken(ctx context.Context, token string) (userID, apiClientID string, err error) {
	raw, err := s.rdb.GetDel(ctx, resetKey(token)).Bytes()
	if errors.Is(err, redis.Nil) {
		return "", "", ErrPasswordResetTokenInvalid
	}
	if err != nil {
		return "", "", fmt.Errorf("fetching password reset session: %w", err)
	}

	var sess passwordResetSession
	if err := json.Unmarshal(raw, &sess); err != nil {
		return "", "", fmt.Errorf("unmarshaling password reset session: %w", err)
	}

	return sess.UserID, sess.APIClientID, nil
}

func resetKey(token string) string {
	return "password_reset:" + token
}
