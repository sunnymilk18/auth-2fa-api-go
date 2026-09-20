package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// pendingLoginSession is the account a short-lived login_token resolves to,
// while something about the login is still pending (a TOTP code to verify,
// or a second-factor method to choose) — shared shape for both
// TOTPLoginStore and TwoFactorSetupStore, which otherwise differ only in
// which Redis key prefix (and so which pending state) they track.
type pendingLoginSession struct {
	UserID      string `json:"user_id"`
	APIClientID string `json:"api_client_id"`
	Email       string `json:"email"`
}

// pendingLoginStore is the generic login_token -> account mapping both
// TOTPLoginStore and TwoFactorSetupStore wrap — issue a token, look up the
// account without ending the session (Peek), and end it once whatever it
// was pending on actually completes (Consume). Unexported: callers use the
// two named wrapper types below, which keep the Redis key namespaces (and
// so the two pending states — "verify a TOTP code" vs "pick a method") from
// ever mixing, even though the underlying mechanics are identical.
type pendingLoginStore struct {
	rdb    *redis.Client
	ttl    time.Duration
	prefix string
}

func newPendingLoginStore(rdb *redis.Client, ttl time.Duration, prefix string) *pendingLoginStore {
	return &pendingLoginStore{rdb: rdb, ttl: ttl, prefix: prefix}
}

func (s *pendingLoginStore) startSession(ctx context.Context, userID, apiClientID, email string) (loginToken string, err error) {
	loginToken, err = generateToken(32)
	if err != nil {
		return "", fmt.Errorf("generating login token: %w", err)
	}

	sess := pendingLoginSession{UserID: userID, APIClientID: apiClientID, Email: email}
	data, err := json.Marshal(sess)
	if err != nil {
		return "", fmt.Errorf("marshaling pending login session: %w", err)
	}

	if err := s.rdb.Set(ctx, s.key(loginToken), data, s.ttl).Err(); err != nil {
		return "", fmt.Errorf("storing pending login session: %w", err)
	}
	return loginToken, nil
}

func (s *pendingLoginStore) peek(ctx context.Context, loginToken string) (sess pendingLoginSession, found bool, err error) {
	raw, err := s.rdb.Get(ctx, s.key(loginToken)).Bytes()
	if errors.Is(err, redis.Nil) {
		return pendingLoginSession{}, false, nil
	}
	if err != nil {
		return pendingLoginSession{}, false, fmt.Errorf("reading pending login session: %w", err)
	}
	if err := json.Unmarshal(raw, &sess); err != nil {
		return pendingLoginSession{}, false, fmt.Errorf("decoding pending login session: %w", err)
	}
	return sess, true, nil
}

func (s *pendingLoginStore) consume(ctx context.Context, loginToken string) error {
	return s.rdb.Del(ctx, s.key(loginToken)).Err()
}

func (s *pendingLoginStore) key(loginToken string) string {
	return s.prefix + loginToken
}
