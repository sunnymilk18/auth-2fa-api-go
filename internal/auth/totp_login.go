package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// totpLoginSession is what TOTPLoginStore keeps in Redis between "password
// verified" and "TOTP code verified" — deliberately much thinner than
// loginSession (see otp.go): there's no code to store here, since nothing
// is generated/emailed server-side for this path. The code itself is
// validated in Go against the account's decrypted secret (see
// auth.Service.verifyTOTPLogin), not inside Redis.
type totpLoginSession struct {
	UserID      string `json:"user_id"`
	APIClientID string `json:"api_client_id"`
	Email       string `json:"email"`
}

// TOTPLoginStore holds the short-lived login_token -> account mapping for
// accounts using the TOTP second factor, mirroring OTPStore's role in the
// email-code flow but without a code to generate or send.
type TOTPLoginStore struct {
	rdb *redis.Client
	ttl time.Duration
}

func NewTOTPLoginStore(rdb *redis.Client, ttl time.Duration) *TOTPLoginStore {
	return &TOTPLoginStore{rdb: rdb, ttl: ttl}
}

// StartSession issues a fresh login token for an account that just passed
// password verification and has TOTP enabled — no code is generated or
// emailed; the client is expected to already have one from its
// authenticator app.
func (s *TOTPLoginStore) StartSession(ctx context.Context, userID, apiClientID, email string) (loginToken string, err error) {
	loginToken, err = generateToken(32)
	if err != nil {
		return "", fmt.Errorf("generating login token: %w", err)
	}

	sess := totpLoginSession{UserID: userID, APIClientID: apiClientID, Email: email}
	data, err := json.Marshal(sess)
	if err != nil {
		return "", fmt.Errorf("marshaling totp login session: %w", err)
	}

	if err := s.rdb.Set(ctx, s.key(loginToken), data, s.ttl).Err(); err != nil {
		return "", fmt.Errorf("storing totp login session: %w", err)
	}
	return loginToken, nil
}

// Peek reports whether loginToken belongs to a pending TOTP login (as
// opposed to the email-OTP flow — see Service.LoginStep2, which checks this
// first to decide which verification path a given token uses) and returns
// the pending session without consuming it.
func (s *TOTPLoginStore) Peek(ctx context.Context, loginToken string) (sess totpLoginSession, found bool, err error) {
	raw, err := s.rdb.Get(ctx, s.key(loginToken)).Bytes()
	if errors.Is(err, redis.Nil) {
		return totpLoginSession{}, false, nil
	}
	if err != nil {
		return totpLoginSession{}, false, fmt.Errorf("reading totp login session: %w", err)
	}
	if err := json.Unmarshal(raw, &sess); err != nil {
		return totpLoginSession{}, false, fmt.Errorf("decoding totp login session: %w", err)
	}
	return sess, true, nil
}

// Consume deletes the session — called once a code has been verified, so
// the same login token can't be reused for a second token pair.
func (s *TOTPLoginStore) Consume(ctx context.Context, loginToken string) error {
	return s.rdb.Del(ctx, s.key(loginToken)).Err()
}

func (s *TOTPLoginStore) key(loginToken string) string {
	return "totp:login:" + loginToken
}
