package auth

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// TOTPLoginStore holds the short-lived login_token -> account mapping for
// accounts using the TOTP second factor, mirroring OTPStore's role in the
// email-code flow but without a code to generate or send — the code is
// validated in Go against the account's decrypted secret (see
// Service.verifyTOTPLogin), not inside Redis. A thin, distinctly-named
// wrapper around pendingLoginStore (see its own doc comment for why this
// isn't just one shared exported type with TwoFactorSetupStore).
type TOTPLoginStore struct {
	*pendingLoginStore
}

func NewTOTPLoginStore(rdb *redis.Client, ttl time.Duration) *TOTPLoginStore {
	return &TOTPLoginStore{newPendingLoginStore(rdb, ttl, "totp:login:")}
}

// StartSession issues a fresh login token for an account that just passed
// password verification and has TOTP enabled — no code is generated or
// emailed; the client is expected to already have one from its
// authenticator app.
func (s *TOTPLoginStore) StartSession(ctx context.Context, userID, apiClientID, email string) (loginToken string, err error) {
	return s.startSession(ctx, userID, apiClientID, email)
}

// Peek reports whether loginToken belongs to a pending TOTP login (as
// opposed to the email-OTP flow — see Service.LoginStep2, which checks this
// first to decide which verification path a given token uses) and returns
// the pending session without consuming it.
func (s *TOTPLoginStore) Peek(ctx context.Context, loginToken string) (sess pendingLoginSession, found bool, err error) {
	return s.peek(ctx, loginToken)
}

// Consume deletes the session — called once a code has been verified, so
// the same login token can't be reused for a second token pair.
func (s *TOTPLoginStore) Consume(ctx context.Context, loginToken string) error {
	return s.consume(ctx, loginToken)
}
