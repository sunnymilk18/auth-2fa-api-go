package auth

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// TwoFactorSetupStore holds the short-lived login_token -> account mapping
// for an account's first-ever login, while it's waiting on the client to
// pick email or TOTP — see Service.LoginStep1's doc comment. A thin,
// distinctly-named wrapper around pendingLoginStore: mechanically identical
// to TOTPLoginStore, but kept as its own type deliberately — the two
// represent genuinely different pending states (one is "pick a method",
// the other is "verify a code against an already-chosen method"), and
// sharing one exported type (and so one Redis key prefix) would make that
// distinction easy to lose track of later, even though the underlying
// Redis mechanics (issue a token, peek, consume) are identical.
type TwoFactorSetupStore struct {
	*pendingLoginStore
}

func NewTwoFactorSetupStore(rdb *redis.Client, ttl time.Duration) *TwoFactorSetupStore {
	return &TwoFactorSetupStore{newPendingLoginStore(rdb, ttl, "2fa-setup:")}
}

// StartSession issues a fresh login token for an account whose password
// just checked out but has never chosen a second-factor method yet.
func (s *TwoFactorSetupStore) StartSession(ctx context.Context, userID, apiClientID, email string) (loginToken string, err error) {
	return s.startSession(ctx, userID, apiClientID, email)
}

// Peek reports whether loginToken belongs to a pending first-login setup
// and returns it without consuming it — both SendLoginEmailCode and
// EnrollTOTP's setup-flow path need to read the pending account without
// ending the session (the client might still switch which method it
// picks, e.g. request an email code, cancel, and try TOTP instead).
func (s *TwoFactorSetupStore) Peek(ctx context.Context, loginToken string) (sess pendingLoginSession, found bool, err error) {
	return s.peek(ctx, loginToken)
}

// Consume deletes the session — called once the account has committed to a
// method: right after an email code is actually sent under this same
// login_token (see Service.SendLoginEmailCode, which reuses the token for
// the resulting OTPStore session), or once TOTP enrollment is confirmed.
// After this, the token belongs to whichever verification flow took over,
// not to this store anymore.
func (s *TwoFactorSetupStore) Consume(ctx context.Context, loginToken string) error {
	return s.consume(ctx, loginToken)
}
