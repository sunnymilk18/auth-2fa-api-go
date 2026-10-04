package auth

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// PinLoginStore holds the pin_token an account with PinRequiredAtLogin gets
// back once its password + second factor already checked out, instead of a
// token pair — see Service.LoginResult and Service.LoginPinStep. Same
// generic login_token -> account mapping as TOTPLoginStore/
// TwoFactorSetupStore, just its own Redis key namespace.
type PinLoginStore struct {
	*pendingLoginStore
}

func NewPinLoginStore(rdb *redis.Client, ttl time.Duration) *PinLoginStore {
	return &PinLoginStore{newPendingLoginStore(rdb, ttl, "pin:login:")}
}

// StartSession issues a fresh pin_token for an account whose password and
// second factor already checked out and that requires the extra PIN step
// before any token is issued.
func (s *PinLoginStore) StartSession(ctx context.Context, userID, apiClientID, email string) (pinToken string, err error) {
	return s.startSession(ctx, userID, apiClientID, email)
}

// Peek resolves pinToken to the account it belongs to without consuming it
// — a wrong PIN attempt must not burn the token (see LoginPinStep's doc
// comment: the same pin_token is reusable across several attempts, up to
// the account PIN's own shared lockout).
func (s *PinLoginStore) Peek(ctx context.Context, pinToken string) (sess pendingLoginSession, found bool, err error) {
	return s.peek(ctx, pinToken)
}

// Consume deletes the session — called once the PIN step actually
// succeeds, right before tokens are issued, so pinToken can never be
// reused afterward.
func (s *PinLoginStore) Consume(ctx context.Context, pinToken string) error {
	return s.consume(ctx, pinToken)
}
