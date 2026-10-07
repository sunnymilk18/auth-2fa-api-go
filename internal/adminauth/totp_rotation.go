package adminauth

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// totpRotationTTL bounds how long a pending TOTP rotation (Service.
// StartTOTPRotation, not yet confirmed) stays usable — long enough to
// scan a QR code and type a 6-digit code, short enough that an abandoned
// rotation doesn't linger forever. Not configurable: this is an internal
// implementation detail of the self-service flow, not something an
// operator needs to tune.
const totpRotationTTL = 10 * time.Minute

// TOTPRotationStore holds, in Redis, the one TOTP secret an admin account
// has generated but not yet confirmed — see Service.StartTOTPRotation/
// ConfirmTOTPRotation. Short-lived by nature (unlike the account's actual
// totp_secret_enc column in Postgres), same reasoning as every other
// short-lived code/secret in this codebase (auth.OTPStore, auth.
// ChangeEmailStore, ...): nothing here is meant to outlive totpRotationTTL.
type TOTPRotationStore struct {
	rdb *redis.Client
}

func NewTOTPRotationStore(rdb *redis.Client) *TOTPRotationStore {
	return &TOTPRotationStore{rdb: rdb}
}

func (s *TOTPRotationStore) pendingKey(accountID string) string {
	return "admin:totp_rotate:pending:" + accountID
}

// SetPending stores secretEnc (already encrypted — see auth.TOTPManager.
// Encrypt) as accountID's one pending rotation, silently replacing any
// previous pending rotation for the same account — Service.
// StartTOTPRotation calling this twice in a row is "start over", not an
// error, matching what a person restarting the flow from scratch expects.
func (s *TOTPRotationStore) SetPending(ctx context.Context, accountID, secretEnc string) error {
	if err := s.rdb.Set(ctx, s.pendingKey(accountID), secretEnc, totpRotationTTL).Err(); err != nil {
		return fmt.Errorf("storing pending totp rotation: %w", err)
	}
	return nil
}

// GetPending reads accountID's pending rotation without consuming it —
// deliberately NOT deleted here, so a wrong confirmation code (see
// Service.ConfirmTOTPRotation) doesn't force restarting the whole flow;
// only ClearPending, called once the code actually validates, removes it.
// ok is false whether the account never started one, already confirmed
// it, or it expired — these are indistinguishable on purpose, same "don't
// leak which" reasoning as adminauth.ErrInvalidCredentials.
func (s *TOTPRotationStore) GetPending(ctx context.Context, accountID string) (secretEnc string, ok bool, err error) {
	val, err := s.rdb.Get(ctx, s.pendingKey(accountID)).Result()
	if err == redis.Nil {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("reading pending totp rotation: %w", err)
	}
	return val, true, nil
}

// ClearPending removes accountID's pending rotation — called once it's
// been confirmed (so it can't be confirmed a second time) or, in
// principle, could be called to cancel one outright, though no caller
// does that today.
func (s *TOTPRotationStore) ClearPending(ctx context.Context, accountID string) error {
	if err := s.rdb.Del(ctx, s.pendingKey(accountID)).Err(); err != nil {
		return fmt.Errorf("clearing pending totp rotation: %w", err)
	}
	return nil
}
