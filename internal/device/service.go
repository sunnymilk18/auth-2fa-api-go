package device

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

var ErrDeviceNotTrusted = errors.New("device not trusted, please login again")

type Service struct {
	repo     *Repository
	trustTTL time.Duration
}

func NewService(repo *Repository, trustTTL time.Duration) *Service {
	return &Service{repo: repo, trustTTL: trustTTL}
}

// Register (re)marks deviceID as trusted for userID and returns a new
// device token in plain text — the caller must hand it to the client
// exactly once; only its hash is ever stored. The PIN that gates this
// device lives on the account, not here — see auth.Service.RegisterDevice,
// which checks/sets it (via user.Service.EnsurePin) before calling this.
func (s *Service) Register(ctx context.Context, userID, deviceID, deviceName string) (deviceToken string, err error) {
	deviceToken, err = generateToken(32)
	if err != nil {
		return "", fmt.Errorf("generating device token: %w", err)
	}

	_, err = s.repo.Upsert(ctx, userID, deviceID, deviceName, hashToken(deviceToken), time.Now().Add(s.trustTTL))
	if err != nil {
		return "", err
	}

	return deviceToken, nil
}

// VerifyToken checks deviceID/deviceToken (possession) only — not the
// account PIN (knowledge), which the caller (auth.Service.DeviceLogin)
// checks separately via user.Service.VerifyPin before calling RotateToken
// below. Splitting these two steps lets the PIN check's own failed-attempt
// lockout apply even when the device_token itself was never in question.
func (s *Service) VerifyToken(ctx context.Context, deviceID, deviceToken string) (*Device, error) {
	d, err := s.repo.FindByDeviceID(ctx, deviceID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrDeviceNotTrusted
		}
		return nil, err
	}

	if d.Revoked || time.Now().After(d.ExpiresAt) {
		return nil, ErrDeviceNotTrusted
	}
	if d.DeviceTokenHash != hashToken(deviceToken) {
		return nil, ErrDeviceNotTrusted
	}

	return d, nil
}

// RotateToken issues a fresh device token for id and extends the trust
// window (sliding expiration) — called once the account PIN gating id has
// already checked out (see VerifyToken above). The caller MUST hand the
// returned token back to the client to replace its stored copy; the old
// one stops working.
func (s *Service) RotateToken(ctx context.Context, id string) (newDeviceToken string, err error) {
	newDeviceToken, err = generateToken(32)
	if err != nil {
		return "", fmt.Errorf("generating device token: %w", err)
	}
	if err := s.repo.MarkSuccess(ctx, id, hashToken(newDeviceToken), time.Now().Add(s.trustTTL)); err != nil {
		return "", err
	}
	return newDeviceToken, nil
}

func (s *Service) List(ctx context.Context, userID string) ([]Info, error) {
	return s.repo.ListByUser(ctx, userID)
}

// EnablePush records id's Firebase Cloud Messaging token, opting an already
// trusted device into push-notification login approval. id must already be
// a trusted device belonging to userID (see Register) — push rides on the
// same pairing as PIN unlock, not a separate registration step.
func (s *Service) EnablePush(ctx context.Context, userID, id, pushToken string) error {
	return s.repo.SetPushToken(ctx, id, userID, pushToken)
}

// DisablePush clears id's push token, opting it back out of push-notification
// login approval — the device itself (PIN unlock, trust) is untouched;
// this only ever turns push off, never revokes the device the way Revoke
// does. Lets someone turn push off without losing their PIN shortcut, the
// same way EnablePush lets them turn it on without a separate pairing step.
func (s *Service) DisablePush(ctx context.Context, userID, id string) error {
	return s.repo.SetPushToken(ctx, id, userID, "")
}

// PushCapableDevices returns userID's trusted devices that have opted in to
// push approval — see Repository.FindPushCapableByUser.
func (s *Service) PushCapableDevices(ctx context.Context, userID string) ([]Device, error) {
	return s.repo.FindPushCapableByUser(ctx, userID)
}

func (s *Service) Revoke(ctx context.Context, userID, id string) error {
	return s.repo.RevokeOwned(ctx, id, userID)
}

// RevokeAllForUser revokes every trusted device belonging to userID. See
// Repository.RevokeAllForUser for why the password reset flow needs this.
func (s *Service) RevokeAllForUser(ctx context.Context, userID string) error {
	return s.repo.RevokeAllForUser(ctx, userID)
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func generateToken(numBytes int) (string, error) {
	b := make([]byte, numBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
