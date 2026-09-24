package device

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidPin       = errors.New("invalid pin")
	ErrDeviceNotTrusted = errors.New("device not trusted, please login again")
	ErrTooManyPinTries  = errors.New("too many failed pin attempts, device trust revoked")
	ErrInvalidPinFormat = errors.New("pin must be exactly 6 digits")
	pinPattern          = regexp.MustCompile(`^\d{6}$`)
)

type Service struct {
	repo        *Repository
	trustTTL    time.Duration
	maxPinTries int
}

func NewService(repo *Repository, trustTTL time.Duration, maxPinTries int) *Service {
	return &Service{repo: repo, trustTTL: trustTTL, maxPinTries: maxPinTries}
}

// Register (re)marks deviceID as trusted for userID, setting a fresh PIN and
// returning a new device token in plain text — the caller must hand it to
// the client exactly once; only its hash is ever stored.
func (s *Service) Register(ctx context.Context, userID, deviceID, deviceName, pin string) (deviceToken string, err error) {
	if !pinPattern.MatchString(pin) {
		return "", ErrInvalidPinFormat
	}

	pinHash, err := bcrypt.GenerateFromPassword([]byte(pin), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hashing pin: %w", err)
	}

	deviceToken, err = generateToken(32)
	if err != nil {
		return "", fmt.Errorf("generating device token: %w", err)
	}

	_, err = s.repo.Upsert(ctx, userID, deviceID, deviceName, hashToken(deviceToken), string(pinHash), time.Now().Add(s.trustTTL))
	if err != nil {
		return "", err
	}

	return deviceToken, nil
}

// VerifyPin checks device_token + pin for deviceID. On success it rotates
// the device token (the caller MUST hand newDeviceToken back to the client
// to replace its stored copy — the old one stops working), extends the
// trust window, and returns the owning user.
func (s *Service) VerifyPin(ctx context.Context, deviceID, deviceToken, pin string) (userID, newDeviceToken string, err error) {
	d, err := s.repo.FindByDeviceID(ctx, deviceID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return "", "", ErrDeviceNotTrusted
		}
		return "", "", err
	}

	if d.Revoked || time.Now().After(d.ExpiresAt) {
		return "", "", ErrDeviceNotTrusted
	}

	if d.DeviceTokenHash != hashToken(deviceToken) {
		return "", "", ErrDeviceNotTrusted
	}

	if err := bcrypt.CompareHashAndPassword([]byte(d.PinHash), []byte(pin)); err != nil {
		attempts, incErr := s.repo.IncrementFailedAttempts(ctx, d.ID)
		if incErr != nil {
			return "", "", incErr
		}
		if attempts >= s.maxPinTries {
			_ = s.repo.Revoke(ctx, d.ID)
			return "", "", ErrTooManyPinTries
		}
		return "", "", ErrInvalidPin
	}

	newDeviceToken, err = generateToken(32)
	if err != nil {
		return "", "", fmt.Errorf("generating device token: %w", err)
	}
	if err := s.repo.MarkSuccess(ctx, d.ID, hashToken(newDeviceToken), time.Now().Add(s.trustTTL)); err != nil {
		return "", "", err
	}

	return d.UserID, newDeviceToken, nil
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
