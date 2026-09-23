package device

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotFound = errors.New("trusted device not found")

type Repository struct {
	pool *pgxpool.Pool
}

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

// Upsert registers a device as trusted, or re-registers it (new token, new
// pin, fresh expiry) if the same device_id already existed — registering a
// device is idempotent from the client's point of view.
func (r *Repository) Upsert(ctx context.Context, userID, deviceID, deviceName, deviceTokenHash, pinHash string, expiresAt time.Time) (*Device, error) {
	const q = `
		INSERT INTO trusted_devices (user_id, device_id, device_name, device_token_hash, pin_hash, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (device_id) DO UPDATE SET
			user_id = EXCLUDED.user_id,
			device_name = EXCLUDED.device_name,
			device_token_hash = EXCLUDED.device_token_hash,
			pin_hash = EXCLUDED.pin_hash,
			failed_pin_attempts = 0,
			revoked = FALSE,
			trusted_at = now(),
			last_used_at = now(),
			expires_at = EXCLUDED.expires_at,
			updated_at = now()
		RETURNING id, user_id, device_id, device_name, device_token_hash, pin_hash,
			failed_pin_attempts, revoked, trusted_at, last_used_at, expires_at, created_at, updated_at`

	d := &Device{}
	err := r.pool.QueryRow(ctx, q, userID, deviceID, deviceName, deviceTokenHash, pinHash, expiresAt).Scan(
		&d.ID, &d.UserID, &d.DeviceID, &d.DeviceName, &d.DeviceTokenHash, &d.PinHash,
		&d.FailedPinAttempts, &d.Revoked, &d.TrustedAt, &d.LastUsedAt, &d.ExpiresAt, &d.CreatedAt, &d.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("upserting trusted device: %w", err)
	}
	return d, nil
}

func (r *Repository) FindByDeviceID(ctx context.Context, deviceID string) (*Device, error) {
	const q = `
		SELECT id, user_id, device_id, device_name, device_token_hash, pin_hash,
			failed_pin_attempts, revoked, COALESCE(push_token, ''), trusted_at, last_used_at, expires_at, created_at, updated_at
		FROM trusted_devices WHERE device_id = $1`

	d := &Device{}
	err := r.pool.QueryRow(ctx, q, deviceID).Scan(
		&d.ID, &d.UserID, &d.DeviceID, &d.DeviceName, &d.DeviceTokenHash, &d.PinHash,
		&d.FailedPinAttempts, &d.Revoked, &d.PushToken, &d.TrustedAt, &d.LastUsedAt, &d.ExpiresAt, &d.CreatedAt, &d.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("querying trusted device: %w", err)
	}
	return d, nil
}

// SetPushToken records deviceID's Firebase Cloud Messaging token — called
// when its user opts in to push-notification login approval from an
// already-authenticated session (see auth.Service.EnablePushApproval).
// Scoped to userID so one user can't register a push token onto a device
// they don't own by guessing its id.
func (r *Repository) SetPushToken(ctx context.Context, id, userID, pushToken string) error {
	const q = `UPDATE trusted_devices SET push_token = $3, updated_at = now() WHERE id = $1 AND user_id = $2`
	tag, err := r.pool.Exec(ctx, q, id, userID, pushToken)
	if err != nil {
		return fmt.Errorf("setting device push token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// FindPushCapableByUser returns every non-revoked, non-expired device for
// userID that has opted in to push approval (push_token set) — usually one,
// but nothing stops an account from enabling it on more than one device.
// auth.Service.StartPushLogin notifies all of them and accepts whichever
// answers first.
func (r *Repository) FindPushCapableByUser(ctx context.Context, userID string) ([]Device, error) {
	const q = `
		SELECT id, user_id, device_id, device_name, device_token_hash, pin_hash,
			failed_pin_attempts, revoked, push_token, trusted_at, last_used_at, expires_at, created_at, updated_at
		FROM trusted_devices
		WHERE user_id = $1 AND revoked = FALSE AND expires_at > now() AND push_token IS NOT NULL AND push_token != ''`

	rows, err := r.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("listing push-capable devices: %w", err)
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var d Device
		if err := rows.Scan(
			&d.ID, &d.UserID, &d.DeviceID, &d.DeviceName, &d.DeviceTokenHash, &d.PinHash,
			&d.FailedPinAttempts, &d.Revoked, &d.PushToken, &d.TrustedAt, &d.LastUsedAt, &d.ExpiresAt, &d.CreatedAt, &d.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning push-capable device: %w", err)
		}
		devices = append(devices, d)
	}
	return devices, rows.Err()
}

func (r *Repository) ListByUser(ctx context.Context, userID string) ([]Info, error) {
	const q = `
		SELECT id, device_name, trusted_at, last_used_at, expires_at
		FROM trusted_devices
		WHERE user_id = $1 AND revoked = FALSE
		ORDER BY last_used_at DESC`

	rows, err := r.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("listing trusted devices: %w", err)
	}
	defer rows.Close()

	var infos []Info
	for rows.Next() {
		var i Info
		if err := rows.Scan(&i.ID, &i.DeviceName, &i.TrustedAt, &i.LastUsedAt, &i.ExpiresAt); err != nil {
			return nil, fmt.Errorf("scanning trusted device: %w", err)
		}
		infos = append(infos, i)
	}
	return infos, rows.Err()
}

// MarkSuccess rotates the device token, resets the failed-attempt counter,
// and extends the trust window (sliding expiration).
func (r *Repository) MarkSuccess(ctx context.Context, id, newDeviceTokenHash string, newExpiresAt time.Time) error {
	const q = `
		UPDATE trusted_devices
		SET device_token_hash = $2, failed_pin_attempts = 0, last_used_at = now(),
			expires_at = $3, updated_at = now()
		WHERE id = $1`
	_, err := r.pool.Exec(ctx, q, id, newDeviceTokenHash, newExpiresAt)
	if err != nil {
		return fmt.Errorf("marking trusted device success: %w", err)
	}
	return nil
}

// IncrementFailedAttempts bumps the counter and returns the new value.
func (r *Repository) IncrementFailedAttempts(ctx context.Context, id string) (int, error) {
	const q = `
		UPDATE trusted_devices SET failed_pin_attempts = failed_pin_attempts + 1, updated_at = now()
		WHERE id = $1
		RETURNING failed_pin_attempts`
	var attempts int
	if err := r.pool.QueryRow(ctx, q, id).Scan(&attempts); err != nil {
		return 0, fmt.Errorf("incrementing failed pin attempts: %w", err)
	}
	return attempts, nil
}

// Revoke invalidates a device unconditionally (used for lockouts after too
// many failed PIN attempts).
func (r *Repository) Revoke(ctx context.Context, id string) error {
	const q = `UPDATE trusted_devices SET revoked = TRUE, updated_at = now() WHERE id = $1`
	_, err := r.pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("revoking trusted device: %w", err)
	}
	return nil
}

// RevokeOwned revokes a device only if it belongs to userID — used by the
// user-facing "remove this device" endpoint so one user can't revoke
// another's device by guessing an id.
func (r *Repository) RevokeOwned(ctx context.Context, id, userID string) error {
	const q = `UPDATE trusted_devices SET revoked = TRUE, updated_at = now() WHERE id = $1 AND user_id = $2`
	tag, err := r.pool.Exec(ctx, q, id, userID)
	if err != nil {
		return fmt.Errorf("revoking trusted device: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RevokeAllForUser revokes every trusted device userID has — used by the
// password reset flow: the trusted-device+PIN shortcut bypasses
// password+OTP entirely, so leaving it intact after a reset would let
// whoever set it up (possibly an attacker, during whatever compromise
// prompted the reset) keep getting in regardless of the new password.
func (r *Repository) RevokeAllForUser(ctx context.Context, userID string) error {
	const q = `UPDATE trusted_devices SET revoked = TRUE, updated_at = now() WHERE user_id = $1 AND revoked = FALSE`
	_, err := r.pool.Exec(ctx, q, userID)
	if err != nil {
		return fmt.Errorf("revoking all trusted devices for user: %w", err)
	}
	return nil
}
