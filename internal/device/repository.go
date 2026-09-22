package device

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var ErrNotFound = errors.New("trusted device not found")

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

// Upsert registers a device as trusted, or re-registers it (new token, new
// pin, fresh expiry) if the same device_id already existed — registering a
// device is idempotent from the client's point of view.
func (r *Repository) Upsert(ctx context.Context, userID, deviceID, deviceName, deviceTokenHash, pinHash string, expiresAt time.Time) (*Device, error) {
	const q = `
		MERGE INTO trusted_devices AS target
		USING (SELECT ? AS user_id, ? AS device_id, ? AS device_name, ? AS device_token_hash, ? AS pin_hash, ? AS expires_at) AS src
		ON target.device_id = src.device_id
		WHEN MATCHED THEN
			UPDATE SET user_id = src.user_id, device_name = src.device_name, device_token_hash = src.device_token_hash,
				pin_hash = src.pin_hash, failed_pin_attempts = 0, revoked = 0, trusted_at = SYSDATETIMEOFFSET(),
				last_used_at = SYSDATETIMEOFFSET(), expires_at = src.expires_at, updated_at = SYSDATETIMEOFFSET()
		WHEN NOT MATCHED THEN
			INSERT (user_id, device_id, device_name, device_token_hash, pin_hash, expires_at)
			VALUES (src.user_id, src.device_id, src.device_name, src.device_token_hash, src.pin_hash, src.expires_at)
		OUTPUT INSERTED.id, INSERTED.user_id, INSERTED.device_id, INSERTED.device_name, INSERTED.device_token_hash, INSERTED.pin_hash,
			INSERTED.failed_pin_attempts, INSERTED.revoked, INSERTED.trusted_at, INSERTED.last_used_at, INSERTED.expires_at,
			INSERTED.created_at, INSERTED.updated_at;`

	d := &Device{}
	err := r.db.QueryRowContext(ctx, q, userID, deviceID, deviceName, deviceTokenHash, pinHash, expiresAt).Scan(
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
			failed_pin_attempts, revoked, trusted_at, last_used_at, expires_at, created_at, updated_at
		FROM trusted_devices WHERE device_id = ?`

	d := &Device{}
	err := r.db.QueryRowContext(ctx, q, deviceID).Scan(
		&d.ID, &d.UserID, &d.DeviceID, &d.DeviceName, &d.DeviceTokenHash, &d.PinHash,
		&d.FailedPinAttempts, &d.Revoked, &d.TrustedAt, &d.LastUsedAt, &d.ExpiresAt, &d.CreatedAt, &d.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("querying trusted device: %w", err)
	}
	return d, nil
}

func (r *Repository) ListByUser(ctx context.Context, userID string) ([]Info, error) {
	const q = `
		SELECT id, device_name, trusted_at, last_used_at, expires_at
		FROM trusted_devices
		WHERE user_id = ? AND revoked = 0
		ORDER BY last_used_at DESC`

	rows, err := r.db.QueryContext(ctx, q, userID)
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
		SET device_token_hash = ?, failed_pin_attempts = 0, last_used_at = SYSDATETIMEOFFSET(),
			expires_at = ?, updated_at = SYSDATETIMEOFFSET()
		WHERE id = ?`
	_, err := r.db.ExecContext(ctx, q, newDeviceTokenHash, newExpiresAt, id)
	if err != nil {
		return fmt.Errorf("marking trusted device success: %w", err)
	}
	return nil
}

// IncrementFailedAttempts bumps the counter and returns the new value.
func (r *Repository) IncrementFailedAttempts(ctx context.Context, id string) (int, error) {
	const q = `
		UPDATE trusted_devices SET failed_pin_attempts = failed_pin_attempts + 1, updated_at = SYSDATETIMEOFFSET()
		OUTPUT INSERTED.failed_pin_attempts
		WHERE id = ?`
	var attempts int
	if err := r.db.QueryRowContext(ctx, q, id).Scan(&attempts); err != nil {
		return 0, fmt.Errorf("incrementing failed pin attempts: %w", err)
	}
	return attempts, nil
}

// Revoke invalidates a device unconditionally (used for lockouts after too
// many failed PIN attempts).
func (r *Repository) Revoke(ctx context.Context, id string) error {
	const q = `UPDATE trusted_devices SET revoked = 1, updated_at = SYSDATETIMEOFFSET() WHERE id = ?`
	_, err := r.db.ExecContext(ctx, q, id)
	if err != nil {
		return fmt.Errorf("revoking trusted device: %w", err)
	}
	return nil
}

// RevokeOwned revokes a device only if it belongs to userID — used by the
// user-facing "remove this device" endpoint so one user can't revoke
// another's device by guessing an id.
func (r *Repository) RevokeOwned(ctx context.Context, id, userID string) error {
	const q = `UPDATE trusted_devices SET revoked = 1, updated_at = SYSDATETIMEOFFSET() WHERE id = ? AND user_id = ?`
	res, err := r.db.ExecContext(ctx, q, id, userID)
	if err != nil {
		return fmt.Errorf("revoking trusted device: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking rows affected: %w", err)
	}
	if n == 0 {
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
	const q = `UPDATE trusted_devices SET revoked = 1, updated_at = SYSDATETIMEOFFSET() WHERE user_id = ? AND revoked = 0`
	_, err := r.db.ExecContext(ctx, q, userID)
	if err != nil {
		return fmt.Errorf("revoking all trusted devices for user: %w", err)
	}
	return nil
}
