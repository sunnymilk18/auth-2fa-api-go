package device

import "time"

// Device is a trusted device: a phone/tablet that already completed a full
// password+OTP login once and was granted a shortcut back in via
// device_token (possession) + pin (knowledge).
type Device struct {
	ID                string
	UserID            string
	DeviceID          string
	DeviceName        string
	DeviceTokenHash   string
	PinHash           string
	FailedPinAttempts int
	Revoked           bool
	// PushToken is the Firebase Cloud Messaging token for this device, set
	// only once its user opts in to push-notification login approval from
	// an already-authenticated session — nil/empty until then, and for any
	// device that never opts in at all. See auth.Service.StartPushLogin.
	PushToken  string
	TrustedAt  time.Time
	LastUsedAt time.Time
	ExpiresAt  time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// Info is the safe-to-expose subset returned by the "list my devices" endpoint.
type Info struct {
	ID         string
	DeviceName string
	TrustedAt  time.Time
	LastUsedAt time.Time
	ExpiresAt  time.Time
}
