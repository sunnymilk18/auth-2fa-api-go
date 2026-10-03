package device

import "time"

// Device is a trusted device: a phone/tablet that already completed a full
// password+OTP login once and was granted a shortcut back in via
// device_token (possession) + the account's PIN (knowledge — see
// user.Service.VerifyPin; the PIN itself lives on the account, not here).
type Device struct {
	ID              string
	UserID          string
	DeviceID        string
	DeviceName      string
	DeviceTokenHash string
	Revoked         bool
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

// Info is the safe-to-expose subset returned by the "list my devices"
// endpoint — never the token/pin hashes themselves, but PushEnabled (unlike
// PushToken on Device) is safe to expose: it's just a bool, not the secret
// FCM token underneath it. Lets a client show accurate "push is on/off for
// this device" state pulled from the server, instead of a locally cached
// flag that could go stale if push got disabled from elsewhere (another
// install of the app, or an admin action).
type Info struct {
	ID          string
	DeviceName  string
	PushEnabled bool
	TrustedAt   time.Time
	LastUsedAt  time.Time
	ExpiresAt   time.Time
}
