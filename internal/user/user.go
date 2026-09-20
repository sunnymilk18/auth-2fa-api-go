package user

import "time"

// User represents a persisted account. Password is only ever stored/handled
// as a bcrypt hash — never in plain text. Email, Username and RUT are each
// unique per APIClientID, not globally — the same value in any of the
// three can be a different account under a different consuming system.
// Login accepts any of the three (see identifier.go) precisely because all
// three carry that same per-tenant uniqueness.
type User struct {
	ID            string
	APIClientID   string
	Email         string
	Username      string
	RUT           string
	PasswordHash  string
	IsActive      bool
	EmailVerified bool
	// TOTPEnabled is true once the account has confirmed an authenticator
	// app (Google Authenticator, Authy, etc.) as its second factor — see
	// auth.Service.ConfirmTOTPEnrollment. The encrypted secret itself is
	// deliberately not part of this struct (fetched only when actually
	// needed to verify a code, via Repository.GetTOTPSecret) so it isn't
	// floating around in every generic user lookup.
	TOTPEnabled bool
	// TwoFactorMethodChosen is false only for an account that has never
	// completed a login before — see auth.Service.LoginStep1's doc comment
	// on the first-login "choose email or authenticator" screen this
	// gates. Flips to true the first time either method actually succeeds,
	// and stays true forever after (switching methods later, from an
	// already-authenticated session, never resets it).
	TwoFactorMethodChosen bool
	CreatedAt             time.Time
	UpdatedAt             time.Time
}
