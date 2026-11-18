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
	// PinRequiredAtLogin, when true, makes auth.Service.LoginStep2 (and
	// every other second-factor completion: TOTP, push, the first-login
	// TOTP setup) withhold tokens and instead hand back a pending
	// LoginResult — the account must also pass auth.Service.LoginPinStep
	// before it gets a token pair. Go itself has no notion of why: this is
	// just a switch a consuming system's own admin panel manages via
	// PUT /system-admin/users/{id}/login-pin-required, for whichever of its
	// own accounts it decides needs the extra step (e.g. its superadmins).
	// Defaults false — every account behaves exactly as before this field
	// existed until something explicitly turns it on.
	PinRequiredAtLogin bool
	// IsDecoy marca una cuenta señuelo (honeytoken): nunca inicia sesión con
	// éxito — VerifyPassword la trata como credenciales incorrectas — y
	// cualquier intento contra ella queda registrado con auth_events.is_decoy
	// en TRUE. No cuenta como usuario real en estadísticas ni listados.
	IsDecoy   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ListedUser is one row of Repository.ListByAPIClient — a User plus its
// tenant's name, resolved in the same query via a LEFT JOIN rather than a
// separate lookup per row. Deliberately not folded into User itself: every
// other place a User is read (FindByEmail, FindByID, ...) has no reason to
// carry this, and User is already used well beyond the admin listing this
// exists for. APIClientName is "" when the tenant can't be resolved (a
// dangling api_client_id, or none at all) — see ListByAPIClient's own doc
// comment for why that can't happen in practice but is handled anyway.
type ListedUser struct {
	User
	APIClientName string
}
