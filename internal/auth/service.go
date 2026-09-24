package auth

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"auth-2fa-api/internal/device"
	"auth-2fa-api/internal/mailer"
	"auth-2fa-api/internal/push"
	"auth-2fa-api/internal/user"
)

// Service wires together password verification, OTP issuance/checking and
// JWT issuance into the full two-factor login flow, plus the trusted-device
// + PIN shortcut that lets a recognized device skip password+OTP.
type Service struct {
	users                *user.Service
	otp                  *OTPStore
	tokens               *TokenManager
	refresh              *RefreshRepository
	devices              *device.Service
	passwordReset        *PasswordResetStore
	emailVerification    *EmailVerificationStore
	loginAttempts        *LoginAttemptLimiter
	mailer               mailer.Mailer
	otpTTL               time.Duration
	refreshTTL           time.Duration
	passwordResetTTL     time.Duration
	emailVerificationTTL time.Duration

	// totp/totpLogin are both nil when TOTP_ENCRYPTION_KEY isn't configured
	// (see cmd/api/main.go) — the feature is opt-in at the deployment level,
	// same as ADMIN_API_TOKEN gating /admin/*. Always constructed together
	// (NewService's caller is the only place that sets either), so every
	// exported TOTP-related method checks totp/totpLogin for nil and
	// returns ErrTOTPNotConfigured rather than panicking; the unexported
	// verifyTOTPLogin skips its own check and relies on that invariant,
	// since its only caller (LoginStep2) already confirmed totpLogin is
	// non-nil before reaching it.
	totp      *TOTPManager
	totpLogin *TOTPLoginStore

	// twoFactorSetup is nil under the exact same condition as totp/totpLogin
	// (TOTP_ENCRYPTION_KEY unset) — when nil, LoginStep1 never offers the
	// first-login "choose your method" screen at all (there's nothing to
	// choose between if TOTP isn't available on this deployment), and just
	// behaves exactly as it did before this feature existed.
	twoFactorSetup *TwoFactorSetupStore

	// push/pushLogin/pushRequestLimiter are all nil when
	// FIREBASE_CREDENTIALS_PATH isn't configured (see cmd/api/main.go) —
	// same opt-in-at-the-deployment-level reasoning as totp/totpLogin.
	// Unlike TOTP, push is never offered at first login even when
	// configured (see startPushLogin's doc comment) — there's a third
	// condition beyond "deployment has it configured": the specific
	// account also needs an already-paired push-capable device.
	push               *push.Client
	pushLogin          *PushLoginStore
	pushRequestLimiter *PushRequestLimiter

	// logger records the push failures startPushLogin otherwise swallows
	// silently (Redis errors, FCM send failures, a stale/unregistered
	// device token) — that fan-out is deliberately best-effort and must
	// never fail a login (see startPushLogin's doc comment), but silent
	// forever makes "why doesn't push ever arrive" undebuggable in
	// production. Never nil — NewService falls back to slog.Default() —
	// so every call site here can log unconditionally.
	logger *slog.Logger
}

func NewService(
	users *user.Service,
	otp *OTPStore,
	tokens *TokenManager,
	refresh *RefreshRepository,
	devices *device.Service,
	passwordReset *PasswordResetStore,
	emailVerification *EmailVerificationStore,
	loginAttempts *LoginAttemptLimiter,
	m mailer.Mailer,
	otpTTL time.Duration,
	refreshTTL time.Duration,
	passwordResetTTL time.Duration,
	emailVerificationTTL time.Duration,
	totpManager *TOTPManager,
	totpLogin *TOTPLoginStore,
	twoFactorSetup *TwoFactorSetupStore,
	pushClient *push.Client,
	pushLogin *PushLoginStore,
	pushRequestLimiter *PushRequestLimiter,
	logger *slog.Logger,
) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		users:                users,
		otp:                  otp,
		tokens:               tokens,
		refresh:              refresh,
		devices:              devices,
		passwordReset:        passwordReset,
		emailVerification:    emailVerification,
		loginAttempts:        loginAttempts,
		mailer:               m,
		otpTTL:               otpTTL,
		refreshTTL:           refreshTTL,
		passwordResetTTL:     passwordResetTTL,
		emailVerificationTTL: emailVerificationTTL,
		totp:                 totpManager,
		totpLogin:            totpLogin,
		twoFactorSetup:       twoFactorSetup,
		push:                 pushClient,
		pushLogin:            pushLogin,
		pushRequestLimiter:   pushRequestLimiter,
		logger:               logger,
	}
}

// ErrEmailAlreadyVerified is returned by ResendEmailVerification when the
// account has already confirmed its email — nothing to resend.
var ErrEmailAlreadyVerified = errors.New("email already verified")

// ErrEmailNotVerified is returned by LoginStep1 when the password was
// correct but the account hasn't confirmed its email yet — see LoginStep1's
// doc comment for why this blocks login entirely rather than just warning.
var ErrEmailNotVerified = errors.New("email not verified")

// Register creates a new user account, scoped to the calling api client,
// and emails a verification code. The account exists in the database right
// away, but LoginStep1 refuses to log it in until that code is confirmed
// (see ConfirmEmailVerification) — otherwise anyone could register using a
// stranger's real email without their consent, and every login attempt
// against that account would keep emailing OTP codes to an inbox that
// person never agreed to receive them in.
func (s *Service) Register(ctx context.Context, apiClientID, email, password, username, rut string) (*user.User, error) {
	u, err := s.users.Register(ctx, apiClientID, email, password, username, rut)
	if err != nil {
		return nil, err
	}

	if err := s.sendVerificationEmail(ctx, u); err != nil {
		return nil, err
	}

	return u, nil
}

func (s *Service) sendVerificationEmail(ctx context.Context, u *user.User) error {
	code, err := s.emailVerification.StartVerification(ctx, u.ID, u.APIClientID, u.Email)
	if err != nil {
		return err
	}

	body := fmt.Sprintf(
		"Confirma tu correo con este código: %s\n\nExpira en %s.",
		code, s.emailVerificationTTL.String(),
	)
	if err := s.mailer.Send(ctx, u.Email, "Confirma tu correo electrónico", body); err != nil {
		return fmt.Errorf("sending email verification: %w", err)
	}
	return nil
}

// ConfirmEmailVerification consumes a verification code and marks the
// account as verified, unblocking LoginStep1.
//
// email is normalized here before it's used to build the Redis lookup key
// — StartVerification (called from Register/ResendEmailVerification) keys
// it off u.Email, which is already normalized, so a caller typing a
// differently-cased email here (very plausible: two separate form
// submissions, an autocapitalizing keyboard) would otherwise never find
// the pending session at all, "no hay una verificación pendiente" despite
// having the exact right code.
func (s *Service) ConfirmEmailVerification(ctx context.Context, apiClientID, email, code string) error {
	email = user.NormalizeEmail(email)
	userID, err := s.emailVerification.ConsumeCode(ctx, apiClientID, email, code)
	if err != nil {
		return err
	}
	return s.users.MarkEmailVerified(ctx, userID)
}

// ResendEmailVerification re-sends the confirmation code for an existing,
// not-yet-verified account — e.g. the first email got lost or its code
// expired. Unlike RequestPasswordReset, this doesn't need to hide whether
// the account exists: registration itself already reveals that (a
// duplicate email fails with a clear "already registered" error).
func (s *Service) ResendEmailVerification(ctx context.Context, apiClientID, email string) error {
	u, err := s.users.FindByEmail(ctx, apiClientID, email)
	if err != nil {
		return err
	}
	if u.EmailVerified {
		return ErrEmailAlreadyVerified
	}
	return s.sendVerificationEmail(ctx, u)
}

// LoginStep1 verifies identifier+password within one api client (tenant)
// and, on success, generates and emails an OTP code. identifier accepts an
// email, a username or a RUT (see user.Service.VerifyPassword) — whichever
// one was used, it returns a login token the client must present in
// LoginStep2 along with the code — the code itself is never returned here.
//
// needsSetup is true exactly once per account: the very first time its
// password checks out, if it has never chosen a second-factor method AND
// this deployment actually has TOTP configured (nothing to choose between
// otherwise). When true, loginToken is NOT an OTP/TOTP session — no code
// was generated or emailed — it identifies a pending choice instead, and
// the client is expected to call either SendLoginEmailCode (picks email) or
// EnrollTOTP/ConfirmTOTP with that same token (picks the authenticator
// app), not LoginStep2 directly. Every login after the first behaves
// exactly as before (needsSetup always false), since whichever path gets
// taken marks the account's choice as made.
//
// Guards against password-guessing spread across many IPs against one
// account (see LoginAttemptLimiter) — checked before, and recorded after,
// VerifyPassword itself, so an account that doesn't exist is throttled
// exactly the same way a real one would be (same as VerifyPassword's own
// error not distinguishing the two) — this must not become a way to probe
// which identifiers are registered.
//
// The lockout counter is keyed by the resolved account's id, not by the
// identifier string used to log in — email, username and rut for the same
// account now share one counter (fixed 2026-09-16; used to be three
// separate ones, one per identifier, letting someone get ~3x the intended
// attempt budget by alternating which one they typed). Resolving the
// account here, before checking the password, doesn't leak anything new:
// VerifyPassword's own error already never distinguishes "no such account"
// from "wrong password" in what it returns, only in this internal lookup.
// When the identifier doesn't resolve to any account at all, falls back to
// the raw identifier string — same as every attempt worked before this,
// and still throttles guessing against nonexistent accounts the same way
// as a real one, which matters for the same enumeration reasons.
//
// pushOffered is true when, on top of whichever base method above, this
// account also has a push-capable device already paired (see
// EnablePushApproval) — the client can poll PollPushLogin with the same
// loginToken and let the user approve from their phone instead of typing
// the code that's already on its way regardless. Always false alongside
// needsSetup==true (see startPushLogin's doc comment for why push can
// never be offered on a first-ever login) and always false when this
// deployment has no FIREBASE_CREDENTIALS_PATH configured at all.
func (s *Service) LoginStep1(ctx context.Context, apiClientID, identifier, password string) (loginToken string, needsSetup bool, pushOffered bool, err error) {
	lockoutKey := identifier
	if resolved, lookupErr := s.users.FindByIdentifier(ctx, apiClientID, identifier); lookupErr == nil {
		lockoutKey = resolved.ID
	}

	locked, err := s.loginAttempts.IsLocked(ctx, apiClientID, lockoutKey)
	if err != nil {
		return "", false, false, err
	}
	if locked {
		return "", false, false, ErrTooManyFailedLogins
	}

	u, err := s.users.VerifyPassword(ctx, apiClientID, identifier, password)
	if err != nil {
		if errors.Is(err, user.ErrInvalidCredentials) {
			// Best-effort: a Redis hiccup here shouldn't turn a legitimate
			// wrong-password response into a 500.
			_ = s.loginAttempts.RecordFailure(ctx, apiClientID, lockoutKey)
		}
		return "", false, false, err
	}
	// Best-effort for the same reason — a stale counter after this just
	// means a slightly stricter throttle later, not a security hole.
	_ = s.loginAttempts.Reset(ctx, apiClientID, lockoutKey)

	// Checked only after a correct password, never before: doing it earlier
	// would let an unauthenticated caller learn whether an email is
	// registered-but-unverified vs. not registered at all, the same
	// enumeration VerifyPassword's shared error already guards against.
	// Blocking here (not just warning) is the actual point of verification
	// — an account registered with a stranger's email but never confirmed
	// otherwise logs in exactly as normal, emailing that real owner an OTP
	// code on every attempt they never asked for.
	if !u.EmailVerified {
		return "", false, false, ErrEmailNotVerified
	}

	// First login ever, and there's actually something to choose between —
	// hand back a pending-choice token instead of defaulting to email. See
	// this method's doc comment for the full shape of what happens next.
	// Push is never offered here — see startPushLogin's doc comment.
	if !u.TwoFactorMethodChosen && s.twoFactorSetup != nil {
		token, err := s.twoFactorSetup.StartSession(ctx, u.ID, u.APIClientID, u.Email)
		if err != nil {
			return "", false, false, err
		}
		return token, true, false, nil
	}

	candidate := pushLoginCandidate{ID: u.ID, APIClientID: u.APIClientID, Email: u.Email}

	// Accounts that confirmed an authenticator app (see
	// ConfirmTOTPEnrollment) skip the emailed code entirely — VerifyOTP
	// still takes the code, but LoginStep2 validates it against the
	// account's TOTP secret instead of a Redis-stored hash. See
	// TOTPLoginStore's doc comment for why this needs its own session
	// rather than reusing OTPStore's.
	if u.TOTPEnabled {
		if s.totp == nil || s.totpLogin == nil {
			// Only reachable if TOTP_ENCRYPTION_KEY was removed from the
			// deployment after some accounts already enrolled — not a
			// normal state, but worth a clear error over a nil-pointer
			// panic or silently falling back to a weaker factor.
			return "", false, false, ErrTOTPNotConfigured
		}
		token, err := s.totpLogin.StartSession(ctx, u.ID, u.APIClientID, u.Email)
		if err != nil {
			return "", false, false, err
		}
		return token, false, s.startPushLogin(ctx, token, candidate), nil
	}

	loginToken, code, err := s.otp.StartSession(ctx, u.ID, u.APIClientID, u.Email)
	if err != nil {
		return "", false, false, err
	}

	// Idempotent, and only actually writes for the (rare) case of an
	// account whose first-ever login landed here directly because TOTP
	// isn't configured on this deployment at all — every other caller of
	// this path already has TwoFactorMethodChosen = true, so the guard
	// skips the query entirely rather than issuing a no-op UPDATE on every
	// single normal login forever.
	if !u.TwoFactorMethodChosen {
		_ = s.users.MarkTwoFactorMethodChosen(ctx, u.ID)
	}

	body := fmt.Sprintf(
		"Tu código de verificación es: %s\n\nExpira en %s. Si no solicitaste este código, ignora este correo.",
		code, s.otpTTL.String(),
	)
	if err := s.mailer.Send(ctx, u.Email, "Tu código de verificación", body); err != nil {
		return "", false, false, fmt.Errorf("sending otp email: %w", err)
	}

	// Started AFTER the email actually sends, deliberately: if push somehow
	// offers before the email send fails above, the caller would have
	// already returned an error with a push session dangling with nothing
	// email-side backing it up — the fallback path ("usar otro método")
	// depends on that email having genuinely gone out.
	return loginToken, false, s.startPushLogin(ctx, loginToken, candidate), nil
}

// LoginStep2 verifies the code — emailed OTP or, for accounts with an
// authenticator app confirmed, a TOTP code — and, on success, issues a
// fresh access/refresh token pair. The client calls the same endpoint
// either way; which verification path applies is decided here, by which
// store recognizes loginToken (see LoginStep1), not by anything the client
// has to specify.
func (s *Service) LoginStep2(ctx context.Context, loginToken, code string) (accessToken, refreshToken string, err error) {
	if s.totpLogin != nil {
		sess, found, err := s.totpLogin.Peek(ctx, loginToken)
		if err != nil {
			return "", "", err
		}
		if found {
			return s.verifyTOTPLogin(ctx, loginToken, sess, code)
		}
	}

	userID, apiClientID, email, err := s.otp.VerifyCode(ctx, loginToken, code)
	if err != nil {
		return "", "", err
	}
	return s.issueTokenPair(ctx, userID, apiClientID, email)
}

// issueTokenPair mints an access+refresh token pair for an already-verified
// user and persists the refresh token. Shared by every login path (password
// + OTP, device + PIN, and refresh rotation).
func (s *Service) issueTokenPair(ctx context.Context, userID, apiClientID, email string) (accessToken, refreshToken string, err error) {
	accessToken, err = s.tokens.IssueAccessToken(userID, apiClientID, email)
	if err != nil {
		return "", "", err
	}
	refreshToken, err = s.tokens.IssueRefreshToken(userID, apiClientID, email)
	if err != nil {
		return "", "", err
	}
	if err := s.refresh.Store(ctx, userID, refreshToken, time.Now().Add(s.refreshTTL)); err != nil {
		return "", "", err
	}
	return accessToken, refreshToken, nil
}

// Refresh validates a refresh token and issues a new access token, rotating
// the refresh token (old one revoked, new one issued) to limit replay risk.
func (s *Service) Refresh(ctx context.Context, refreshToken string) (accessToken, newRefreshToken string, err error) {
	claims, err := s.tokens.ParseRefreshToken(refreshToken)
	if err != nil {
		return "", "", ErrRefreshTokenInvalid
	}

	valid, err := s.refresh.IsValid(ctx, refreshToken)
	if err != nil {
		return "", "", err
	}
	if !valid {
		return "", "", ErrRefreshTokenInvalid
	}

	if err := s.refresh.Revoke(ctx, refreshToken); err != nil {
		return "", "", err
	}

	return s.issueTokenPair(ctx, claims.Subject, claims.APIClientID, claims.Email)
}

// Logout revokes a refresh token so it can no longer be used.
func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	return s.refresh.Revoke(ctx, refreshToken)
}

// RequestPasswordReset emails a reset code if apiClientID/email matches an
// account. Always succeeds from the caller's point of view regardless of
// whether the account exists — same reasoning as VerifyPassword returning
// one error for both "no such user" and "wrong password": the response
// must not leak which emails are registered.
func (s *Service) RequestPasswordReset(ctx context.Context, apiClientID, email string) error {
	u, err := s.users.FindByEmail(ctx, apiClientID, email)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			return nil
		}
		return err
	}

	// u.Email, not the raw email param — same reason as
	// ConfirmEmailVerification's own fix: this key has to be found again
	// later by ResetPassword using whatever casing the person retypes, and
	// the only casing guaranteed to match every time is the normalized one.
	code, err := s.passwordReset.StartReset(ctx, u.ID, u.APIClientID, u.Email)
	if err != nil {
		return err
	}

	body := fmt.Sprintf(
		"Usa este código para restablecer tu contraseña: %s\n\nExpira en %s. Si no solicitaste esto, ignora este correo.",
		code, s.passwordResetTTL.String(),
	)
	if err := s.mailer.Send(ctx, u.Email, "Restablece tu contraseña", body); err != nil {
		return fmt.Errorf("sending password reset email: %w", err)
	}
	return nil
}

// ResetPassword consumes a reset code and sets a new password. It also
// revokes every refresh token and every trusted device (PIN unlock) the
// user has — a password reset should force re-authentication everywhere:
// the trusted-device shortcut bypasses password+OTP entirely, so leaving it
// intact would let whoever set it up (possibly an attacker, during whatever
// compromise prompted the reset) keep getting in regardless of the new
// password.
//
// Validates newPassword before consuming the code, not after — the code is
// single-use (see PasswordResetStore.ConsumeCode), so checking it only
// afterward (as user.Service.UpdatePassword itself also does, as a
// backstop) would burn a legitimate reset attempt on a too-short password
// and force requesting a whole new code just for that.
func (s *Service) ResetPassword(ctx context.Context, apiClientID, email, code, newPassword string) error {
	if !user.ValidatePassword(newPassword) {
		return user.ErrInvalidPassword
	}

	// Same normalization RequestPasswordReset now stores the code under
	// (u.Email) — without this, a person who typed a differently-cased
	// email here than they did when requesting the code would never find
	// their own pending reset, even with the exact right code.
	email = user.NormalizeEmail(email)
	userID, err := s.passwordReset.ConsumeCode(ctx, apiClientID, email, code)
	if err != nil {
		return err
	}
	if err := s.users.UpdatePassword(ctx, userID, newPassword); err != nil {
		return err
	}
	if err := s.refresh.RevokeAllForUser(ctx, userID); err != nil {
		return err
	}
	return s.devices.RevokeAllForUser(ctx, userID)
}

// PublicKeys exposes every public key access tokens can currently be
// verified against (kid -> key), for JWKS — normally just one, more only
// during a JWT key rotation's overlap window (see TokenManager.AddVerificationKey).
func (s *Service) PublicKeys() map[string]*rsa.PublicKey {
	return s.tokens.PublicKeys()
}

// RegisterDevice marks deviceID as trusted for the already-authenticated
// userID (the caller must have just completed a full password+OTP login)
// and returns a device token the client must store securely — it's shown
// only once.
func (s *Service) RegisterDevice(ctx context.Context, userID, deviceID, deviceName, pin string) (deviceToken string, err error) {
	return s.devices.Register(ctx, userID, deviceID, deviceName, pin)
}

// DeviceLogin verifies a device_token + pin pair and, on success, issues a
// fresh access/refresh token pair — the trusted-device shortcut around
// password+OTP. It also returns a rotated device token that MUST replace
// the client's stored one; the old one stops working.
func (s *Service) DeviceLogin(ctx context.Context, deviceID, deviceToken, pin string) (accessToken, refreshToken, newDeviceToken string, err error) {
	userID, newDeviceToken, err := s.devices.VerifyPin(ctx, deviceID, deviceToken, pin)
	if err != nil {
		return "", "", "", err
	}

	u, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return "", "", "", err
	}
	if !u.IsActive {
		return "", "", "", ErrAccountBanned
	}

	accessToken, refreshToken, err = s.issueTokenPair(ctx, u.ID, u.APIClientID, u.Email)
	if err != nil {
		return "", "", "", err
	}
	return accessToken, refreshToken, newDeviceToken, nil
}

// ListDevices returns the authenticated user's trusted devices.
func (s *Service) ListDevices(ctx context.Context, userID string) ([]device.Info, error) {
	return s.devices.List(ctx, userID)
}

// RevokeDevice revokes one of the authenticated user's trusted devices.
func (s *Service) RevokeDevice(ctx context.Context, userID, deviceRowID string) error {
	return s.devices.Revoke(ctx, userID, deviceRowID)
}

var ErrUnauthorized = errors.New("unauthorized")

// ErrAccountBanned is returned by DeviceLogin when the account behind an
// otherwise-valid device_token+pin has been deactivated (see
// user.Service.Ban). LoginStep1's own password check already refuses a
// deactivated account via user.ErrInvalidCredentials (see
// user.Service.VerifyPassword) — this closes the same door for the
// trusted-device shortcut, which bypasses password+OTP entirely and so
// never went through that check on its own.
var ErrAccountBanned = errors.New("account is banned")
