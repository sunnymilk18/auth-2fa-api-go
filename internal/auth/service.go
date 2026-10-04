package auth

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"auth-2fa-api/internal/apiclient"
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
	changeEmail          *ChangeEmailStore
	loginAttempts        *LoginAttemptLimiter
	mailer               mailer.Mailer
	otpTTL               time.Duration
	refreshTTL           time.Duration
	passwordResetTTL     time.Duration
	emailVerificationTTL time.Duration
	changeEmailTTL       time.Duration

	// apiClients and panelBaseURL are used only to build the panel link in
	// AdminChangeEmail's email — see changeEmailPanelLink. apiClients reads
	// each tenant's own api_clients.panel_base_url; panelBaseURL is a
	// deployment-wide fallback (config.PanelBaseURL) used when a tenant
	// hasn't configured its own. Both can be left unset (apiClients nil,
	// panelBaseURL "") — the email is then sent with no link, same as
	// before this feature existed.
	apiClients   *apiclient.Service
	panelBaseURL string

	// loginPin backs the mandatory-PIN-after-second-factor step (see
	// LoginResult, LoginPinStep, AdminSetLoginPinRequired) — nilable the
	// same way accessRevocation is: every account defaults to
	// PinRequiredAtLogin == false, so a test or deployment that never
	// touches that feature can leave this nil and nothing reaches it (the
	// gate itself only ever calls into loginPin once it already confirmed
	// the account's flag is set).
	loginPin *PinLoginStore

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

	// accessRevocation lets AdminBanUser/AdminRevokeAllSessions/
	// ResetPassword make an already-issued access token stop working
	// immediately, not just once it naturally expires — see
	// AccessRevocationStore's own doc comment. Nilable purely so tests that
	// don't care about this can skip wiring it (every call site here
	// guards with a nil check); a real deployment (cmd/api/main.go) always
	// sets it, unlike totp/push, which are genuinely optional features.
	accessRevocation *AccessRevocationStore
}

func NewService(
	users *user.Service,
	otp *OTPStore,
	tokens *TokenManager,
	refresh *RefreshRepository,
	devices *device.Service,
	passwordReset *PasswordResetStore,
	emailVerification *EmailVerificationStore,
	changeEmail *ChangeEmailStore,
	loginAttempts *LoginAttemptLimiter,
	m mailer.Mailer,
	otpTTL time.Duration,
	refreshTTL time.Duration,
	passwordResetTTL time.Duration,
	emailVerificationTTL time.Duration,
	changeEmailTTL time.Duration,
	totpManager *TOTPManager,
	totpLogin *TOTPLoginStore,
	twoFactorSetup *TwoFactorSetupStore,
	pushClient *push.Client,
	pushLogin *PushLoginStore,
	pushRequestLimiter *PushRequestLimiter,
	logger *slog.Logger,
	accessRevocation *AccessRevocationStore,
	apiClients *apiclient.Service,
	panelBaseURL string,
	loginPin *PinLoginStore,
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
		changeEmail:          changeEmail,
		loginAttempts:        loginAttempts,
		mailer:               m,
		otpTTL:               otpTTL,
		refreshTTL:           refreshTTL,
		passwordResetTTL:     passwordResetTTL,
		emailVerificationTTL: emailVerificationTTL,
		changeEmailTTL:       changeEmailTTL,
		totp:                 totpManager,
		totpLogin:            totpLogin,
		twoFactorSetup:       twoFactorSetup,
		push:                 pushClient,
		pushLogin:            pushLogin,
		pushRequestLimiter:   pushRequestLimiter,
		logger:               logger,
		accessRevocation:     accessRevocation,
		apiClients:           apiClients,
		panelBaseURL:         panelBaseURL,
		loginPin:             loginPin,
	}
}

// markAccessTokensRevoked is a nil-safe passthrough to
// accessRevocation.MarkRevoked — every caller below already has other
// error-returning cleanup to do around it, so this keeps each call site a
// one-liner instead of repeating the nil check three times.
func (s *Service) markAccessTokensRevoked(ctx context.Context, userID string) error {
	if s.accessRevocation == nil {
		return nil
	}
	return s.accessRevocation.MarkRevoked(ctx, userID)
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
		code, humanDuration(s.emailVerificationTTL),
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
// loginToken and let the user approve from their phone. Always false
// alongside needsSetup==true (see startPushLogin's doc comment for why push
// can never be offered on a first-ever login) and always false when this
// deployment has no FIREBASE_CREDENTIALS_PATH configured at all.
//
// When pushOffered is true AND the account's base method is email, the OTP
// is deliberately NOT sent here — same pattern as every push-capable system
// in the wild (Microsoft Authenticator, Duo, Google prompt): push is the
// default challenge, and the emailed code is an on-demand fallback the
// client has to explicitly request via RequestLoginEmailCode, not something
// that goes out on every single login whether or not it ends up used. TOTP
// accounts aren't affected by this either way — that code was never
// server-sent to begin with, it comes from the account's own authenticator
// app.
func (s *Service) LoginStep1(ctx context.Context, apiClientID, identifier, password string) (loginToken string, needsSetup bool, pushOffered bool, method string, err error) {
	lockoutKey := identifier
	if resolved, lookupErr := s.users.FindByIdentifier(ctx, apiClientID, identifier); lookupErr == nil {
		lockoutKey = resolved.ID
	}

	locked, retryAfter, err := s.loginAttempts.IsLocked(ctx, apiClientID, lockoutKey)
	if err != nil {
		return "", false, false, "", err
	}
	if locked {
		return "", false, false, "", &LockedOutError{RetryAfter: retryAfter}
	}

	u, err := s.users.VerifyPassword(ctx, apiClientID, identifier, password)
	if err != nil {
		if errors.Is(err, user.ErrInvalidCredentials) {
			// Best-effort: a Redis hiccup here shouldn't turn a legitimate
			// wrong-password response into a 500.
			_ = s.loginAttempts.RecordFailure(ctx, apiClientID, lockoutKey)
		}
		return "", false, false, "", err
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
		return "", false, false, "", ErrEmailNotVerified
	}

	// First login ever, and there's actually something to choose between —
	// hand back a pending-choice token instead of defaulting to email. See
	// this method's doc comment for the full shape of what happens next.
	// Push is never offered here — see startPushLogin's doc comment. method
	// is "" here (and whenever pushOffered ends up true below): neither
	// case has an actual pending code yet for Handlers.Login to report.
	if !u.TwoFactorMethodChosen && s.twoFactorSetup != nil {
		token, err := s.twoFactorSetup.StartSession(ctx, u.ID, u.APIClientID, u.Email)
		if err != nil {
			return "", false, false, "", err
		}
		return token, true, false, "", nil
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
			return "", false, false, "", ErrTOTPNotConfigured
		}
		token, err := s.totpLogin.StartSession(ctx, u.ID, u.APIClientID, u.Email)
		if err != nil {
			return "", false, false, "", err
		}
		pushOffered := s.startPushLogin(ctx, token, candidate)
		method := "totp"
		if pushOffered {
			method = ""
		}
		return token, false, pushOffered, method, nil
	}

	loginToken, err = generateToken(32)
	if err != nil {
		return "", false, false, "", fmt.Errorf("generating login token: %w", err)
	}

	// Push is checked BEFORE the OTP email, deliberately, and the email is
	// skipped entirely when push is offered — matching how push-capable
	// systems in the wild (Microsoft Authenticator, Duo, Google prompt)
	// actually behave: push is the default challenge, and other factors are
	// an on-demand fallback the person has to explicitly ask for (see
	// RequestLoginEmailCode), not something sent on every single login
	// regardless of whether it ends up getting used. Emailing an OTP nobody
	// asked for on every login the account ever makes is exactly the kind
	// of unnecessary email volume this avoids.
	pushOffered = s.startPushLogin(ctx, loginToken, candidate)

	if !pushOffered {
		code, err := s.otp.StartSessionWithToken(ctx, loginToken, u.ID, u.APIClientID, u.Email)
		if err != nil {
			return "", false, false, "", err
		}
		body := fmt.Sprintf(
			"Tu código de verificación es: %s\n\nExpira en %s. Si no solicitaste este código, ignora este correo.",
			code, humanDuration(s.otpTTL),
		)
		if err := s.mailer.Send(ctx, u.Email, "Tu código de verificación", body); err != nil {
			return "", false, false, "", fmt.Errorf("sending otp email: %w", err)
		}
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

	method = "email"
	if pushOffered {
		method = ""
	}
	return loginToken, false, pushOffered, method, nil
}

// LoginStep2 verifies the code — emailed OTP or, for accounts with an
// authenticator app confirmed, a TOTP code — and, on success, issues a
// fresh access/refresh token pair. The client calls the same endpoint
// either way; which verification path applies is decided here, by which
// store recognizes loginToken (see LoginStep1), not by anything the client
// has to specify.
func (s *Service) LoginStep2(ctx context.Context, loginToken, code string) (LoginResult, error) {
	if s.totpLogin != nil {
		sess, found, err := s.totpLogin.Peek(ctx, loginToken)
		if err != nil {
			return LoginResult{}, err
		}
		if found {
			return s.verifyTOTPLogin(ctx, loginToken, sess, code)
		}
	}

	userID, apiClientID, email, err := s.otp.VerifyCode(ctx, loginToken, code)
	if err != nil {
		return LoginResult{}, err
	}
	return s.finishLogin(ctx, userID, apiClientID, email)
}

// ResendLoginOTP re-issues a fresh code under the same login_token for a
// plain email-OTP login already in progress (LoginStep1's !pushOffered
// branch, where the code is emailed automatically) — the "I didn't get the
// code" recovery a normal login has no other way to trigger, since
// LoginStep1 only ever sends the first one. Unlike RequestLoginEmailCode
// (the push fallback), this doesn't need a push session: it works straight
// off the OTP session LoginStep1 already created, so it requires no
// feature flag and works with push disabled entirely.
//
// A TOTP-enabled account's loginToken lives in totpLogin, not otp — that's
// checked first so that case gets its own clear error
// (ErrTOTPCodeNotResendable) instead of the generic "session expired"
// ErrLoginSessionNotFound, since the account itself hasn't gone anywhere;
// there's just nothing here to resend, the code comes from the person's
// own authenticator app.
func (s *Service) ResendLoginOTP(ctx context.Context, loginToken string) error {
	if s.totpLogin != nil {
		if _, found, err := s.totpLogin.Peek(ctx, loginToken); err == nil && found {
			return ErrTOTPCodeNotResendable
		}
	}

	sess, found, err := s.otp.Peek(ctx, loginToken)
	if err != nil {
		return err
	}
	if !found {
		return ErrLoginSessionNotFound
	}

	code, err := s.otp.StartSessionWithToken(ctx, loginToken, sess.UserID, sess.APIClientID, sess.Email)
	if err != nil {
		return err
	}
	body := fmt.Sprintf(
		"Tu código de verificación es: %s\n\nExpira en %s. Si no solicitaste este código, ignora este correo.",
		code, humanDuration(s.otpTTL),
	)
	if err := s.mailer.Send(ctx, sess.Email, "Tu código de verificación", body); err != nil {
		return fmt.Errorf("sending otp email: %w", err)
	}
	return nil
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

// LoginResult is what a login's final step (LoginStep2, PollPushLogin,
// ConfirmTOTPEnrollmentAndLogin, LoginPinStep) resolves to. Exactly one of
// two shapes:
//   - PinRequired == false: AccessToken/RefreshToken carry a real token
//     pair, same as before this feature existed.
//   - PinRequired == true: no tokens — the account has PinRequiredAtLogin
//     set, so password + second factor alone isn't enough. PinToken is a
//     short-lived, single-use token for LoginPinStep; PinSet reports
//     whether the account already has an account PIN (false means
//     LoginPinStep's caller must pass create: true to set one).
type LoginResult struct {
	AccessToken  string
	RefreshToken string
	PinRequired  bool
	PinToken     string
	PinSet       bool
}

// finishLogin is the single point every login path funnels through once
// password + whichever second factor already checked out — see
// LoginResult's doc comment for the two shapes this can resolve to. Reads
// the account fresh (never from a cached pendingLoginSession, which never
// carries PinRequiredAtLogin) specifically to make this decision.
func (s *Service) finishLogin(ctx context.Context, userID, apiClientID, email string) (LoginResult, error) {
	u, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return LoginResult{}, err
	}
	if u.PinRequiredAtLogin {
		pinToken, err := s.loginPin.StartSession(ctx, userID, apiClientID, email)
		if err != nil {
			return LoginResult{}, err
		}
		hasPin, err := s.users.HasPin(ctx, userID)
		if err != nil {
			return LoginResult{}, err
		}
		return LoginResult{PinRequired: true, PinToken: pinToken, PinSet: hasPin}, nil
	}

	accessToken, refreshToken, err := s.issueTokenPair(ctx, userID, apiClientID, email)
	if err != nil {
		return LoginResult{}, err
	}
	return LoginResult{AccessToken: accessToken, RefreshToken: refreshToken}, nil
}

// LoginPinStep completes a login that finishLogin reported PinRequired for
// — the last step before tokens are issued for an account with
// PinRequiredAtLogin set. pinToken is single-use ONLY on success: a wrong
// PIN leaves the session alone (same as a wrong email-OTP code doesn't burn
// login_token — see LoginStep2), so the client can retry with the same
// pinToken up to the account PIN's own shared lockout
// (user.Service.VerifyPin) — this step's failed attempts count against
// that same counter, not a separate one.
//
// create selects which of the account PIN's two states pinToken's holder
// is in, exactly like RegisterDevice's own pin parameter
// (user.Service.EnsurePin): false verifies pin against an existing account
// PIN (the common case); true means the account has none yet (LoginResult.
// PinSet was false) and pin becomes its new one — same format validation as
// every other PIN creation. Passing create: true for an account that
// already has a PIN just verifies against it instead, same dual-meaning
// reuse EnsurePin already has.
func (s *Service) LoginPinStep(ctx context.Context, pinToken, pin string, create bool) (LoginResult, error) {
	sess, found, err := s.loginPin.Peek(ctx, pinToken)
	if err != nil {
		return LoginResult{}, err
	}
	if !found {
		return LoginResult{}, ErrLoginSessionNotFound
	}

	var pinErr error
	if create {
		pinErr = s.users.EnsurePin(ctx, sess.UserID, pin)
	} else {
		pinErr = s.users.VerifyPin(ctx, sess.UserID, pin)
	}
	if pinErr != nil {
		s.logger.Warn("login pin step failed", "user_id", sess.UserID, "error", pinErr)
		return LoginResult{}, pinErr
	}

	if err := s.loginPin.Consume(ctx, pinToken); err != nil {
		return LoginResult{}, err
	}
	accessToken, refreshToken, err := s.issueTokenPair(ctx, sess.UserID, sess.APIClientID, sess.Email)
	if err != nil {
		return LoginResult{}, err
	}
	s.logger.Info("login pin step succeeded", "user_id", sess.UserID)
	return LoginResult{AccessToken: accessToken, RefreshToken: refreshToken}, nil
}

// AdminSetLoginPinRequired flips PinRequiredAtLogin for userID (scoped to
// apiClientID — see checkUserScope). Doesn't revoke anything either way:
// turning it on doesn't touch existing sessions/trusted devices (see
// finishLogin — only a NEW login, from here on, goes through the extra
// step), and turning it off just stops asking for it going forward.
func (s *Service) AdminSetLoginPinRequired(ctx context.Context, apiClientID, userID string, required bool) error {
	u, err := s.checkUserScope(ctx, apiClientID, userID)
	if err != nil {
		return err
	}
	if err := s.users.SetLoginPinRequired(ctx, userID, required); err != nil {
		return err
	}
	s.logger.Info("login pin requirement changed", "user_id", userID, "api_client_id", u.APIClientID, "required", required)
	return nil
}

// Refresh validates a refresh token and issues a new access token, rotating
// the refresh token (old one revoked, new one issued) to limit replay risk.
// The validate-and-revoke step is one atomic operation (see
// RefreshRepository.ConsumeIfValid) rather than a separate check followed
// by a separate revoke — two near-simultaneous requests with the same
// token (several browser tabs on the same account, a client retrying after
// a dropped response) could otherwise both pass a separate check before
// either one's revoke landed, minting two token pairs from what should
// only ever be usable once.
//
// Also checks the account is still active — a second layer of defense on
// top of AdminBanUser already revoking every refresh token (and marking
// every access token already issued as untrusted — see
// AccessRevocationStore) a banned account has: if that ever races or
// partially fails, this still refuses the renewal outright instead of
// silently keeping a banned account's session alive.
//
// A token that fails ConsumeIfValid gets one more check — RefreshRepository.
// CheckReuse — before this gives up on it: if it's specifically a token
// that was already used a while ago (not just unknown or expired), that's
// treated as a likely sign of a stolen copy being replayed, and every
// session the account has is revoked as a precaution (same actions
// AdminBanUser takes, minus the ban itself — this doesn't lock the account
// out, it just forces everyone, attacker included, to re-authenticate).
// The caller always sees the same ErrRefreshTokenInvalid either way,
// whether or not this fired — never anything that would tell an attacker
// their reuse attempt was specifically noticed.
func (s *Service) Refresh(ctx context.Context, refreshToken string) (accessToken, newRefreshToken string, err error) {
	claims, err := s.tokens.ParseRefreshToken(refreshToken)
	if err != nil {
		return "", "", ErrRefreshTokenInvalid
	}

	consumed, err := s.refresh.ConsumeIfValid(ctx, refreshToken)
	if err != nil {
		return "", "", err
	}
	if !consumed {
		s.reactToPossibleTokenReuse(ctx, refreshToken)
		return "", "", ErrRefreshTokenInvalid
	}

	u, err := s.users.FindByID(ctx, claims.Subject)
	if err != nil {
		return "", "", err
	}
	if !u.IsActive {
		return "", "", ErrAccountBanned
	}

	return s.issueTokenPair(ctx, claims.Subject, claims.APIClientID, claims.Email)
}

// reactToPossibleTokenReuse revokes every session an account has the
// moment a refresh token that was already used a while ago (not just
// unknown or expired) gets presented again — see Refresh's own doc
// comment. Deliberately swallows its own errors (logged, not returned):
// this is best-effort defense-in-depth on top of an already-rejected
// request, not something that should change what the caller sees.
func (s *Service) reactToPossibleTokenReuse(ctx context.Context, refreshToken string) {
	userID, suspicious, err := s.refresh.CheckReuse(ctx, refreshToken)
	if err != nil {
		s.logger.Error("checking refresh token reuse", "error", err)
		return
	}
	if !suspicious {
		return
	}
	if err := s.refresh.RevokeAllForUser(ctx, userID); err != nil {
		s.logger.Error("revoking sessions after suspected refresh token reuse", "user_id", userID, "error", err)
	}
	if err := s.devices.RevokeAllForUser(ctx, userID); err != nil {
		s.logger.Error("revoking devices after suspected refresh token reuse", "user_id", userID, "error", err)
	}
	if err := s.markAccessTokensRevoked(ctx, userID); err != nil {
		s.logger.Error("marking access tokens revoked after suspected refresh token reuse", "user_id", userID, "error", err)
	}
	s.logger.Warn("possible refresh token reuse detected, revoked every session for the account", "user_id", userID)
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

	how := `Ingresa el código en la pantalla "Recuperar contraseña" del panel, opción "Ya tengo un código".`
	if link := s.panelLink(ctx, u.APIClientID, "/forgot-password", u.Email); link != "" {
		how = fmt.Sprintf("Para hacerlo, abre este enlace e ingresa el código: %s.", link)
	}
	body := fmt.Sprintf(
		"Usa este código para restablecer tu contraseña: %s. %s El código expira en %s. Si no solicitaste esto, ignora este correo.",
		code, how, humanDuration(s.passwordResetTTL),
	)
	if err := s.mailer.Send(ctx, u.Email, "Restablece tu contraseña", body); err != nil {
		return fmt.Errorf("sending password reset email: %w", err)
	}
	return nil
}

// ResetPassword consumes a reset code and sets a new password. It also
// revokes every refresh token and every trusted device (PIN unlock) the
// user has, and marks every access token already issued as no longer
// trusted from this instant on (see AccessRevocationStore) — a password
// reset should force re-authentication everywhere, immediately: the
// trusted-device shortcut bypasses password+OTP entirely, and a live
// access token is still good for actions on its own regardless of the
// password, so leaving either intact would let whoever set it up (possibly
// an attacker, during whatever compromise prompted the reset) keep getting
// in or keep acting despite the new password.
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
	if err := s.devices.RevokeAllForUser(ctx, userID); err != nil {
		return err
	}
	return s.markAccessTokensRevoked(ctx, userID)
}

// checkUserScope looks up userID and, when apiClientID is non-empty,
// confirms the account actually belongs to that tenant — returning
// user.ErrNotFound (never a distinct "forbidden") when it doesn't, so a
// scoped system-admin token gets the exact same response for "no such
// user" and "that user belongs to someone else's system": neither
// confirms nor denies the id exists at all outside its own tenant.
//
// apiClientID == "" means "no scoping" — the operator's own global
// X-Admin-Token, which every AdminXxx method below also uses (via the
// same functions, just called with an empty apiClientID from
// /admin/users/* instead of /system-admin/users/*), so there's exactly
// one code path for each action regardless of which credential invoked it.
func (s *Service) checkUserScope(ctx context.Context, apiClientID, userID string) (*user.User, error) {
	u, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if apiClientID != "" && u.APIClientID != apiClientID {
		return nil, user.ErrNotFound
	}
	return u, nil
}

// AdminBanUser deactivates userID (scoped to apiClientID — see
// checkUserScope), revokes every refresh token and trusted device it has,
// and marks every access token already issued as no longer trusted from
// this instant on (see AccessRevocationStore) — same as ResetPassword.
// Without the refresh/device revocation, a session already open at ban
// time could keep renewing indefinitely (see Refresh's own doc comment for
// the second layer of defense against that same gap); without the access
// token marker, that session could keep acting for up to ACCESS_TOKEN_TTL
// after the ban even though it could no longer renew.
func (s *Service) AdminBanUser(ctx context.Context, apiClientID, userID string) error {
	if _, err := s.checkUserScope(ctx, apiClientID, userID); err != nil {
		return err
	}
	if err := s.users.Ban(ctx, userID); err != nil {
		return err
	}
	if err := s.refresh.RevokeAllForUser(ctx, userID); err != nil {
		return err
	}
	if err := s.devices.RevokeAllForUser(ctx, userID); err != nil {
		return err
	}
	return s.markAccessTokensRevoked(ctx, userID)
}

// AdminUnbanUser reverses a previous AdminBanUser (scoped to apiClientID).
func (s *Service) AdminUnbanUser(ctx context.Context, apiClientID, userID string) error {
	if _, err := s.checkUserScope(ctx, apiClientID, userID); err != nil {
		return err
	}
	return s.users.Unban(ctx, userID)
}

// AdminDisableTOTP turns off userID's authenticator-app factor (scoped to
// apiClientID) — login falls back to the email OTP flow, same effect as
// the self-service /auth/totp/disable, but usable when the account can't
// log in at all to reach that endpoint (e.g. a lost phone).
func (s *Service) AdminDisableTOTP(ctx context.Context, apiClientID, userID string) error {
	if _, err := s.checkUserScope(ctx, apiClientID, userID); err != nil {
		return err
	}
	return s.users.DisableTOTP(ctx, userID)
}

// AdminRevokeAllSessions revokes every refresh token and trusted device
// userID has (scoped to apiClientID) and marks every access token already
// issued as no longer trusted from this instant on (see
// AccessRevocationStore), without banning the account — forces
// re-authentication everywhere, immediately, without locking the account
// out.
func (s *Service) AdminRevokeAllSessions(ctx context.Context, apiClientID, userID string) error {
	if _, err := s.checkUserScope(ctx, apiClientID, userID); err != nil {
		return err
	}
	if err := s.refresh.RevokeAllForUser(ctx, userID); err != nil {
		return err
	}
	if err := s.devices.RevokeAllForUser(ctx, userID); err != nil {
		return err
	}
	return s.markAccessTokensRevoked(ctx, userID)
}

// AdminListUsers returns one page of registered users — every account
// that matches, including ones that never finished registering (unverified
// email, no 2FA method chosen yet), which is the whole point: unlike every
// other Admin* method above, there's no userID to scope by here, so this
// is the only way an operator or a tenant's own system can discover an
// account exists at all instead of already knowing its id. apiClientID
// scopes the results to one tenant when non-empty (the /system-admin/users
// case); when empty (the /admin/users case — the operator's own unscoped
// X-Admin-Token), results span every tenant instead. q, when non-empty,
// narrows this to accounts whose email, username or rut contains it. See
// user.Service.ListByAPIClient for the page/pageSize clamping rules and
// q's matching semantics.
func (s *Service) AdminListUsers(ctx context.Context, apiClientID string, page, pageSize int, q string) (users []*user.User, total, effectivePage, effectivePageSize int, err error) {
	return s.users.ListByAPIClient(ctx, apiClientID, page, pageSize, q)
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
// only once. pin plays a dual role depending on whether the account already
// has one (see user.Service.EnsurePin): no PIN yet, pin becomes the
// account's new one; already has one, pin must match it. Either way, the
// device itself ends up gated by the account's PIN, not one of its own —
// see package device's doc comment.
func (s *Service) RegisterDevice(ctx context.Context, userID, deviceID, deviceName, pin string) (deviceToken string, err error) {
	if err := s.users.EnsurePin(ctx, userID, pin); err != nil {
		return "", err
	}
	return s.devices.Register(ctx, userID, deviceID, deviceName)
}

// DeviceLogin verifies a device_token (possession) + the account's PIN
// (knowledge) and, on success, issues a fresh access/refresh token pair —
// the trusted-device shortcut around password+OTP. It also returns a
// rotated device token that MUST replace the client's stored one; the old
// one stops working. Unlike before, a wrong PIN here no longer revokes the
// device — it counts against the account's shared PIN lockout instead (see
// user.Service.VerifyPin), since the PIN is the account's now, not this
// device's alone.
func (s *Service) DeviceLogin(ctx context.Context, deviceID, deviceToken, pin string) (accessToken, refreshToken, newDeviceToken string, err error) {
	d, err := s.devices.VerifyToken(ctx, deviceID, deviceToken)
	if err != nil {
		return "", "", "", err
	}

	if err := s.users.VerifyPin(ctx, d.UserID, pin); err != nil {
		return "", "", "", err
	}

	newDeviceToken, err = s.devices.RotateToken(ctx, d.ID)
	if err != nil {
		return "", "", "", err
	}

	u, err := s.users.FindByID(ctx, d.UserID)
	if err != nil {
		return "", "", "", err
	}
	if !u.IsActive {
		return "", "", "", ErrAccountBanned
	}
	// The trusted-device shortcut replaces password+second-factor entirely
	// with device possession + the account PIN — an account that requires
	// the PIN step ON TOP OF a full password+second-factor login can't be
	// satisfied by this path at all, since no second factor was ever
	// checked here. Same "no path around it" rule as finishLogin: the
	// client has to fall back to the regular /auth/login flow, which does
	// enforce the step (see LoginResult).
	if u.PinRequiredAtLogin {
		return "", "", "", ErrLoginPinStepRequired
	}

	accessToken, refreshToken, err = s.issueTokenPair(ctx, u.ID, u.APIClientID, u.Email)
	if err != nil {
		return "", "", "", err
	}
	return accessToken, refreshToken, newDeviceToken, nil
}

// SetPin creates or changes the authenticated userID's account PIN — see
// user.Service.SetPin.
func (s *Service) SetPin(ctx context.Context, userID, newPin, currentPin string) error {
	return s.users.SetPin(ctx, userID, newPin, currentPin)
}

// VerifyPin confirms userID's account PIN with no other side effect — the
// building block POST /auth/pin/verify exposes for a caller (e.g.
// empresa-backend, before a destructive admin action) to confirm "the
// person at the keyboard still knows the PIN" without creating a session or
// rotating any token. See user.Service.VerifyPin for the shared lockout.
func (s *Service) VerifyPin(ctx context.Context, userID, pin string) error {
	return s.users.VerifyPin(ctx, userID, pin)
}

// AdminResetPin clears userID's account PIN (scoped to apiClientID — see
// checkUserScope) and revokes every trusted device and session it has,
// same reasoning as AdminBanUser/ResetPassword: a PIN reset means the old
// one shouldn't be trusted anymore, so anything it alone could unlock
// (a trusted device) or that was open before the reset (an active session)
// goes with it.
func (s *Service) AdminResetPin(ctx context.Context, apiClientID, userID string) error {
	if _, err := s.checkUserScope(ctx, apiClientID, userID); err != nil {
		return err
	}
	if err := s.users.ClearPin(ctx, userID); err != nil {
		return err
	}
	if err := s.refresh.RevokeAllForUser(ctx, userID); err != nil {
		return err
	}
	if err := s.devices.RevokeAllForUser(ctx, userID); err != nil {
		return err
	}
	return s.markAccessTokensRevoked(ctx, userID)
}

// AdminChangeEmail starts an admin-initiated email correction for userID
// (scoped to apiClientID — see checkUserScope): for an account that typo'd
// its email at registration and, as a result, can never confirm it or use
// password reset to get back in. Doesn't change anything yet — validates
// newEmail, sends it a code, and leaves the change pending. The admin
// never sees that code: ConfirmChangeEmail (a public /auth/* route, not
// gated by any admin token — see Handlers.ConfirmChangeEmail) is what
// actually applies the change, called by the account itself once it
// proves control of newEmail.
func (s *Service) AdminChangeEmail(ctx context.Context, apiClientID, userID, newEmail string) error {
	u, err := s.checkUserScope(ctx, apiClientID, userID)
	if err != nil {
		return err
	}

	newEmail = user.NormalizeEmail(newEmail)
	if !user.ValidateEmail(newEmail) {
		return user.ErrInvalidEmail
	}
	if _, err := s.users.FindByEmail(ctx, u.APIClientID, newEmail); err == nil {
		return user.ErrEmailTaken
	} else if !errors.Is(err, user.ErrNotFound) {
		return err
	}

	code, err := s.changeEmail.StartChange(ctx, u.ID, u.APIClientID, u.Email, newEmail)
	if err != nil {
		return err
	}

	how := `Ingresa el código en la pantalla "Confirmar correo nuevo" del panel.`
	if link := s.panelLink(ctx, u.APIClientID, "/confirmar-correo", newEmail); link != "" {
		how = fmt.Sprintf("Para confirmarlo, abre este enlace e ingresa el código: %s.", link)
	}
	body := fmt.Sprintf(
		"Un administrador solicitó corregir el correo de tu cuenta. Tu código de confirmación es: %s. %s El código expira en %s. Si no reconoces esta solicitud, ignora este correo: el cambio no se aplica sin él.",
		code, how, humanDuration(s.changeEmailTTL),
	)
	if err := s.mailer.Send(ctx, newEmail, "Confirma tu nuevo correo", body); err != nil {
		return fmt.Errorf("sending change-email code: %w", err)
	}
	return nil
}

// panelLink builds a link to the tenant's panel at path, carrying only
// email (URL-encoded) in the query string — never a code: the code stays
// typed by hand from the email body, so it never ends up in browser
// history or server logs. Returns "" if neither the tenant nor the
// deployment has a panel configured (see AdminChangeEmail's and
// RequestPasswordReset's own callers). Best-effort — a failure to look up
// the tenant's own panel_base_url just falls back to the deployment-wide
// one (or no link at all), never blocks sending the code itself.
func (s *Service) panelLink(ctx context.Context, apiClientID, path, email string) string {
	base := s.panelBaseURL
	if s.apiClients != nil {
		if c, err := s.apiClients.FindByID(ctx, apiClientID); err == nil && c.PanelBaseURL != nil && *c.PanelBaseURL != "" {
			base = *c.PanelBaseURL
		}
	}
	if base == "" {
		return ""
	}
	return strings.TrimRight(base, "/") + path + "?email=" + url.QueryEscape(email)
}

// humanDuration renders d in plain Spanish ("1 hora", "60 minutos") for the
// change-email email, instead of Go's own "1h0m0s" — only whole hours or
// whole minutes get a human form; anything else falls back to d.String().
func humanDuration(d time.Duration) string {
	switch {
	case d > 0 && d%time.Hour == 0:
		h := int(d / time.Hour)
		if h == 1 {
			return "1 hora"
		}
		return fmt.Sprintf("%d horas", h)
	case d > 0 && d%time.Minute == 0:
		m := int(d / time.Minute)
		if m == 1 {
			return "1 minuto"
		}
		return fmt.Sprintf("%d minutos", m)
	default:
		return d.String()
	}
}

// ConfirmChangeEmail applies a pending email change — proving control of
// newEmail with the code AdminChangeEmail sent it. On success it marks the
// account's email verified (the whole point: an account that could never
// confirm its typo'd original email is unstuck), and revokes every
// refresh token, trusted device and already-issued access token the
// account has — same reasoning as ResetPassword: a new email is a new
// identity for this account going forward, nothing from before (possibly
// including whoever caused the need for this correction) should keep
// working. The previous address is notified that the change happened, in
// case it wasn't the account's own owner who requested it — best-effort:
// a failure there doesn't undo an otherwise-successful change.
func (s *Service) ConfirmChangeEmail(ctx context.Context, apiClientID, newEmail, code string) error {
	newEmail = user.NormalizeEmail(newEmail)
	userID, oldEmail, err := s.changeEmail.ConsumeCode(ctx, apiClientID, newEmail, code)
	if err != nil {
		return err
	}

	if err := s.users.UpdateEmail(ctx, userID, newEmail); err != nil {
		return err
	}
	if err := s.refresh.RevokeAllForUser(ctx, userID); err != nil {
		return err
	}
	if err := s.devices.RevokeAllForUser(ctx, userID); err != nil {
		return err
	}
	if err := s.markAccessTokensRevoked(ctx, userID); err != nil {
		return err
	}

	body := fmt.Sprintf("El correo de tu cuenta cambió a %s. Si no reconoces este cambio, contacta a soporte de inmediato.", newEmail)
	if err := s.mailer.Send(ctx, oldEmail, "El correo de tu cuenta cambió", body); err != nil {
		s.logger.Error("sending change-email notice to the old address failed", "user_id", userID, "error", err)
	}
	return nil
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

// ErrLoginPinStepRequired is returned by DeviceLogin when the account
// behind an otherwise-valid device_token+pin also has PinRequiredAtLogin
// set — see DeviceLogin's own doc comment for why that shortcut can't
// satisfy this account's requirement on its own.
var ErrLoginPinStepRequired = errors.New("this account requires the full login flow (password + second factor + pin)")
