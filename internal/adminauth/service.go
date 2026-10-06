package adminauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"auth-2fa-api/internal/auth"
	"auth-2fa-api/internal/user"
)

// ErrInvalidCredentials covers every way Login can fail before a session is
// issued — unknown email, inactive account, wrong password, or wrong TOTP
// code all collapse to this one error. Deliberately not distinguished
// (same reasoning user.Service.VerifyPassword already documents for end
// users): telling an attacker which specific factor was wrong narrows down
// what they still need to guess.
var ErrInvalidCredentials = errors.New("invalid admin credentials")

// ErrSessionInvalid means a session cookie's token doesn't currently
// resolve to anything usable — unknown, revoked, expired, or its account
// was itself revoked since the session was issued.
var ErrSessionInvalid = errors.New("admin session invalid or expired")

// ErrCannotRevokeSelf means the caller tried to revoke the very account
// they're currently logged in as — see RevokeAccount's doc comment for why
// that's blocked outright rather than merely discouraged: it's exactly the
// scenario that could strand the panel with no way back in if the caller
// got it wrong.
var ErrCannotRevokeSelf = errors.New("an admin cannot revoke their own account")

// ErrLastSuperAdminAccount means the target of RevokeAccount is the only
// currently-active superadmin account — revoking it would leave no one
// able to manage other admin accounts (create, revoke) or reach any other
// superadmin-only route, and no path back in except the CLI (see
// cmd/createadmin), so it's refused rather than allowed and discovered
// too late. Revoking the last active *regular* admin, by contrast, is
// fine as long as at least one superadmin remains — that superadmin
// already has full access regardless.
var ErrLastSuperAdminAccount = errors.New("cannot revoke the only active superadmin account")

// loginLimiterNamespace is the apiClientID auth.LoginAttemptLimiter keys
// failures under for admin logins — a fixed, non-UUID string so it can
// never collide with a real tenant's own lockout counters (those are
// always real api_client UUIDs), same trick as middleware.Blacklist's
// operator-owned allowlist entries using "" for the same reason.
const loginLimiterNamespace = "admin-panel"

// adminSessionTokenBytes is the raw entropy behind a session token before
// hex-encoding — 32 bytes (256 bits), same as apiclient's API keys and
// well above what's brute-forceable.
const adminSessionTokenBytes = 32

// Service is the whole operator-panel-login surface: provisioning admin
// accounts, logging in (email + password + mandatory TOTP) and validating
// the session a login grants. See this package's doc comment for why it
// exists alongside the shared X-Admin-Token rather than replacing it.
type Service struct {
	accounts     *AccountRepository
	sessions     *SessionRepository
	totp         *auth.TOTPManager
	loginLimiter *auth.LoginAttemptLimiter
	sessionTTL   time.Duration
}

func NewService(accounts *AccountRepository, sessions *SessionRepository, totp *auth.TOTPManager, loginLimiter *auth.LoginAttemptLimiter, sessionTTL time.Duration) *Service {
	return &Service{
		accounts:     accounts,
		sessions:     sessions,
		totp:         totp,
		loginLimiter: loginLimiter,
		sessionTTL:   sessionTTL,
	}
}

// CreateAccount provisions a new admin account, generating its TOTP secret
// server-side — TOTP is mandatory from creation (see migration
// 0015_admin_accounts.sql's doc comment), there's no opt-in enrollment
// step the way end users have. otpauthURL is what the panel renders as a
// QR code; both it and the raw secret are only ever available here, once —
// same one-time-visibility rule as an API key (see apiclient.Service.Create).
func (s *Service) CreateAccount(ctx context.Context, email, password string, role Role) (account *AdminAccount, otpauthURL string, err error) {
	if !role.Valid() {
		return nil, "", ErrInvalidRole
	}
	email = user.NormalizeEmail(email)

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, "", fmt.Errorf("hashing admin password: %w", err)
	}

	secret, url, err := s.totp.GenerateSecret(email)
	if err != nil {
		return nil, "", fmt.Errorf("generating admin totp secret: %w", err)
	}
	secretEnc, err := s.totp.Encrypt(secret)
	if err != nil {
		return nil, "", fmt.Errorf("encrypting admin totp secret: %w", err)
	}

	account, err = s.accounts.Create(ctx, email, string(passwordHash), secretEnc, role)
	if err != nil {
		return nil, "", err
	}
	return account, url, nil
}

// Login verifies email+password+totpCode and, on success, issues a new
// session: the raw token (to set as the panel's httpOnly cookie value) and
// when it expires. Throttled per email via auth.LoginAttemptLimiter, same
// mechanism (and same non-permanent reasoning — see its own doc comment)
// already protecting end-user login.
func (s *Service) Login(ctx context.Context, email, password, totpCode string) (sessionToken string, expiresAt time.Time, err error) {
	email = user.NormalizeEmail(email)

	locked, retryAfter, err := s.loginLimiter.IsLocked(ctx, loginLimiterNamespace, email)
	if err != nil {
		return "", time.Time{}, err
	}
	if locked {
		return "", time.Time{}, &auth.LockedOutError{RetryAfter: retryAfter}
	}

	account, err := s.accounts.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			_ = s.loginLimiter.RecordFailure(ctx, loginLimiterNamespace, email)
			return "", time.Time{}, ErrInvalidCredentials
		}
		return "", time.Time{}, err
	}
	if !account.Active {
		_ = s.loginLimiter.RecordFailure(ctx, loginLimiterNamespace, email)
		return "", time.Time{}, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(account.PasswordHash), []byte(password)); err != nil {
		_ = s.loginLimiter.RecordFailure(ctx, loginLimiterNamespace, email)
		return "", time.Time{}, ErrInvalidCredentials
	}

	secret, err := s.totp.Decrypt(account.TOTPSecretEnc)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("decrypting admin totp secret: %w", err)
	}
	if !s.totp.ValidateCode(secret, totpCode) {
		_ = s.loginLimiter.RecordFailure(ctx, loginLimiterNamespace, email)
		return "", time.Time{}, ErrInvalidCredentials
	}

	_ = s.loginLimiter.Reset(ctx, loginLimiterNamespace, email)

	token, err := generateSessionToken()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("generating admin session token: %w", err)
	}
	expiresAt = time.Now().Add(s.sessionTTL)
	if err := s.sessions.Store(ctx, account.ID, token, expiresAt); err != nil {
		return "", time.Time{}, err
	}
	return token, expiresAt, nil
}

// ValidateSession resolves a session cookie's raw token to the email and
// role of the admin it belongs to. role is returned as a plain string
// (not the Role type the rest of this package uses internally) because
// this exact signature is what satisfies middleware.AdminSessionValidator
// — see that interface's own doc comment for why middleware deliberately
// doesn't import this package's types. middleware.RequireSuperAdmin
// compares it against middleware.AdminRoleSuperAdmin, which must stay
// equal to string(RoleSuperAdmin) — see that constant's doc comment.
// Also rejects a token belonging to an account that was revoked after the
// session was issued, not just one the session row itself already marks
// revoked/expired.
func (s *Service) ValidateSession(ctx context.Context, token string) (email string, role string, ok bool, err error) {
	accountID, found, err := s.sessions.FindValidAccountID(ctx, token)
	if err != nil {
		return "", "", false, err
	}
	if !found {
		return "", "", false, nil
	}
	account, err := s.accounts.FindByID(ctx, accountID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return "", "", false, nil
		}
		return "", "", false, err
	}
	if !account.Active {
		return "", "", false, nil
	}
	return account.Email, string(account.Role), true, nil
}

// Logout revokes a single session (the one the cookie being cleared
// pointed to) — every other session the same admin holds on other devices
// keeps working, same as a regular user logging out of one browser.
func (s *Service) Logout(ctx context.Context, token string) error {
	return s.sessions.Revoke(ctx, token)
}

// ListAccounts returns every admin account, oldest first.
func (s *Service) ListAccounts(ctx context.Context) ([]*AdminAccount, error) {
	return s.accounts.List(ctx)
}

// RevokeAccount deactivates an admin account and immediately invalidates
// every session it currently holds — unlike a regular tenant user ban
// (which leaves existing sessions to expire naturally unless sessions are
// separately revoked), a revoked *admin* account must stop working right
// away given the blast radius a lingering cross-tenant session would have.
//
// Two guardrails on top of that, both checked before anything is written:
// actorEmail (the caller's own email, resolved from their session — pass
// "" for the X-Admin-Token/script path, which has no "self" to protect)
// can never match id's account (ErrCannotRevokeSelf), and if id is a
// currently-active superadmin, it can never be the last one
// (ErrLastSuperAdminAccount — see that error's own doc comment for why a
// regular admin being the "last" one isn't the same kind of problem).
// Without these, a mistake here could strand the panel with no way to
// manage admin accounts at all, recoverable only via cmd/createadmin
// against the database directly.
func (s *Service) RevokeAccount(ctx context.Context, actorEmail, id string) error {
	account, err := s.accounts.FindByID(ctx, id)
	if err != nil {
		return err
	}
	if actorEmail != "" && account.Email == user.NormalizeEmail(actorEmail) {
		return ErrCannotRevokeSelf
	}
	if account.Active && account.Role == RoleSuperAdmin {
		activeSuperAdmins, err := s.accounts.CountActiveByRole(ctx, RoleSuperAdmin)
		if err != nil {
			return err
		}
		if activeSuperAdmins <= 1 {
			return ErrLastSuperAdminAccount
		}
	}

	if err := s.accounts.SetActive(ctx, id, false); err != nil {
		return err
	}
	return s.sessions.RevokeAllForAccount(ctx, id)
}

func generateSessionToken() (string, error) {
	b := make([]byte, adminSessionTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
