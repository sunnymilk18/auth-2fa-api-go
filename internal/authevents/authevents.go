// Package authevents records end-user authentication attempts (login,
// password reset, registration) and IP ban/unban history into auth_events
// — the foundation for the admin panel's "tanda 2" of Estadísticas and,
// later, a Security Center. Deliberately a standalone leaf package (no
// imports of this project's other packages, same reasoning as
// internal/audit's own doc comment): internal/auth is the main caller, and
// internal/middleware already imports internal/auth (for
// APIClientIDFromContext — see ratelimit.go), so this package must not
// import either of those or the reverse import would cycle.
//
// Never holds a plaintext email, password, TOTP code, PIN, or token — see
// Entry's own doc comment.
package authevents

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Kind values — see auth_events.kind's own doc comment in the migration.
const (
	KindLogin                = "login"
	KindPasswordResetRequest = "password_reset_request"
	KindPasswordResetConfirm = "password_reset_confirm"
	KindRegister             = "register"
	KindIPBan                = "ip_ban"
	KindIPUnban              = "ip_unban"
)

// Method values — only meaningful alongside KindLogin.
const (
	MethodPassword      = "password"
	MethodTOTP          = "totp"
	MethodEmailCode     = "email_code"
	MethodPush          = "push"
	MethodDevicePin     = "device_pin"
	MethodDeviceTrusted = "device_trusted"
)

// Result values. Grouped by which Kind each applies to — a consuming panel
// maps each one to display text, so treat this list the same as
// audit.Action*: a value is never renamed or removed, only added to.
const (
	// ResultSuccess applies to every Kind (login, password_reset_confirm,
	// register, ip_ban, ip_unban) except password_reset_request, which
	// uses ResultCodeSent instead (see its own doc comment for why).
	ResultSuccess = "success"

	// --- login ---

	// ResultBadCredentials covers an unknown identifier, a banned/inactive
	// account, and a wrong password alike — collapsed into one value on
	// purpose, mirroring user.Service.VerifyPassword's own
	// anti-enumeration guarantee (see that function's doc comment). Never
	// split further without also reconsidering whether doing so leaks
	// anything new.
	ResultBadCredentials   = "bad_credentials"
	ResultEmailNotVerified = "email_not_verified"
	ResultLockedOut        = "locked_out"
	ResultBadTOTP          = "bad_totp"
	ResultTooManyAttempts  = "too_many_attempts"
	ResultSessionExpired   = "session_expired"
	// ResultBadPin is LoginPinStep's own wrong-PIN outcome — distinct from
	// DeviceLogin's own PIN check, which shares ResultBadCredentials-style
	// semantics via device.ErrDeviceNotTrusted/user.PinInvalidError instead
	// (see ResultBadDeviceToken).
	ResultBadPin = "bad_pin"
	// ResultBadDeviceToken/ResultAccountBanned/ResultPinStepRequired are
	// DeviceLogin-specific — unlike the password path, DeviceLogin can
	// tell these apart without any anti-enumeration concern (possessing a
	// device_token already proves more than an email address does).
	ResultBadDeviceToken  = "bad_device_token"
	ResultAccountBanned   = "account_banned"
	ResultPinStepRequired = "pin_step_required"

	// --- password_reset_request ---

	// ResultCodeSent/ResultAccountNotFound: the HTTP response is always
	// identical for both (see auth.Service.RequestPasswordReset's doc
	// comment) — these two values exist so the audit trail can be more
	// honest than the response without changing it.
	ResultCodeSent        = "code_sent"
	ResultAccountNotFound = "account_not_found"

	// --- password_reset_confirm ---

	ResultNotFound     = "not_found"
	ResultInvalidCode  = "invalid_code"
	ResultTooManyTries = "too_many_tries"

	// --- register ---

	ResultEmailTaken    = "email_taken"
	ResultRUTTaken      = "rut_taken"
	ResultUsernameTaken = "username_taken"
	ResultInvalidInput  = "invalid_input"

	// --- ip_ban / ip_unban ---

	ResultBanned   = "banned"
	ResultUnbanned = "unbanned"

	// ResultError is the fallback for an internal error (a Redis hiccup, a
	// DB error) that isn't any of the above — written so the row count
	// stays exhaustive (every attempt gets a row) rather than silently
	// missing one whenever something unrelated to the attempt itself goes
	// wrong.
	ResultError = "error"
)

// BanOrigin values — only meaningful alongside KindIPBan/KindIPUnban.
const (
	// BanOriginAutomatic: the rate limiter's own strike/ban escalation
	// (see middleware.Blacklist.RecordViolation) — never has an actor.
	BanOriginAutomatic = "automatic"
	// BanOriginOperator: an operator lifted a ban via DELETE
	// /admin/blacklist/{ip} — ActorEmail is that operator's email.
	BanOriginOperator = "operator"
	// BanOriginTenant: a tenant lifted its own ban via DELETE
	// /system-admin/blacklist/{ip} — that route carries no operator
	// identity (see internal/httpserver/blacklist_handlers.go's own doc
	// comment), so ActorEmail stays "" and APIClientID is the attribution
	// instead.
	BanOriginTenant = "tenant"
)

// Entry is one row of auth_events. Never holds a plaintext email,
// password, TOTP code, PIN, or token — see package doc comment. Every
// field left at its zero value ("") is written as SQL NULL, not an empty
// string, except UserAgent (always NOT NULL, "" when absent) and IsDecoy
// (always FALSE today — see the migration's own doc comment).
type Entry struct {
	APIClientID string
	UserID      string
	Kind        string
	Method      string
	Result      string
	EmailHash   string
	BanOrigin   string
	ActorEmail  string
	IP          string
	UserAgent   string
	IsDecoy     bool
}

// MaxUserAgentLength bounds UserAgent — a header a caller fully controls,
// truncated rather than rejected since it's informational only, never
// matched against or parsed back.
const MaxUserAgentLength = 200

// TruncateUserAgent cuts ua down to MaxUserAgentLength runes — exported so
// every caller (internal/auth's handlers) applies the exact same limit
// the column comment documents, rather than each re-deriving it.
func TruncateUserAgent(ua string) string {
	runes := []rune(ua)
	if len(runes) > MaxUserAgentLength {
		return string(runes[:MaxUserAgentLength])
	}
	return ua
}

// Repository persists Entry rows in Postgres.
type Repository struct {
	pool *pgxpool.Pool
}

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

// nullIfEmpty turns "" into a real SQL NULL — used for every nullable
// column below (api_client_id/user_id/method/email_hash/ban_origin/
// actor_email/ip): pgx would otherwise try to insert a literal empty
// string into a UUID/INET column and fail, and an empty string in a
// nullable TEXT column would defeat the point of NULL meaning "not
// applicable to this kind" (see Entry's own doc comment).
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// Insert writes one entry. Append-only by design, same as
// admin_audit_log — there is no update or delete of an individual row
// (see Service.DeleteExpired for the one bulk exception, retention, not
// correction).
func (r *Repository) Insert(ctx context.Context, e Entry) error {
	const q = `
		INSERT INTO auth_events (api_client_id, user_id, kind, method, result, email_hash, ban_origin, actor_email, ip, user_agent, is_decoy)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`
	_, err := r.pool.Exec(ctx, q,
		nullIfEmpty(e.APIClientID), nullIfEmpty(e.UserID), e.Kind, nullIfEmpty(e.Method), e.Result,
		nullIfEmpty(e.EmailHash), nullIfEmpty(e.BanOrigin), nullIfEmpty(e.ActorEmail), nullIfEmpty(e.IP),
		e.UserAgent, e.IsDecoy,
	)
	if err != nil {
		return fmt.Errorf("inserting auth event: %w", err)
	}
	return nil
}

// DeleteOlderThan removes every entry created before cutoff — the
// retention sweep (see Service.DeleteExpired), same periodic-job pattern
// as audit.Repository.DeleteOlderThan/RefreshRepository.DeleteExpired.
func (r *Repository) DeleteOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	const q = `DELETE FROM auth_events WHERE created_at < $1`
	tag, err := r.pool.Exec(ctx, q, cutoff)
	if err != nil {
		return 0, fmt.Errorf("deleting old auth events: %w", err)
	}
	return tag.RowsAffected(), nil
}

// Service is what internal/auth and internal/middleware actually call —
// Log never returns an error and never blocks the caller's own action on
// the write's success, exact same reasoning (and nil-safety) as
// audit.Service.Log: a failure to record an auth event must never prevent
// a real login/reset/ban from completing.
type Service struct {
	repo          *Repository
	retention     time.Duration
	logger        *slog.Logger
	writeFailures metric.Int64Counter

	// emailHashSecret derives EmailHash via HMAC-SHA256 — nil (not
	// configured) means HashEmail returns ("", false) and callers omit
	// the field entirely, same "degrade, don't fail startup" contract as
	// middleware.Blacklist.Reference/BAN_REFERENCE_SECRET. Deliberately
	// its own secret (AUTH_EVENTS_EMAIL_HASH_SECRET), not reused from
	// BAN_REFERENCE_SECRET or anything else already in this project —
	// same reasoning as that secret's own doc comment: mixing an HMAC's
	// purpose with an unrelated secret's turns into a real problem the
	// day either one needs to rotate independently of the other.
	emailHashSecret []byte
}

// NewService wires Service. retention bounds how long an entry survives
// before the periodic cleanup removes it — configurable via
// AUTH_EVENTS_RETENTION_DAYS (90 by default). emailHashSecret can be nil —
// see Service.emailHashSecret's own doc comment.
func NewService(repo *Repository, retention time.Duration, emailHashSecret []byte, meter metric.Meter, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	writeFailures, _ := meter.Int64Counter(
		"auth.events.write_failures",
		metric.WithDescription("Auth events that failed to write"),
		metric.WithUnit("{entry}"),
	)
	return &Service{repo: repo, retention: retention, logger: logger, writeFailures: writeFailures, emailHashSecret: emailHashSecret}
}

// Log records e — see Service's own doc comment for why this never
// returns an error. Safe to call on a nil *Service (no-op), same as
// audit.Service.Log — lets a caller built once at startup be passed
// through everywhere without every test helper having to construct a real
// one.
func (s *Service) Log(ctx context.Context, e Entry) {
	if s == nil {
		return
	}
	if err := s.repo.Insert(ctx, e); err != nil {
		s.logger.Error("writing auth event failed", "kind", e.Kind, "result", e.Result, "error", err)
		s.writeFailures.Add(ctx, 1, metric.WithAttributes(attribute.String("kind", e.Kind)))
	}
}

// HashEmail normalizes email the same way user.NormalizeEmail does
// (lowercase, trimmed — duplicated as a one-liner here rather than
// imported, same leaf-package reasoning as the package doc comment) and
// derives a non-reversible HMAC-SHA256 hex digest from it. ok is false
// when AUTH_EVENTS_EMAIL_HASH_SECRET isn't configured — callers omit
// Entry.EmailHash entirely rather than send a SHA-256-only (dictionary-
// attackable) fallback; see Service.emailHashSecret's own doc comment for
// why this must never silently degrade to plain SHA-256 instead of just
// omitting the field.
func (s *Service) HashEmail(email string) (hash string, ok bool) {
	if s == nil || len(s.emailHashSecret) == 0 {
		return "", false
	}
	normalized := strings.ToLower(strings.TrimSpace(email))
	mac := hmac.New(sha256.New, s.emailHashSecret)
	mac.Write([]byte(normalized))
	return hex.EncodeToString(mac.Sum(nil)), true
}

// HasEmailHashSecret reports whether AUTH_EVENTS_EMAIL_HASH_SECRET is
// configured — used once at startup (cmd/api/main.go) to log a warning
// when it's missing, same "degrade loudly, don't fail" contract as
// HashEmail itself. Safe on a nil *Service.
func (s *Service) HasEmailHashSecret() bool {
	return s != nil && len(s.emailHashSecret) > 0
}

// DeleteExpired removes every entry older than the configured retention —
// meant to be called from the same periodic background job as the
// project's other DeleteExpired-style cleanups.
func (s *Service) DeleteExpired(ctx context.Context) (int64, error) {
	return s.repo.DeleteOlderThan(ctx, time.Now().Add(-s.retention))
}

// ParseIP validates and normalizes ip for Entry.IP — "" (not an error)
// when ip is empty (no IP resolvable), so callers can pass
// internal/auth's own client-IP resolution straight through without
// checking it themselves. An unparsable non-empty value is also treated
// as "" rather than failing the whole Log call — a malformed IP is never
// worth losing the rest of the event over.
func ParseIP(ip string) string {
	if ip == "" {
		return ""
	}
	if net.ParseIP(ip) == nil {
		return ""
	}
	return ip
}
