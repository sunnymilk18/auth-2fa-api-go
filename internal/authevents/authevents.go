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
// (TRUE cuando el intento apunta a una cuenta señuelo — migración 0021).
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

// LoginFailureResults es qué valores de result, bajo kind = 'login', cuentan
// como un intento fallido de credenciales o de códigos. Es la definición que
// usan Estadísticas (internal/stats) y el detector de accesos anómalos
// (internal/detector), compartida aquí para que ambos cuenten lo mismo.
// Deliberadamente NO es "todo lo que no sea success": pin_step_required (la
// cuenta solo necesita su paso extra de PIN), session_expired (una sesión de
// verificación vencida) y email_not_verified (la contraseña era correcta) no
// son intentos fallidos de credenciales, y contarlos inflaría las gráficas
// y las alertas con filas que parecen un ataque pero no lo son.
var LoginFailureResults = []string{
	ResultBadCredentials,
	ResultBadTOTP,
	ResultInvalidCode,
	ResultBadPin,
	ResultBadDeviceToken,
	ResultTooManyAttempts,
	ResultLockedOut,
	ResultAccountBanned,
}

// IsLoginFailure reporta si result está en LoginFailureResults.
func IsLoginFailure(result string) bool {
	for _, r := range LoginFailureResults {
		if r == result {
			return true
		}
	}
	return false
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

// writeTimeout bounds Log's own insert once it's detached from the
// caller's context (see Log) — long enough for a normal write, short
// enough that a stuck connection can't hang around indefinitely.
const writeTimeout = 3 * time.Second

// ListedEvent is one row as GET /admin/security/events returns it.
// APIClientID/APIClientName/UserID/UserEmail/Method/BanOrigin/ActorEmail/
// IP are "" when the underlying column is NULL — same COALESCE-to-""
// convention stats.Repository.FailuresByTenant already uses for the same
// nullable columns, rather than a pointer/sql.Null* type; the HTTP handler
// is what turns "" back into an absent JSON field where the contract calls
// for that (Method/BanOrigin/ActorEmail as null, User as a null object).
type ListedEvent struct {
	ID            int64
	CreatedAt     time.Time
	Kind          string
	Method        string
	Result        string
	APIClientID   string
	APIClientName string
	UserID        string
	UserEmail     string
	IP            string
	UserAgent     string
	BanOrigin     string
	ActorEmail    string
	IsDecoy       bool
}

// EventFilter narrows ListEvents — every field left at its zero value
// means "no filter on this". Unlike audit.Filter, a caller-supplied value
// that doesn't even parse (a malformed IP, a non-UUID tenant, an
// unparsable date) is rejected by the HTTP handler with 400 before it ever
// reaches here — this endpoint is meant for investigating incidents, so a
// typo silently matching "everything" instead of "nothing" would be
// actively misleading. From/To are always already resolved by the time
// they reach here — see ResolveEventRange.
type EventFilter struct {
	APIClientID string
	Kind        string
	Method      string
	Result      string
	IP          string
	From        time.Time
	To          time.Time
}

// DefaultEventRangeWindow/MaxEventRangeWindow bound the from/to a caller
// can ask ListEvents for — see ResolveEventRange.
const (
	DefaultEventRangeWindow = 7 * 24 * time.Hour
	MaxEventRangeWindow     = 90 * 24 * time.Hour
)

// ResolveEventRange turns the caller's optional from/to into the pair
// EventFilter.From/To actually need, enforcing GET /admin/security/events'
// range rules: to defaults to now; from defaults to DefaultEventRangeWindow
// (7 days) before whichever to ends up being — so "to given, from not"
// still yields a 7-day window ending at that to, not at now; from after to
// is rejected outright rather than silently swapped; and the resolved
// span may never exceed MaxEventRangeWindow (90 days, matching
// AUTH_EVENTS_RETENTION_DAYS' default) — never silently clamped, since a
// quietly-narrowed range during an incident investigation would be worse
// than an explicit error. A to in the future is accepted without error:
// there's nothing unsafe about it, it just won't match any rows yet.
func ResolveEventRange(from, to *time.Time, now time.Time) (resolvedFrom, resolvedTo time.Time, err error) {
	if to != nil {
		resolvedTo = *to
	} else {
		resolvedTo = now
	}
	if from != nil {
		resolvedFrom = *from
	} else {
		resolvedFrom = resolvedTo.Add(-DefaultEventRangeWindow)
	}
	if resolvedFrom.After(resolvedTo) {
		return time.Time{}, time.Time{}, fmt.Errorf("from no puede ser posterior a to")
	}
	if resolvedTo.Sub(resolvedFrom) > MaxEventRangeWindow {
		return time.Time{}, time.Time{}, fmt.Errorf("el rango entre from y to no puede superar los 90 días")
	}
	return resolvedFrom, resolvedTo, nil
}

// ListEvents returns one page of auth_events for GET /admin/security/events,
// most recent first (created_at DESC, id DESC as the tie-break — unlike
// admin_audit_log's own List, which has none; auth_events can write several
// rows in the same millisecond under load, so a stable tie-break actually
// matters here). Joins api_clients/users to resolve APIClientName/UserEmail
// — both LEFT JOINs, since api_client_id/user_id are nullable (see the
// migration's own doc comment) and must never turn into an INNER JOIN that
// would silently drop an unattributed row. Never selects email_hash — see
// package doc comment.
func (r *Repository) ListEvents(ctx context.Context, f EventFilter, offset, limit int) ([]*ListedEvent, int, error) {
	query := `
		SELECT auth_events.id, auth_events.created_at, auth_events.kind, COALESCE(auth_events.method, ''), auth_events.result,
			COALESCE(auth_events.api_client_id::text, ''), COALESCE(api_clients.name, ''),
			COALESCE(auth_events.user_id::text, ''), COALESCE(users.email, ''),
			COALESCE(host(auth_events.ip), ''), auth_events.user_agent,
			COALESCE(auth_events.ban_origin, ''), COALESCE(auth_events.actor_email, ''), auth_events.is_decoy,
			COUNT(*) OVER() AS total
		FROM auth_events
		LEFT JOIN api_clients ON api_clients.id = auth_events.api_client_id
		LEFT JOIN users ON users.id = auth_events.user_id
		WHERE auth_events.created_at >= $1 AND auth_events.created_at <= $2`
	args := []any{f.From, f.To}
	if f.APIClientID != "" {
		args = append(args, f.APIClientID)
		query += fmt.Sprintf(" AND auth_events.api_client_id = $%d", len(args))
	}
	if f.Kind != "" {
		args = append(args, f.Kind)
		query += fmt.Sprintf(" AND auth_events.kind = $%d", len(args))
	}
	if f.Method != "" {
		args = append(args, f.Method)
		query += fmt.Sprintf(" AND auth_events.method = $%d", len(args))
	}
	if f.Result != "" {
		args = append(args, f.Result)
		query += fmt.Sprintf(" AND auth_events.result = $%d", len(args))
	}
	if f.IP != "" {
		args = append(args, f.IP)
		query += fmt.Sprintf(" AND auth_events.ip = $%d::inet", len(args))
	}
	query += fmt.Sprintf(" ORDER BY auth_events.created_at DESC, auth_events.id DESC OFFSET $%d LIMIT $%d", len(args)+1, len(args)+2)
	args = append(args, offset, limit)

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("listing auth events: %w", err)
	}
	defer rows.Close()

	var out []*ListedEvent
	total := 0
	for rows.Next() {
		e := &ListedEvent{}
		if err := rows.Scan(
			&e.ID, &e.CreatedAt, &e.Kind, &e.Method, &e.Result,
			&e.APIClientID, &e.APIClientName,
			&e.UserID, &e.UserEmail,
			&e.IP, &e.UserAgent,
			&e.BanOrigin, &e.ActorEmail, &e.IsDecoy,
			&total,
		); err != nil {
			return nil, 0, fmt.Errorf("scanning auth event: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("listing auth events: %w", err)
	}
	return out, total, nil
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
	// Detached from the caller's own cancellation (context.WithoutCancel
	// keeps its values, e.g. trace info, but drops its Done channel) and
	// given its own short deadline instead — otherwise a client that
	// disconnects mid-request cancels ctx before the insert reaches
	// Postgres, silently losing the very event the request was about.
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
	defer cancel()
	if err := s.repo.Insert(writeCtx, e); err != nil {
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

// defaultEventPageSize/maxEventPageSize mirror audit.Service.List's own
// constants — same reasoning, same values, kept independent since the two
// have no other reason to depend on each other.
const (
	defaultEventPageSize = 50
	maxEventPageSize     = 100
)

// ListEvents returns one page of entries for GET /admin/security/events —
// page/pageSize clamped the same way audit.Service.List already does for
// its own listing.
func (s *Service) ListEvents(ctx context.Context, f EventFilter, page, pageSize int) (events []*ListedEvent, total, effectivePage, effectivePageSize int, err error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = defaultEventPageSize
	}
	if pageSize > maxEventPageSize {
		pageSize = maxEventPageSize
	}
	offset := (page - 1) * pageSize
	events, total, err = s.repo.ListEvents(ctx, f, offset, pageSize)
	return events, total, page, pageSize, err
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
