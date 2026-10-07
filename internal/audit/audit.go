// Package audit records what operators did through /admin/* — who, what
// action, on what target, from where, and when. Deliberately a standalone
// leaf package (no imports of this project's other packages): every
// feature package that performs an admin action (internal/auth,
// internal/apiclient, internal/adminauth, internal/middleware's blacklist
// handlers in internal/httpserver) needs to be able to call this one
// without risking an import cycle — several of them already import each
// other.
//
// Never holds secrets: no password hashes, API keys, TOTP secrets, or
// one-time codes ever go into an Entry — only what was done and what it
// was done to. See Entry's own doc comment.
package audit

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Action values — the full set, used by every /admin/* route that
// modifies something. Treat this list as part of the HTTP contract: a
// consuming panel maps each one to display text, so a value is never
// renamed or removed, only added to.
const (
	ActionUserBan                 = "user.ban"
	ActionUserUnban               = "user.unban"
	ActionUserTOTPDisable         = "user.totp_disable"
	ActionUserPINReset            = "user.pin_reset"
	ActionUserSessionsRevoke      = "user.sessions_revoke"
	ActionUserEmailChangeRequest  = "user.email_change_request"
	ActionUserLoginPinRequiredSet = "user.login_pin_required_set"
	ActionUserLockoutsCleared     = "user.lockouts_cleared"

	ActionClientCreate               = "client.create"
	ActionClientActivate             = "client.activate"
	ActionClientDeactivate           = "client.deactivate"
	ActionClientRotateKey            = "client.rotate_key"
	ActionClientSetPanelBaseURL      = "client.set_panel_base_url"
	ActionClientSystemAdminKeyRotate = "client.system_admin_key_rotate"
	ActionClientSystemAdminKeyRevoke = "client.system_admin_key_revoke"

	ActionBlacklistUnban  = "blacklist.unban"
	ActionAllowlistAdd    = "allowlist.add"
	ActionAllowlistRemove = "allowlist.remove"

	ActionAccountCreate         = "account.create"
	ActionAccountRevoke         = "account.revoke"
	ActionAccountReactivate     = "account.reactivate"
	ActionAccountPasswordChange = "account.password_change"
	ActionAccountTOTPRotate     = "account.totp_rotate"

	ActionAdminLogin       = "admin.login"
	ActionAdminLoginFailed = "admin.login_failed"
)

// TargetType values, paired with Entry.TargetID/TargetLabel.
const (
	TargetTypeUser         = "user"
	TargetTypeClient       = "client"
	TargetTypeBlacklistIP  = "blacklist_ip"
	TargetTypeAllowlistIP  = "allowlist_ip"
	TargetTypeAdminAccount = "admin_account"
)

// Entry is one row of admin_audit_log. TargetLabel is a human-readable
// snapshot of the target taken AT THE TIME of the action (the user's
// email, the client's name, the IP) — deliberately denormalized rather
// than joined from TargetID at read time, so a past entry stays legible
// even after the target's own name/email changes or the target itself is
// gone. Never a secret: no password, API key, TOTP secret, or one-time
// code belongs in any field here — see package doc comment.
type Entry struct {
	ActorEmail  string
	ActorRole   string
	Action      string
	TargetType  string
	TargetID    string
	TargetLabel string
	ActorIP     string
}

// ListedEntry is one row as GET /admin/audit returns it.
type ListedEntry struct {
	ID          string
	CreatedAt   time.Time
	ActorEmail  string
	ActorRole   string
	Action      string
	TargetType  string
	TargetID    string
	TargetLabel string
	ActorIP     string
}

// Filter narrows List — every field left at its zero value means "no
// filter on this".
type Filter struct {
	Actor  string
	Action string
	From   *time.Time
	To     *time.Time
}

// defaultPageSize/maxPageSize mirror user.Service.ListByAPIClient's own
// constants — same reasoning, same values, kept independent rather than
// shared since the two have no other reason to depend on each other.
const (
	defaultPageSize = 50
	maxPageSize     = 100
)

// Repository persists Entry rows in Postgres.
type Repository struct {
	pool *pgxpool.Pool
}

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

// Insert writes one entry. The only method that touches admin_audit_log
// with a write — there is no update or delete of an individual row,
// append-only by design (see DeleteOlderThan for the one bulk exception,
// retention, not correction).
func (r *Repository) Insert(ctx context.Context, e Entry) error {
	const q = `
		INSERT INTO admin_audit_log (actor_email, actor_role, action, target_type, target_id, target_label, actor_ip)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := r.pool.Exec(ctx, q, e.ActorEmail, e.ActorRole, e.Action, e.TargetType, e.TargetID, e.TargetLabel, e.ActorIP)
	if err != nil {
		return fmt.Errorf("inserting audit log entry: %w", err)
	}
	return nil
}

// List returns one page of entries, most recent first, optionally
// narrowed by f — see Filter's own doc comment. offset/limit are already
// resolved (see Service.List for where page/pageSize get clamped and
// turned into these).
func (r *Repository) List(ctx context.Context, f Filter, offset, limit int) ([]*ListedEntry, int, error) {
	query := `
		SELECT id, created_at, actor_email, actor_role, action, target_type, target_id, target_label, actor_ip,
			COUNT(*) OVER() AS total
		FROM admin_audit_log`
	var args []any
	var conditions []string

	if f.Actor != "" {
		args = append(args, f.Actor)
		conditions = append(conditions, fmt.Sprintf("actor_email = $%d", len(args)))
	}
	if f.Action != "" {
		args = append(args, f.Action)
		conditions = append(conditions, fmt.Sprintf("action = $%d", len(args)))
	}
	if f.From != nil {
		args = append(args, *f.From)
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", len(args)))
	}
	if f.To != nil {
		args = append(args, *f.To)
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", len(args)))
	}
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += fmt.Sprintf(" ORDER BY created_at DESC OFFSET $%d LIMIT $%d", len(args)+1, len(args)+2)
	args = append(args, offset, limit)

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("listing audit log entries: %w", err)
	}
	defer rows.Close()

	var entries []*ListedEntry
	total := 0
	for rows.Next() {
		e := &ListedEntry{}
		if err := rows.Scan(
			&e.ID, &e.CreatedAt, &e.ActorEmail, &e.ActorRole, &e.Action, &e.TargetType, &e.TargetID, &e.TargetLabel, &e.ActorIP,
			&total,
		); err != nil {
			return nil, 0, fmt.Errorf("scanning audit log entry: %w", err)
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("listing audit log entries: %w", err)
	}
	return entries, total, nil
}

// DeleteOlderThan removes every entry created before cutoff — the
// retention sweep (see Service's doc comment on AUDIT_RETENTION_DAYS),
// called from the same kind of periodic background job as
// RefreshRepository.DeleteExpired / SessionRepository.DeleteExpired.
func (r *Repository) DeleteOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	const q = `DELETE FROM admin_audit_log WHERE created_at < $1`
	tag, err := r.pool.Exec(ctx, q, cutoff)
	if err != nil {
		return 0, fmt.Errorf("deleting old audit log entries: %w", err)
	}
	return tag.RowsAffected(), nil
}

// Service is what every /admin/* handler actually calls — Log never
// returns an error and never blocks the caller's own action on the
// write's success: a failure to record an audit entry must not prevent
// the real action (ban a user, rotate a key, ...) from completing, since
// that would turn an observability feature into a single point of
// failure for the whole admin panel. A write failure is instead logged
// (server-side only) and counted on a metric, so it's visible to whoever
// watches dashboards/alerts without silently vanishing.
type Service struct {
	repo          *Repository
	retention     time.Duration
	logger        *slog.Logger
	writeFailures metric.Int64Counter
}

// NewService wires Service. retention bounds how long an entry survives
// before the periodic cleanup (see DeleteOlderThan) removes it —
// configurable via AUDIT_RETENTION_DAYS (365 by default), not a fixed
// constant, since different institutions can have different retention
// requirements and this shouldn't need a code change to adjust.
func NewService(repo *Repository, retention time.Duration, meter metric.Meter, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	writeFailures, _ := meter.Int64Counter(
		"admin.audit.write_failures",
		metric.WithDescription("Audit log entries that failed to write"),
		metric.WithUnit("{entry}"),
	)
	return &Service{repo: repo, retention: retention, logger: logger, writeFailures: writeFailures}
}

// Log records e — see Service's own doc comment for why this never
// returns an error. Safe to call on a nil *Service (no-op): lets a caller
// built once at startup be passed through everywhere without every test
// helper having to construct a real one.
func (s *Service) Log(ctx context.Context, e Entry) {
	if s == nil {
		return
	}
	if err := s.repo.Insert(ctx, e); err != nil {
		s.logger.Error("writing audit log entry failed", "action", e.Action, "actor_email", e.ActorEmail, "target_type", e.TargetType, "target_id", e.TargetID, "error", err)
		s.writeFailures.Add(ctx, 1, metric.WithAttributes(attribute.String("action", e.Action)))
	}
}

// List returns one page of entries for GET /admin/audit — page/pageSize
// clamped the same way user.Service.ListByAPIClient already does for its
// own listing.
func (s *Service) List(ctx context.Context, f Filter, page, pageSize int) (entries []*ListedEntry, total, effectivePage, effectivePageSize int, err error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = defaultPageSize
	}
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}
	offset := (page - 1) * pageSize
	entries, total, err = s.repo.List(ctx, f, offset, pageSize)
	return entries, total, page, pageSize, err
}

// DeleteExpired removes every entry older than the configured retention —
// meant to be called from the same periodic background job as the
// project's other DeleteExpired-style cleanups.
func (s *Service) DeleteExpired(ctx context.Context) (int64, error) {
	return s.repo.DeleteOlderThan(ctx, time.Now().Add(-s.retention))
}

// RemoteIP extracts the caller's bare IP (no port) from r.RemoteAddr, for
// Entry.ActorIP. Deliberately NOT middleware.ClientIP: that resolves
// X-Forwarded-For for traffic a *trusted proxy* forwards (end users going
// through a consuming system's own backend — see TRUSTED_PROXY_CIDRS),
// which doesn't apply here — an operator's browser or script talks to
// this API directly, so the real TCP peer address is already the right
// one, and reaching for middleware.ClientIP would require importing
// internal/middleware here, which this package deliberately never does
// (see package doc comment).
func RemoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
