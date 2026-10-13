// Package stats computes the read-only numbers GET /admin/stats shows —
// from data that already exists (users, admin_audit_log, auth_events — see
// internal/authevents for that last one, added for "tanda 2": end-user
// login/ban activity). Deliberately its own package rather than folded
// into internal/user or internal/audit: it reads across tables none of
// those packages' own repositories need for their own purposes, so it
// would be an odd fit grafted onto any one of them.
package stats

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"auth-2fa-api/internal/authevents"
)

// Range7d/Range30d are the only values GET /admin/stats' range query
// param accepts — see ParseRangeDays.
const (
	Range7d  = "7d"
	Range30d = "30d"
)

// maxTenants/maxActionTypes/maxFailingIPs bound UsersPerTenant/
// OperatorActionsByType/TopFailingIPs — see Service.Overview's doc comment
// for why these are a fixed "top N" rather than paginated.
const (
	maxTenants     = 50
	maxActionTypes = 10
	maxFailingIPs  = 10
)

// ParseRangeDays turns "7d"/"30d" into the number of calendar days the
// response should cover (including today) — any other value is rejected
// outright (the HTTP handler maps that to 400), there's no default.
func ParseRangeDays(rangeParam string) (days int, ok bool) {
	switch rangeParam {
	case Range7d:
		return 7, true
	case Range30d:
		return 30, true
	default:
		return 0, false
	}
}

// Range is the resolved window Overview queries over — every boundary
// already computed once in ResolveRange, so the repository methods below
// never re-derive "what does N days mean" themselves.
type Range struct {
	// Start/End bound created_at as absolute instants: Start inclusive,
	// End exclusive (the instant "tomorrow" begins in TZ). Comparing a
	// timestamptz column against these is correct regardless of the
	// database session's own timezone — Postgres stores timestamptz as
	// UTC internally, so an absolute instant comparison never depends on
	// which zone asked for it.
	Start, End time.Time
	// TZName is the IANA zone name rows get bucketed into a day by (see
	// UsersPerDay/OperatorActionsPerDay) — passed to Postgres's own
	// AT TIME ZONE, which resolves it against Postgres's own bundled
	// timezone database (not the OS's — every mainstream Postgres
	// distribution ships its own, so this doesn't depend on the database
	// host having tzdata installed, only the Go binary needing
	// time/tzdata to validate it up front — see cmd/api/main.go's blank
	// import).
	TZName string
	// Days is every calendar day in the window, oldest first, formatted
	// "2006-01-02" in TZName — the full list GET /admin/stats always
	// returns a count for, zero-filled where a day has no rows, so the
	// panel's chart never has a gap.
	Days []string
}

// ResolveRange computes Range for days calendar days up to and including
// now (converted into loc first, so "today" means today in the caller's
// timezone, not the server's). Exported mainly so the HTTP handler and
// tests can both call it against a known `now` — Service.Overview is the
// only real caller in production code.
func ResolveRange(days int, loc *time.Location, now time.Time) Range {
	now = now.In(loc)
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	start := todayStart.AddDate(0, 0, -(days - 1))
	end := todayStart.AddDate(0, 0, 1)

	dayLabels := make([]string, days)
	for i := 0; i < days; i++ {
		dayLabels[i] = start.AddDate(0, 0, i).Format("2006-01-02")
	}

	return Range{Start: start, End: end, TZName: loc.String(), Days: dayLabels}
}

// DayCount is one bucket of UsersPerDay.
type DayCount struct {
	Day   string
	Count int
}

// DayActionCount is one bucket of OperatorActionsPerDay — Failed counts
// the subset of Count matching one of the action names Service.Overview
// passes in (see its own doc comment for which ones).
type DayActionCount struct {
	Day    string
	Count  int
	Failed int
}

// TenantCount is one row of UsersPerTenant.
type TenantCount struct {
	APIClientID   string
	APIClientName string
	Total         int
	NewInRange    int
}

// ActionTypeCount is one row of OperatorActionsByType.
type ActionTypeCount struct {
	Action string
	Count  int
}

// Repository reads the aggregate numbers Overview needs, straight out of
// Postgres — no caching, no denormalized counters: every call re-scans
// users/admin_audit_log fresh (see idx_users_created_at/
// idx_admin_audit_log_created_at for why that stays cheap at this scale).
type Repository struct {
	pool *pgxpool.Pool
}

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

// UsersTotal counts every user, across every tenant.
func (r *Repository) UsersTotal(ctx context.Context) (int, error) {
	var n int
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("counting users: %w", err)
	}
	return n, nil
}

// UsersBanned counts users with is_active = FALSE right now (see
// user.Service.Ban) — a point-in-time count, not bounded by Range.
func (r *Repository) UsersBanned(ctx context.Context) (int, error) {
	var n int
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE is_active = FALSE`).Scan(&n); err != nil {
		return 0, fmt.Errorf("counting banned users: %w", err)
	}
	return n, nil
}

// UsersPerDay returns new-user counts bucketed by day in rng.TZName —
// only days that actually have at least one row; Service.Overview
// zero-fills the rest from rng.Days.
func (r *Repository) UsersPerDay(ctx context.Context, rng Range) ([]DayCount, error) {
	const q = `
		SELECT (created_at AT TIME ZONE $1)::date AS day, count(*)
		FROM users
		WHERE created_at >= $2 AND created_at < $3
		GROUP BY day
		ORDER BY day`
	rows, err := r.pool.Query(ctx, q, rng.TZName, rng.Start, rng.End)
	if err != nil {
		return nil, fmt.Errorf("counting users per day: %w", err)
	}
	defer rows.Close()

	var out []DayCount
	for rows.Next() {
		var day time.Time
		var count int
		if err := rows.Scan(&day, &count); err != nil {
			return nil, fmt.Errorf("scanning users per day: %w", err)
		}
		out = append(out, DayCount{Day: day.Format("2006-01-02"), Count: count})
	}
	return out, rows.Err()
}

// UsersPerTenant returns up to limit tenants, largest first — Total is
// every user that tenant has ever had, NewInRange is the subset created
// within rng. Ties (same Total) break by api_client_name then
// api_client_id, both ascending, so the order is stable across calls
// instead of depending on an unspecified tie-break the planner happens to
// pick. This is a "top N for a dashboard", not the real tenant listing
// (that's GET /admin/clients) — a platform with more than limit tenants
// simply doesn't show the smallest ones here.
func (r *Repository) UsersPerTenant(ctx context.Context, rng Range, limit int) ([]TenantCount, error) {
	const q = `
		SELECT users.api_client_id, COALESCE(api_clients.name, ''),
			count(*) AS total,
			count(*) FILTER (WHERE users.created_at >= $1 AND users.created_at < $2) AS new_in_range
		FROM users
		LEFT JOIN api_clients ON api_clients.id = users.api_client_id
		GROUP BY users.api_client_id, api_clients.name
		ORDER BY total DESC, api_clients.name ASC, users.api_client_id ASC
		LIMIT $3`
	rows, err := r.pool.Query(ctx, q, rng.Start, rng.End, limit)
	if err != nil {
		return nil, fmt.Errorf("counting users per tenant: %w", err)
	}
	defer rows.Close()

	var out []TenantCount
	for rows.Next() {
		var t TenantCount
		if err := rows.Scan(&t.APIClientID, &t.APIClientName, &t.Total, &t.NewInRange); err != nil {
			return nil, fmt.Errorf("scanning users per tenant: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// OperatorActionsPerDay returns admin_audit_log counts bucketed by day in
// rng.TZName, same zero-fill contract as UsersPerDay. failedActions
// names which audit.Action* values count toward Failed — e.g.
// admin.login_failed, account.pin_failed; see Service.Overview for the
// actual list, kept out of this package so it never needs to import
// internal/audit just for two string constants.
func (r *Repository) OperatorActionsPerDay(ctx context.Context, rng Range, failedActions []string) ([]DayActionCount, error) {
	const q = `
		SELECT (created_at AT TIME ZONE $1)::date AS day,
			count(*) AS count,
			count(*) FILTER (WHERE action = ANY($2)) AS failed
		FROM admin_audit_log
		WHERE created_at >= $3 AND created_at < $4
		GROUP BY day
		ORDER BY day`
	rows, err := r.pool.Query(ctx, q, rng.TZName, failedActions, rng.Start, rng.End)
	if err != nil {
		return nil, fmt.Errorf("counting operator actions per day: %w", err)
	}
	defer rows.Close()

	var out []DayActionCount
	for rows.Next() {
		var day time.Time
		var dc DayActionCount
		if err := rows.Scan(&day, &dc.Count, &dc.Failed); err != nil {
			return nil, fmt.Errorf("scanning operator actions per day: %w", err)
		}
		dc.Day = day.Format("2006-01-02")
		out = append(out, dc)
	}
	return out, rows.Err()
}

// OperatorActionsByType returns the top limit actions by volume within
// rng, most frequent first — ties break by action name ascending, same
// stability reasoning as UsersPerTenant's tie-break.
func (r *Repository) OperatorActionsByType(ctx context.Context, rng Range, limit int) ([]ActionTypeCount, error) {
	const q = `
		SELECT action, count(*) AS count
		FROM admin_audit_log
		WHERE created_at >= $1 AND created_at < $2
		GROUP BY action
		ORDER BY count DESC, action ASC
		LIMIT $3`
	rows, err := r.pool.Query(ctx, q, rng.Start, rng.End, limit)
	if err != nil {
		return nil, fmt.Errorf("counting operator actions by type: %w", err)
	}
	defer rows.Close()

	var out []ActionTypeCount
	for rows.Next() {
		var a ActionTypeCount
		if err := rows.Scan(&a.Action, &a.Count); err != nil {
			return nil, fmt.Errorf("scanning operator actions by type: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// loginFailureResults is which auth_events.result values under kind =
// 'login' count as a failed login attempt for LoginsByDay/
// FailuresByTenant/TopFailingIPs — deliberately NOT "anything that isn't
// success": pin_step_required (the account just needs its extra PIN
// step, not an attack), session_expired (a stale verification session)
// and email_not_verified (the password was actually correct) aren't
// failed credential attempts, and counting them as such would inflate
// these three charts with rows that look like an attack but aren't. A
// result left out of both this list and ResultSuccess simply isn't
// counted in either column — it isn't what these charts are for; the
// per-result breakdown is what GET /admin/security/events (a later
// entry) is for.
var loginFailureResults = []string{
	authevents.ResultBadCredentials,
	authevents.ResultBadTOTP,
	authevents.ResultInvalidCode,
	authevents.ResultBadPin,
	authevents.ResultBadDeviceToken,
	authevents.ResultTooManyAttempts,
	authevents.ResultLockedOut,
	authevents.ResultAccountBanned,
}

// LoginDayCount is one bucket of LoginsByDay — Success/Failed are end-user
// login attempts (auth_events.kind = 'login'), not operator actions (see
// DayActionCount for that, a separate thing).
type LoginDayCount struct {
	Day     string
	Success int
	Failed  int
}

// LoginsByDay returns end-user login attempt counts bucketed by day in
// rng.TZName, same zero-fill contract as UsersPerDay. Success counts
// auth_events.result = 'success'; Failed counts only loginFailureResults
// — see that variable's own doc comment for why it's not simply "every
// other result".
func (r *Repository) LoginsByDay(ctx context.Context, rng Range) ([]LoginDayCount, error) {
	const q = `
		SELECT (created_at AT TIME ZONE $1)::date AS day,
			count(*) FILTER (WHERE result = $2) AS success,
			count(*) FILTER (WHERE result = ANY($3)) AS failed
		FROM auth_events
		WHERE kind = $4 AND created_at >= $5 AND created_at < $6
		GROUP BY day
		ORDER BY day`
	rows, err := r.pool.Query(ctx, q, rng.TZName, authevents.ResultSuccess, loginFailureResults, authevents.KindLogin, rng.Start, rng.End)
	if err != nil {
		return nil, fmt.Errorf("counting logins per day: %w", err)
	}
	defer rows.Close()

	var out []LoginDayCount
	for rows.Next() {
		var day time.Time
		var lc LoginDayCount
		if err := rows.Scan(&day, &lc.Success, &lc.Failed); err != nil {
			return nil, fmt.Errorf("scanning logins per day: %w", err)
		}
		lc.Day = day.Format("2006-01-02")
		out = append(out, lc)
	}
	return out, rows.Err()
}

// TenantLoginCount is one row of FailuresByTenant.
type TenantLoginCount struct {
	APIClientID   string
	APIClientName string
	Success       int
	Failed        int
}

// FailuresByTenant returns up to limit tenants, most login failures
// first, within rng — same "top N for a dashboard" reasoning as
// UsersPerTenant, and the same stable tie-break (name then id, both
// ascending).
func (r *Repository) FailuresByTenant(ctx context.Context, rng Range, limit int) ([]TenantLoginCount, error) {
	const q = `
		SELECT COALESCE(auth_events.api_client_id::text, ''), COALESCE(api_clients.name, ''),
			count(*) FILTER (WHERE auth_events.result = $1) AS success,
			count(*) FILTER (WHERE auth_events.result = ANY($2)) AS failed
		FROM auth_events
		LEFT JOIN api_clients ON api_clients.id = auth_events.api_client_id
		WHERE auth_events.kind = $3 AND auth_events.created_at >= $4 AND auth_events.created_at < $5
		GROUP BY auth_events.api_client_id, api_clients.name
		ORDER BY failed DESC, api_clients.name ASC, auth_events.api_client_id ASC
		LIMIT $6`
	rows, err := r.pool.Query(ctx, q, authevents.ResultSuccess, loginFailureResults, authevents.KindLogin, rng.Start, rng.End, limit)
	if err != nil {
		return nil, fmt.Errorf("counting login failures per tenant: %w", err)
	}
	defer rows.Close()

	var out []TenantLoginCount
	for rows.Next() {
		var t TenantLoginCount
		if err := rows.Scan(&t.APIClientID, &t.APIClientName, &t.Success, &t.Failed); err != nil {
			return nil, fmt.Errorf("scanning login failures per tenant: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// IPFailureCount is one row of TopFailingIPs.
type IPFailureCount struct {
	IP     string
	Failed int
	LastAt time.Time
}

// TopFailingIPs returns up to limit IPs, most failed login attempts first
// within rng — ties break by IP ascending for stability. Rows with no IP
// resolved (see internal/auth's clientIP — practically never happens once
// TRUSTED_PROXY_CIDRS is configured correctly, but possible if it isn't)
// are excluded rather than grouped into one misleading "" bucket.
func (r *Repository) TopFailingIPs(ctx context.Context, rng Range, limit int) ([]IPFailureCount, error) {
	const q = `
		SELECT host(ip), count(*) AS failed, max(created_at) AS last_at
		FROM auth_events
		WHERE kind = $1 AND result = ANY($2) AND ip IS NOT NULL AND created_at >= $3 AND created_at < $4
		GROUP BY ip
		ORDER BY failed DESC, ip ASC
		LIMIT $5`
	rows, err := r.pool.Query(ctx, q, authevents.KindLogin, loginFailureResults, rng.Start, rng.End, limit)
	if err != nil {
		return nil, fmt.Errorf("counting top failing ips: %w", err)
	}
	defer rows.Close()

	var out []IPFailureCount
	for rows.Next() {
		var f IPFailureCount
		if err := rows.Scan(&f.IP, &f.Failed, &f.LastAt); err != nil {
			return nil, fmt.Errorf("scanning top failing ips: %w", err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// BansByDay returns IP ban counts (auth_events.kind = 'ip_ban', any
// origin — see authevents.BanOrigin*) bucketed by day in rng.TZName, same
// zero-fill contract as UsersPerDay.
func (r *Repository) BansByDay(ctx context.Context, rng Range) ([]DayCount, error) {
	const q = `
		SELECT (created_at AT TIME ZONE $1)::date AS day, count(*)
		FROM auth_events
		WHERE kind = $2 AND created_at >= $3 AND created_at < $4
		GROUP BY day
		ORDER BY day`
	rows, err := r.pool.Query(ctx, q, rng.TZName, authevents.KindIPBan, rng.Start, rng.End)
	if err != nil {
		return nil, fmt.Errorf("counting bans per day: %w", err)
	}
	defer rows.Close()

	var out []DayCount
	for rows.Next() {
		var day time.Time
		var count int
		if err := rows.Scan(&day, &count); err != nil {
			return nil, fmt.Errorf("scanning bans per day: %w", err)
		}
		out = append(out, DayCount{Day: day.Format("2006-01-02"), Count: count})
	}
	return out, rows.Err()
}

// Overview is what GET /admin/stats returns — OperatorActionsPerDay/
// OperatorActionsByType are nil for a regular admin (see Service.
// Overview's includeOperatorStats parameter) and non-nil, possibly empty,
// for a superadmin; the HTTP handler is what turns "nil" into "the field
// is absent from the JSON" rather than this package.
type Overview struct {
	RangeParam     string
	TZName         string
	UsersTotal     int
	UsersBanned    int
	UsersPerDay    []DayCount
	UsersPerTenant []TenantCount

	// LoginsByDay/FailuresByTenant/TopFailingIPs/BansByDay are "tanda 2" —
	// end-user authentication activity (internal/authevents) — always
	// present for both a regular admin and a superadmin, unlike
	// OperatorActionsPerDay/OperatorActionsByType below: this is about
	// what end users are doing, not operator visibility, so there's no
	// reason to restrict it the same way GET /admin/audit is.
	LoginsByDay      []LoginDayCount
	FailuresByTenant []TenantLoginCount
	TopFailingIPs    []IPFailureCount
	BansByDay        []DayCount

	OperatorActionsPerDay []DayActionCount
	OperatorActionsByType []ActionTypeCount
}

// Service is what the HTTP handler calls — see Overview's doc comment.
type Service struct {
	repo *Repository
}

func NewService(repo *Repository) *Service {
	return &Service{repo: repo}
}

// zeroFillDays merges counts (only the days that had data) onto days
// (every day in the window) so the response never has a gap — the panel
// can chart Days directly without checking for missing entries.
func zeroFillDays(days []string, counts []DayCount) []DayCount {
	byDay := make(map[string]int, len(counts))
	for _, c := range counts {
		byDay[c.Day] = c.Count
	}
	out := make([]DayCount, len(days))
	for i, d := range days {
		out[i] = DayCount{Day: d, Count: byDay[d]}
	}
	return out
}

// zeroFillLoginDays mirrors zeroFillActionDays for LoginsByDay.
func zeroFillLoginDays(days []string, counts []LoginDayCount) []LoginDayCount {
	byDay := make(map[string]LoginDayCount, len(counts))
	for _, c := range counts {
		byDay[c.Day] = c
	}
	out := make([]LoginDayCount, len(days))
	for i, d := range days {
		c := byDay[d]
		c.Day = d
		out[i] = c
	}
	return out
}

func zeroFillActionDays(days []string, counts []DayActionCount) []DayActionCount {
	byDay := make(map[string]DayActionCount, len(counts))
	for _, c := range counts {
		byDay[c.Day] = c
	}
	out := make([]DayActionCount, len(days))
	for i, d := range days {
		dc := byDay[d]
		dc.Day = d
		out[i] = dc
	}
	return out
}

// Overview computes the full response for rng. failedActions is the list
// of audit.Action* values that count toward OperatorActionsPerDay's
// Failed field — the caller (httpserver) passes it in rather than this
// package importing internal/audit, same reasoning as the Repository
// method's own doc comment. includeOperatorStats is false for a regular
// admin: OperatorActionsPerDay/OperatorActionsByType are left nil
// entirely (not even queried — a regular admin has no use for operator
// visibility, so there's no reason to spend the two extra queries) rather
// than computed and then discarded.
func (s *Service) Overview(ctx context.Context, rangeParam string, rng Range, includeOperatorStats bool, failedActions []string) (*Overview, error) {
	usersTotal, err := s.repo.UsersTotal(ctx)
	if err != nil {
		return nil, err
	}
	usersBanned, err := s.repo.UsersBanned(ctx)
	if err != nil {
		return nil, err
	}
	perDay, err := s.repo.UsersPerDay(ctx, rng)
	if err != nil {
		return nil, err
	}
	perTenant, err := s.repo.UsersPerTenant(ctx, rng, maxTenants)
	if err != nil {
		return nil, err
	}

	out := &Overview{
		RangeParam:     rangeParam,
		TZName:         rng.TZName,
		UsersTotal:     usersTotal,
		UsersBanned:    usersBanned,
		UsersPerDay:    zeroFillDays(rng.Days, perDay),
		UsersPerTenant: perTenant,
	}
	if perTenant == nil {
		out.UsersPerTenant = []TenantCount{}
	}

	loginsByDay, err := s.repo.LoginsByDay(ctx, rng)
	if err != nil {
		return nil, err
	}
	out.LoginsByDay = zeroFillLoginDays(rng.Days, loginsByDay)

	failuresByTenant, err := s.repo.FailuresByTenant(ctx, rng, maxTenants)
	if err != nil {
		return nil, err
	}
	out.FailuresByTenant = failuresByTenant
	if failuresByTenant == nil {
		out.FailuresByTenant = []TenantLoginCount{}
	}

	topFailingIPs, err := s.repo.TopFailingIPs(ctx, rng, maxFailingIPs)
	if err != nil {
		return nil, err
	}
	out.TopFailingIPs = topFailingIPs
	if topFailingIPs == nil {
		out.TopFailingIPs = []IPFailureCount{}
	}

	bansByDay, err := s.repo.BansByDay(ctx, rng)
	if err != nil {
		return nil, err
	}
	out.BansByDay = zeroFillDays(rng.Days, bansByDay)

	if !includeOperatorStats {
		return out, nil
	}

	actionsPerDay, err := s.repo.OperatorActionsPerDay(ctx, rng, failedActions)
	if err != nil {
		return nil, err
	}
	actionsByType, err := s.repo.OperatorActionsByType(ctx, rng, maxActionTypes)
	if err != nil {
		return nil, err
	}
	out.OperatorActionsPerDay = zeroFillActionDays(rng.Days, actionsPerDay)
	out.OperatorActionsByType = actionsByType
	if actionsByType == nil {
		out.OperatorActionsByType = []ActionTypeCount{}
	}
	return out, nil
}

// LoadLocation resolves tzName the way GET /admin/stats' tz query param
// is specified to behave: "" means UTC (the default when the param is
// omitted), the literal "Local" is refused outright even though Go's own
// time.LoadLocation accepts it as a special case meaning "the server's
// local timezone" — silently cutting days by whatever zone the container
// happens to be running in would be exactly the kind of inconsistent,
// environment-dependent behavior this tz parameter exists to avoid, and
// "Local" isn't a real IANA zone name a client could have meant on
// purpose anyway. Any other invalid name surfaces time.LoadLocation's own
// error.
func LoadLocation(tzName string) (*time.Location, error) {
	if tzName == "" {
		return time.UTC, nil
	}
	if strings.EqualFold(tzName, "Local") {
		return nil, fmt.Errorf(`invalid timezone %q`, tzName)
	}
	return time.LoadLocation(tzName)
}
