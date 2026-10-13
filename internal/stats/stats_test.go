package stats_test

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"auth-2fa-api/internal/stats"
	"auth-2fa-api/internal/testutil"
)

func TestParseRangeDays(t *testing.T) {
	if days, ok := stats.ParseRangeDays("7d"); !ok || days != 7 {
		t.Fatalf(`ParseRangeDays("7d") = (%d, %v), want (7, true)`, days, ok)
	}
	if days, ok := stats.ParseRangeDays("30d"); !ok || days != 30 {
		t.Fatalf(`ParseRangeDays("30d") = (%d, %v), want (30, true)`, days, ok)
	}
	for _, bad := range []string{"", "7", "90d", "7D", "1y"} {
		if _, ok := stats.ParseRangeDays(bad); ok {
			t.Fatalf("ParseRangeDays(%q) = ok, want rejected", bad)
		}
	}
}

func TestLoadLocation_EmptyMeansUTC(t *testing.T) {
	loc, err := stats.LoadLocation("")
	if err != nil || loc != time.UTC {
		t.Fatalf("LoadLocation(\"\") = (%v, %v), want (time.UTC, nil)", loc, err)
	}
}

// "Local" is a real, valid argument to Go's own time.LoadLocation (it
// means "the server's own timezone") — refused anyway, see stats.
// LoadLocation's doc comment for why a client-supplied tz should never
// silently fall back to wherever the container happens to be running.
func TestLoadLocation_RejectsLocal(t *testing.T) {
	for _, v := range []string{"Local", "local", "LOCAL"} {
		if _, err := stats.LoadLocation(v); err == nil {
			t.Fatalf("LoadLocation(%q) = nil error, want it rejected", v)
		}
	}
}

func TestLoadLocation_AcceptsRealIANAZone(t *testing.T) {
	loc, err := stats.LoadLocation("America/Santiago")
	if err != nil {
		t.Fatalf("LoadLocation(\"America/Santiago\"): %v", err)
	}
	if loc.String() != "America/Santiago" {
		t.Fatalf("LoadLocation(\"America/Santiago\").String() = %q, want \"America/Santiago\"", loc.String())
	}
}

func TestLoadLocation_RejectsUnknownZone(t *testing.T) {
	if _, err := stats.LoadLocation("Not/A_Real_Zone"); err == nil {
		t.Fatal("LoadLocation(\"Not/A_Real_Zone\") = nil error, want it rejected")
	}
}

// ResolveRange must cut by calendar day in the GIVEN timezone, not UTC —
// the whole reason tz is a parameter at all. Pick a moment and a zone
// where "today" in that zone is a different calendar date than "today"
// in UTC, and confirm the window's Days labels (and End boundary) land on
// the zone's date, not UTC's.
func TestResolveRange_CutsByDayInGivenTimezone(t *testing.T) {
	loc, err := stats.LoadLocation("America/Santiago")
	if err != nil {
		t.Fatalf("LoadLocation: %v", err)
	}
	// 02:00 UTC on 2026-03-10 is still 2026-03-09 at 23:00 in
	// America/Santiago (UTC-3 that time of year) — "today" must be the
	// 9th, not the 10th.
	now := time.Date(2026, 3, 10, 2, 0, 0, 0, time.UTC)

	rng := stats.ResolveRange(7, loc, now)

	wantLastDay := "2026-03-09"
	if got := rng.Days[len(rng.Days)-1]; got != wantLastDay {
		t.Fatalf("last day = %q, want %q (today in America/Santiago, not UTC)", got, wantLastDay)
	}
	wantFirstDay := "2026-03-03"
	if got := rng.Days[0]; got != wantFirstDay {
		t.Fatalf("first day = %q, want %q (7 days including today)", got, wantFirstDay)
	}
	if len(rng.Days) != 7 {
		t.Fatalf("len(Days) = %d, want 7", len(rng.Days))
	}
	if rng.TZName != "America/Santiago" {
		t.Fatalf("TZName = %q, want %q", rng.TZName, "America/Santiago")
	}
	// End is exclusive, the instant the day AFTER "today" (in the zone)
	// begins — 2026-03-10 00:00 America/Santiago.
	wantEnd := time.Date(2026, 3, 10, 0, 0, 0, 0, loc)
	if !rng.End.Equal(wantEnd) {
		t.Fatalf("End = %v, want %v", rng.End, wantEnd)
	}
}

func TestResolveRange_UTCDefault(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	rng := stats.ResolveRange(30, time.UTC, now)
	if len(rng.Days) != 30 {
		t.Fatalf("len(Days) = %d, want 30", len(rng.Days))
	}
	if rng.Days[len(rng.Days)-1] != "2026-06-15" {
		t.Fatalf("last day = %q, want 2026-06-15", rng.Days[len(rng.Days)-1])
	}
	if rng.TZName != "UTC" {
		t.Fatalf("TZName = %q, want \"UTC\"", rng.TZName)
	}
}

// TestRepository_UsersTotalAndBanned_ReflectsChanges checks relative
// deltas, not absolute counts — users is a shared, persistent table
// across every test in this suite (see testutil.PostgresPool's doc
// comment), so an exact total would be flaky by construction; the delta
// a single test itself causes is always exact.
func TestRepository_UsersTotalAndBanned_ReflectsChanges(t *testing.T) {
	pool := testutil.PostgresPool(t)
	repo := stats.NewRepository(pool)
	ctx := context.Background()

	totalBefore, err := repo.UsersTotal(ctx)
	if err != nil {
		t.Fatalf("UsersTotal (before): %v", err)
	}
	bannedBefore, err := repo.UsersBanned(ctx)
	if err != nil {
		t.Fatalf("UsersBanned (before): %v", err)
	}

	client, _ := testutil.NewAPIClient(t, pool)
	_ = testutil.NewUser(t, pool, client.ID, "correcthorsebattery")
	u2 := testutil.NewUser(t, pool, client.ID, "correcthorsebattery")
	if _, err := pool.Exec(ctx, `UPDATE users SET is_active = FALSE WHERE id = $1`, u2.ID); err != nil {
		t.Fatalf("banning u2: %v", err)
	}

	totalAfter, err := repo.UsersTotal(ctx)
	if err != nil {
		t.Fatalf("UsersTotal (after): %v", err)
	}
	bannedAfter, err := repo.UsersBanned(ctx)
	if err != nil {
		t.Fatalf("UsersBanned (after): %v", err)
	}

	if totalAfter-totalBefore != 2 {
		t.Fatalf("UsersTotal delta = %d, want 2", totalAfter-totalBefore)
	}
	if bannedAfter-bannedBefore != 1 {
		t.Fatalf("UsersBanned delta = %d, want 1", bannedAfter-bannedBefore)
	}
}

// backdateUserCreatedAt directly rewrites a test user's created_at — the
// only way to control which day bucket it lands in, since testutil.
// NewUser always registers at "now".
func backdateUserCreatedAt(t *testing.T, pool *pgxpool.Pool, userID string, ts time.Time) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `UPDATE users SET created_at = $1 WHERE id = $2`, ts, userID); err != nil {
		t.Fatalf("backdating user created_at: %v", err)
	}
}

// UsersPerDay must bucket by calendar day in the range's own timezone —
// backdated 3 days ago (well clear of "today", which concurrently running
// tests also create users under) so this test's delta for that one
// specific day is exact regardless of what else is happening in the
// shared database at the same time.
func TestRepository_UsersPerDay_BucketsByDayInRangeTimezone(t *testing.T) {
	pool := testutil.PostgresPool(t)
	repo := stats.NewRepository(pool)
	ctx := context.Background()

	loc := time.UTC
	now := time.Now().In(loc)
	targetDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc).AddDate(0, 0, -3)
	targetLabel := targetDay.Format("2006-01-02")
	rng := stats.ResolveRange(7, loc, now)

	before, err := repo.UsersPerDay(ctx, rng)
	if err != nil {
		t.Fatalf("UsersPerDay (before): %v", err)
	}
	countBefore := 0
	for _, d := range before {
		if d.Day == targetLabel {
			countBefore = d.Count
		}
	}

	client, _ := testutil.NewAPIClient(t, pool)
	u1 := testutil.NewUser(t, pool, client.ID, "correcthorsebattery")
	u2 := testutil.NewUser(t, pool, client.ID, "correcthorsebattery")
	backdateUserCreatedAt(t, pool, u1.ID, targetDay.Add(3*time.Hour))
	backdateUserCreatedAt(t, pool, u2.ID, targetDay.Add(20*time.Hour))

	after, err := repo.UsersPerDay(ctx, rng)
	if err != nil {
		t.Fatalf("UsersPerDay (after): %v", err)
	}
	countAfter := 0
	for _, d := range after {
		if d.Day == targetLabel {
			countAfter = d.Count
		}
	}

	if countAfter-countBefore != 2 {
		t.Fatalf("UsersPerDay[%s] delta = %d, want 2 (before=%d, after=%d)", targetLabel, countAfter-countBefore, countBefore, countAfter)
	}
}

// UsersPerTenant groups by api_client_id, which is unique per test (a
// fresh UUID from testutil.NewAPIClient) — so, unlike the whole-table
// counts above, this tenant's OWN row can be asserted exactly: nothing
// else in the shared database could ever share its id.
func TestRepository_UsersPerTenant_TotalsAndNewInRange(t *testing.T) {
	pool := testutil.PostgresPool(t)
	repo := stats.NewRepository(pool)
	ctx := context.Background()

	client, _ := testutil.NewAPIClient(t, pool)
	inRange := testutil.NewUser(t, pool, client.ID, "correcthorsebattery")
	_ = inRange
	outOfRange := testutil.NewUser(t, pool, client.ID, "correcthorsebattery")

	loc := time.UTC
	now := time.Now().In(loc)
	rng := stats.ResolveRange(7, loc, now)
	// Outside the 7-day window (10 days ago) — counts toward Total, not
	// NewInRange.
	backdateUserCreatedAt(t, pool, outOfRange.ID, now.AddDate(0, 0, -10))

	// A limit far beyond maxTenants (50, the real production default —
	// unaffected by this test): the shared test database accumulates
	// leftover tenants across this whole suite's history (well into the
	// thousands), so a smaller limit here risks this test's own rows
	// landing outside the top N and failing for a reason that has
	// nothing to do with the behavior under test.
	rows, err := repo.UsersPerTenant(ctx, rng, 1_000_000)
	if err != nil {
		t.Fatalf("UsersPerTenant: %v", err)
	}
	var got *stats.TenantCount
	for i := range rows {
		if rows[i].APIClientID == client.ID {
			got = &rows[i]
		}
	}
	if got == nil {
		t.Fatalf("no row for api_client_id=%s in %+v", client.ID, rows)
	}
	if got.APIClientName != client.Name {
		t.Fatalf("APIClientName = %q, want %q", got.APIClientName, client.Name)
	}
	if got.Total != 2 {
		t.Fatalf("Total = %d, want 2", got.Total)
	}
	if got.NewInRange != 1 {
		t.Fatalf("NewInRange = %d, want 1 (only the non-backdated user)", got.NewInRange)
	}
}

// Two tenants tied on Total break the tie by api_client_name ascending —
// deterministic ordering, see Repository.UsersPerTenant's doc comment.
func TestRepository_UsersPerTenant_TiesBreakByNameThenID(t *testing.T) {
	pool := testutil.PostgresPool(t)
	repo := stats.NewRepository(pool)
	ctx := context.Background()

	clientA, _ := testutil.NewAPIClient(t, pool)
	clientB, _ := testutil.NewAPIClient(t, pool)
	testutil.NewUser(t, pool, clientA.ID, "correcthorsebattery")
	testutil.NewUser(t, pool, clientB.ID, "correcthorsebattery")

	loc := time.UTC
	rng := stats.ResolveRange(7, loc, time.Now())

	// A limit far beyond maxTenants (50, the real production default —
	// unaffected by this test): the shared test database accumulates
	// leftover tenants across this whole suite's history (well into the
	// thousands), so a smaller limit here risks this test's own rows
	// landing outside the top N and failing for a reason that has
	// nothing to do with the behavior under test.
	rows, err := repo.UsersPerTenant(ctx, rng, 1_000_000)
	if err != nil {
		t.Fatalf("UsersPerTenant: %v", err)
	}
	idxA, idxB := -1, -1
	for i := range rows {
		if rows[i].APIClientID == clientA.ID {
			idxA = i
		}
		if rows[i].APIClientID == clientB.ID {
			idxB = i
		}
	}
	if idxA == -1 || idxB == -1 {
		t.Fatalf("missing one of clientA=%s clientB=%s in %+v", clientA.ID, clientB.ID, rows)
	}
	// testutil.NewAPIClient names them "testclient-<suffix>" with
	// independently random suffixes, so assert relative to whichever
	// name actually sorts first rather than assuming A < B.
	wantAFirst := clientA.Name < clientB.Name
	if wantAFirst && idxA > idxB {
		t.Fatalf("tied totals: %s (idx %d) should sort before %s (idx %d) by name", clientA.Name, idxA, clientB.Name, idxB)
	}
	if !wantAFirst && idxB > idxA {
		t.Fatalf("tied totals: %s (idx %d) should sort before %s (idx %d) by name", clientB.Name, idxB, clientA.Name, idxA)
	}
}

// insertAuditRow writes directly to admin_audit_log, bypassing
// audit.Repository.Insert (which always defaults created_at to now() —
// no way to backdate through it) — same reasoning as
// backdateUserCreatedAt above. action is a fake, test-only string
// (never a real audit.Action* value) so OperatorActionsByType's grouping
// can never collide with a real action some other concurrently running
// test wrote.
func insertAuditRow(t *testing.T, pool *pgxpool.Pool, action string, createdAt time.Time) {
	t.Helper()
	const q = `INSERT INTO admin_audit_log (created_at, actor_email, actor_role, action) VALUES ($1, 'stats-test@example.com', 'superadmin', $2) RETURNING id`
	var id string
	if err := pool.QueryRow(context.Background(), q, createdAt, action).Scan(&id); err != nil {
		t.Fatalf("inserting test audit row: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM admin_audit_log WHERE id = $1`, id)
	})
}

func TestRepository_OperatorActionsPerDay_CountsFailedSeparately(t *testing.T) {
	pool := testutil.PostgresPool(t)
	repo := stats.NewRepository(pool)
	ctx := context.Background()

	loc := time.UTC
	now := time.Now().In(loc)
	targetDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc).AddDate(0, 0, -3)
	targetLabel := targetDay.Format("2006-01-02")
	rng := stats.ResolveRange(7, loc, now)
	failedActions := []string{"stats_test.marker_failed"}

	before, err := repo.OperatorActionsPerDay(ctx, rng, failedActions)
	if err != nil {
		t.Fatalf("OperatorActionsPerDay (before): %v", err)
	}
	var beforeCount, beforeFailed int
	for _, d := range before {
		if d.Day == targetLabel {
			beforeCount, beforeFailed = d.Count, d.Failed
		}
	}

	insertAuditRow(t, pool, "stats_test.marker_ok", targetDay.Add(2*time.Hour))
	insertAuditRow(t, pool, "stats_test.marker_failed", targetDay.Add(4*time.Hour))
	insertAuditRow(t, pool, "stats_test.marker_failed", targetDay.Add(6*time.Hour))

	after, err := repo.OperatorActionsPerDay(ctx, rng, failedActions)
	if err != nil {
		t.Fatalf("OperatorActionsPerDay (after): %v", err)
	}
	var afterCount, afterFailed int
	for _, d := range after {
		if d.Day == targetLabel {
			afterCount, afterFailed = d.Count, d.Failed
		}
	}

	if afterCount-beforeCount != 3 {
		t.Fatalf("count delta = %d, want 3", afterCount-beforeCount)
	}
	if afterFailed-beforeFailed != 2 {
		t.Fatalf("failed delta = %d, want 2", afterFailed-beforeFailed)
	}
}

func TestRepository_OperatorActionsByType_TopOrderedByCount(t *testing.T) {
	pool := testutil.PostgresPool(t)
	repo := stats.NewRepository(pool)
	ctx := context.Background()

	loc := time.UTC
	now := time.Now().In(loc)
	rng := stats.ResolveRange(7, loc, now)

	insertAuditRow(t, pool, "stats_test.frequent", now.Add(-time.Hour))
	insertAuditRow(t, pool, "stats_test.frequent", now.Add(-2*time.Hour))
	insertAuditRow(t, pool, "stats_test.frequent", now.Add(-3*time.Hour))
	insertAuditRow(t, pool, "stats_test.rare", now.Add(-time.Hour))

	rows, err := repo.OperatorActionsByType(ctx, rng, 1000)
	if err != nil {
		t.Fatalf("OperatorActionsByType: %v", err)
	}
	var frequent, rare *stats.ActionTypeCount
	for i := range rows {
		switch rows[i].Action {
		case "stats_test.frequent":
			frequent = &rows[i]
		case "stats_test.rare":
			rare = &rows[i]
		}
	}
	if frequent == nil || rare == nil {
		t.Fatalf("missing test actions in %+v", rows)
	}
	if frequent.Count != 3 {
		t.Fatalf("frequent.Count = %d, want 3", frequent.Count)
	}
	if rare.Count != 1 {
		t.Fatalf("rare.Count = %d, want 1", rare.Count)
	}
}

// Service.Overview must zero-fill every day in the window, not just the
// ones with data — the whole point of returning Days up front.
func TestService_Overview_ZeroFillsDaysWithNoUserActivity(t *testing.T) {
	pool := testutil.PostgresPool(t)
	svc := stats.NewService(stats.NewRepository(pool))
	ctx := context.Background()

	loc := time.UTC
	rng := stats.ResolveRange(7, loc, time.Now())

	overview, err := svc.Overview(ctx, "7d", rng, false, nil)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	if len(overview.UsersPerDay) != 7 {
		t.Fatalf("len(UsersPerDay) = %d, want 7 (one per day, zero-filled)", len(overview.UsersPerDay))
	}
	for i, d := range overview.UsersPerDay {
		if d.Day != rng.Days[i] {
			t.Fatalf("UsersPerDay[%d].Day = %q, want %q (order must match rng.Days)", i, d.Day, rng.Days[i])
		}
	}
}

// includeOperatorStats=false must leave both operator fields nil — the
// HTTP handler relies on nil-vs-non-nil to decide whether the JSON field
// appears at all (see statsResponse's own doc comment in httpserver).
func TestService_Overview_OmitsOperatorStatsWhenNotRequested(t *testing.T) {
	pool := testutil.PostgresPool(t)
	svc := stats.NewService(stats.NewRepository(pool))
	ctx := context.Background()
	rng := stats.ResolveRange(7, time.UTC, time.Now())

	overview, err := svc.Overview(ctx, "7d", rng, false, []string{"irrelevant"})
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	if overview.OperatorActionsPerDay != nil {
		t.Fatalf("OperatorActionsPerDay = %+v, want nil when includeOperatorStats=false", overview.OperatorActionsPerDay)
	}
	if overview.OperatorActionsByType != nil {
		t.Fatalf("OperatorActionsByType = %+v, want nil when includeOperatorStats=false", overview.OperatorActionsByType)
	}
}

func TestService_Overview_IncludesOperatorStatsWhenRequested(t *testing.T) {
	pool := testutil.PostgresPool(t)
	svc := stats.NewService(stats.NewRepository(pool))
	ctx := context.Background()
	rng := stats.ResolveRange(7, time.UTC, time.Now())

	overview, err := svc.Overview(ctx, "7d", rng, true, []string{"admin.login_failed"})
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	if overview.OperatorActionsPerDay == nil {
		t.Fatal("OperatorActionsPerDay = nil, want non-nil (even if empty) when includeOperatorStats=true")
	}
	if len(overview.OperatorActionsPerDay) != 7 {
		t.Fatalf("len(OperatorActionsPerDay) = %d, want 7 (zero-filled)", len(overview.OperatorActionsPerDay))
	}
	if overview.OperatorActionsByType == nil {
		t.Fatal("OperatorActionsByType = nil, want non-nil (even if empty) when includeOperatorStats=true")
	}
}

// insertAuthEvent is insertAuditRow's counterpart for auth_events — same
// delta-based-testing reasoning (the shared test database accumulates
// rows across this whole suite's history, so tests assert on the change a
// fresh insert causes, not on an absolute count).
func insertAuthEvent(t *testing.T, pool *pgxpool.Pool, apiClientID, kind, result, ip string, createdAt time.Time) {
	t.Helper()
	const q = `
		INSERT INTO auth_events (api_client_id, kind, result, ip, user_agent, created_at)
		VALUES ($1, $2, $3, NULLIF($4, '')::inet, '', $5)
		RETURNING id`
	var id string
	if err := pool.QueryRow(context.Background(), q, apiClientID, kind, result, ip, createdAt).Scan(&id); err != nil {
		t.Fatalf("inserting test auth_events row: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM auth_events WHERE id = $1`, id)
	})
}

func TestRepository_LoginsByDay_SplitsSuccessAndFailed(t *testing.T) {
	pool := testutil.PostgresPool(t)
	repo := stats.NewRepository(pool)
	ctx := context.Background()
	client, _ := testutil.NewAPIClient(t, pool)

	loc := time.UTC
	now := time.Now().In(loc)
	targetDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc).AddDate(0, 0, -2)
	targetLabel := targetDay.Format("2006-01-02")
	rng := stats.ResolveRange(7, loc, now)

	insertAuthEvent(t, pool, client.ID, "login", "success", "", targetDay.Add(time.Hour))
	insertAuthEvent(t, pool, client.ID, "login", "success", "", targetDay.Add(2*time.Hour))
	insertAuthEvent(t, pool, client.ID, "login", "bad_credentials", "", targetDay.Add(3*time.Hour))
	// A different kind on the same day must not count toward either
	// bucket — confirms the WHERE kind = 'login' filter is actually
	// applied, not just the result split.
	insertAuthEvent(t, pool, client.ID, "register", "success", "", targetDay.Add(4*time.Hour))

	rows, err := repo.LoginsByDay(ctx, rng)
	if err != nil {
		t.Fatalf("LoginsByDay: %v", err)
	}
	var found *stats.LoginDayCount
	for i := range rows {
		if rows[i].Day == targetLabel {
			found = &rows[i]
		}
	}
	if found == nil {
		t.Fatalf("no LoginsByDay row for %s in %+v", targetLabel, rows)
	}
	if found.Success < 2 || found.Failed < 1 {
		t.Fatalf("LoginsByDay[%s] = %+v, want at least Success=2 Failed=1", targetLabel, found)
	}
}

func TestRepository_FailuresByTenant_CountsPerTenant(t *testing.T) {
	pool := testutil.PostgresPool(t)
	repo := stats.NewRepository(pool)
	ctx := context.Background()
	client, _ := testutil.NewAPIClient(t, pool)

	loc := time.UTC
	rng := stats.ResolveRange(7, loc, time.Now())

	insertAuthEvent(t, pool, client.ID, "login", "success", "", time.Now())
	insertAuthEvent(t, pool, client.ID, "login", "bad_credentials", "", time.Now())
	insertAuthEvent(t, pool, client.ID, "login", "bad_credentials", "", time.Now())

	// Same large-limit reasoning as TestRepository_UsersPerTenant_TiesBreakByNameThenID
	// — the shared test database has far more than maxTenants tenants by now.
	rows, err := repo.FailuresByTenant(ctx, rng, 1_000_000)
	if err != nil {
		t.Fatalf("FailuresByTenant: %v", err)
	}
	var found *stats.TenantLoginCount
	for i := range rows {
		if rows[i].APIClientID == client.ID {
			found = &rows[i]
		}
	}
	if found == nil {
		t.Fatalf("no FailuresByTenant row for tenant %s", client.ID)
	}
	if found.Success != 1 || found.Failed != 2 {
		t.Fatalf("FailuresByTenant[%s] = %+v, want Success=1 Failed=2", client.ID, found)
	}
}

func TestRepository_TopFailingIPs_OrderedByFailedDesc(t *testing.T) {
	pool := testutil.PostgresPool(t)
	repo := stats.NewRepository(pool)
	ctx := context.Background()
	client, _ := testutil.NewAPIClient(t, pool)

	loc := time.UTC
	rng := stats.ResolveRange(7, loc, time.Now())

	// A unique, unroutable test IP (TEST-NET-1, RFC 5737) per test run so
	// this doesn't collide with a leftover row from a previous run — the
	// last octet is UniqueSuffix's first byte, parsed as hex into 0-255
	// (UniqueSuffix itself is hex text, not valid as a decimal octet
	// as-is).
	lastOctet, err := strconv.ParseUint(testutil.UniqueSuffix(t)[:2], 16, 8)
	if err != nil {
		t.Fatalf("parsing unique suffix as hex: %v", err)
	}
	ip := fmt.Sprintf("203.0.113.%d", lastOctet)
	insertAuthEvent(t, pool, client.ID, "login", "bad_credentials", ip, time.Now())
	insertAuthEvent(t, pool, client.ID, "login", "bad_credentials", ip, time.Now())
	insertAuthEvent(t, pool, client.ID, "login", "success", ip, time.Now()) // must not count toward Failed

	rows, err := repo.TopFailingIPs(ctx, rng, 1_000_000)
	if err != nil {
		t.Fatalf("TopFailingIPs: %v", err)
	}
	var found *stats.IPFailureCount
	for i := range rows {
		if rows[i].IP == ip {
			found = &rows[i]
		}
	}
	if found == nil {
		t.Fatalf("no TopFailingIPs row for %s in %d rows", ip, len(rows))
	}
	if found.Failed != 2 {
		t.Fatalf("TopFailingIPs[%s].Failed = %d, want 2", ip, found.Failed)
	}
	if found.LastAt.IsZero() {
		t.Fatalf("TopFailingIPs[%s].LastAt is zero, want the last failed attempt's time", ip)
	}
}

func TestRepository_BansByDay_CountsIPBanEvents(t *testing.T) {
	pool := testutil.PostgresPool(t)
	repo := stats.NewRepository(pool)
	ctx := context.Background()
	client, _ := testutil.NewAPIClient(t, pool)

	loc := time.UTC
	now := time.Now().In(loc)
	targetDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc).AddDate(0, 0, -1)
	targetLabel := targetDay.Format("2006-01-02")
	rng := stats.ResolveRange(7, loc, now)

	insertAuthEvent(t, pool, client.ID, "ip_ban", "banned", "203.0.113.9", targetDay.Add(time.Hour))
	insertAuthEvent(t, pool, client.ID, "ip_unban", "unbanned", "203.0.113.9", targetDay.Add(2*time.Hour)) // must not count

	rows, err := repo.BansByDay(ctx, rng)
	if err != nil {
		t.Fatalf("BansByDay: %v", err)
	}
	var found *stats.DayCount
	for i := range rows {
		if rows[i].Day == targetLabel {
			found = &rows[i]
		}
	}
	if found == nil {
		t.Fatalf("no BansByDay row for %s in %+v", targetLabel, rows)
	}
	if found.Count < 1 {
		t.Fatalf("BansByDay[%s].Count = %d, want at least 1", targetLabel, found.Count)
	}
}

// Overview must always include tanda-2 blocks, for a regular admin too —
// unlike OperatorActionsPerDay/OperatorActionsByType, these are never
// gated behind includeOperatorStats.
func TestService_Overview_AlwaysIncludesLoginStatsRegardlessOfRole(t *testing.T) {
	pool := testutil.PostgresPool(t)
	svc := stats.NewService(stats.NewRepository(pool))
	ctx := context.Background()
	rng := stats.ResolveRange(7, time.UTC, time.Now())

	overview, err := svc.Overview(ctx, "7d", rng, false, nil)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	if len(overview.LoginsByDay) != 7 {
		t.Fatalf("len(LoginsByDay) = %d, want 7 (zero-filled) even with includeOperatorStats=false", len(overview.LoginsByDay))
	}
	if len(overview.BansByDay) != 7 {
		t.Fatalf("len(BansByDay) = %d, want 7 (zero-filled) even with includeOperatorStats=false", len(overview.BansByDay))
	}
	if overview.FailuresByTenant == nil {
		t.Fatal("FailuresByTenant = nil, want non-nil (even if empty)")
	}
	if overview.TopFailingIPs == nil {
		t.Fatal("TopFailingIPs = nil, want non-nil (even if empty)")
	}
}
