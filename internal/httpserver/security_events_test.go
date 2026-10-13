package httpserver_test

// Covers GET /admin/security/events: filters (tenant/kind/method/result/ip),
// the from/to range rules (defaulting, 90-day cap, from-after-to), pagination/
// ordering, that admin and superadmin both get access (unlike GET
// /admin/audit, superadmin-only), that email_hash never appears in the
// response, and that an event with no tenant/user attribution doesn't break
// the JSON. The underlying query itself (joins, COALESCE-to-"" handling) is
// exercised indirectly through these — there's no separate
// internal/authevents repository-level test file for ListEvents because the
// interesting behavior here is almost entirely about the HTTP contract
// (filter validation, range rules, response shape), not the SQL.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp"

	"auth-2fa-api/internal/adminauth"
	"auth-2fa-api/internal/testutil"
)

// insertSecurityEvent is stats_test.go's insertAuthEvent, extended with the
// extra columns this endpoint's response needs to cover (method, user_id,
// ban_origin, actor_email) — kept local to this package rather than shared,
// same reasoning stats_test.go's own copy already established (each test
// package owns its row-insertion helper rather than exporting one from
// production code just for tests).
func insertSecurityEvent(t *testing.T, pool *pgxpool.Pool, apiClientID, userID, kind, method, result, ip, banOrigin, actorEmail string, createdAt time.Time) int64 {
	t.Helper()
	const q = `
		INSERT INTO auth_events (api_client_id, user_id, kind, method, result, ip, ban_origin, actor_email, user_agent, created_at)
		VALUES (NULLIF($1, '')::uuid, NULLIF($2, '')::uuid, $3, NULLIF($4, ''), $5, NULLIF($6, '')::inet, NULLIF($7, ''), NULLIF($8, ''), '', $9)
		RETURNING id`
	var id int64
	if err := pool.QueryRow(context.Background(), q, apiClientID, userID, kind, method, result, ip, banOrigin, actorEmail, createdAt).Scan(&id); err != nil {
		t.Fatalf("inserting test auth_events row: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM auth_events WHERE id = $1`, id)
	})
	return id
}

func loginRegularAdminForSecurityEvents(t *testing.T, r http.Handler, adminAccounts *adminauth.Service, pool *pgxpool.Pool) *http.Cookie {
	t.Helper()
	email := "secev-admin-" + testutil.UniqueSuffix(t) + "@example.com"
	account, otpauthURL, err := adminAccounts.CreateAccount(t.Context(), email, "correct-horse-battery", adminauth.RoleAdmin)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM admin_accounts WHERE id = $1`, account.ID)
	})
	key, err := otp.NewKeyFromURL(otpauthURL)
	if err != nil {
		t.Fatalf("parsing otpauth url: %v", err)
	}
	return loginAsAdmin(t, r, email, "correct-horse-battery", key.Secret())
}

type securityEventJSON struct {
	ID         int64          `json:"id"`
	CreatedAt  string         `json:"created_at"`
	Kind       string         `json:"kind"`
	Method     *string        `json:"method"`
	Result     string         `json:"result"`
	Tenant     map[string]any `json:"tenant"`
	User       map[string]any `json:"user"`
	IP         string         `json:"ip"`
	UserAgent  string         `json:"user_agent"`
	BanOrigin  *string        `json:"ban_origin"`
	ActorEmail *string        `json:"actor_email"`
	IsDecoy    bool           `json:"is_decoy"`
}

type listSecurityEventsJSON struct {
	Events []securityEventJSON `json:"events"`
	Page   int                 `json:"page"`
	Total  int                 `json:"total"`
}

func TestSecurityEvents_NoSession_Returns401(t *testing.T) {
	r, _, _, _ := newTestRouterWithAdminPanel(t)

	rec := adminPanelRequest(r, http.MethodGet, "/admin/security/events", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /admin/security/events with no session: status = %d, want 401", rec.Code)
	}
}

func TestSecurityEvents_RegularAdminAndSuperAdminBothGetAccess(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)

	adminCookie := loginRegularAdminForSecurityEvents(t, r, adminAccounts, pool)
	if rec := adminPanelRequest(r, http.MethodGet, "/admin/security/events", adminCookie); rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/security/events as regular admin: status = %d, body = %s, want 200 (unlike GET /admin/audit, this isn't superadmin-only)", rec.Code, rec.Body.String())
	}

	email := "secev-super-" + testutil.UniqueSuffix(t) + "@example.com"
	account, otpauthURL, err := adminAccounts.CreateAccount(t.Context(), email, "correct-horse-battery", adminauth.RoleSuperAdmin)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM admin_accounts WHERE id = $1`, account.ID) })
	key, err := otp.NewKeyFromURL(otpauthURL)
	if err != nil {
		t.Fatalf("parsing otpauth url: %v", err)
	}
	superCookie := loginAsAdmin(t, r, email, "correct-horse-battery", key.Secret())
	if rec := adminPanelRequest(r, http.MethodGet, "/admin/security/events", superCookie); rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/security/events as superadmin: status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestSecurityEvents_FilterByTenantKindMethodResultIP(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)
	cookie := loginRegularAdminForSecurityEvents(t, r, adminAccounts, pool)
	client, _ := testutil.NewAPIClient(t, pool)
	other, _ := testutil.NewAPIClient(t, pool)

	now := time.Now()
	ip := "203.0.113.77"
	target := insertSecurityEvent(t, pool, client.ID, "", "login", "password", "bad_credentials", ip, "", "", now)
	insertSecurityEvent(t, pool, other.ID, "", "login", "password", "bad_credentials", ip, "", "", now)              // different tenant
	insertSecurityEvent(t, pool, client.ID, "", "register", "", "email_taken", ip, "", "", now)                      // different kind
	insertSecurityEvent(t, pool, client.ID, "", "login", "totp", "bad_credentials", ip, "", "", now)                 // different method
	insertSecurityEvent(t, pool, client.ID, "", "login", "password", "success", ip, "", "", now)                     // different result
	insertSecurityEvent(t, pool, client.ID, "", "login", "password", "bad_credentials", "198.51.100.9", "", "", now) // different ip

	url := "/admin/security/events?tenant=" + client.ID + "&kind=login&method=password&result=bad_credentials&ip=" + ip
	rec := adminPanelRequest(r, http.MethodGet, url, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: status = %d, body = %s", url, rec.Code, rec.Body.String())
	}
	var resp listSecurityEventsJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if len(resp.Events) != 1 || resp.Events[0].ID != target {
		t.Fatalf("filtered events = %+v, want exactly the one matching row (id=%d)", resp.Events, target)
	}
}

func TestSecurityEvents_OrderIsCreatedAtThenIDDescending(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)
	cookie := loginRegularAdminForSecurityEvents(t, r, adminAccounts, pool)
	client, _ := testutil.NewAPIClient(t, pool)

	// Same timestamp, twice — only the id DESC tie-break can order these
	// two consistently.
	sameInstant := time.Now()
	first := insertSecurityEvent(t, pool, client.ID, "", "login", "password", "bad_credentials", "", "", "", sameInstant)
	second := insertSecurityEvent(t, pool, client.ID, "", "login", "password", "bad_credentials", "", "", "", sameInstant)

	rec := adminPanelRequest(r, http.MethodGet, "/admin/security/events?tenant="+client.ID, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/security/events: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp listSecurityEventsJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if len(resp.Events) != 2 || resp.Events[0].ID != second || resp.Events[1].ID != first {
		t.Fatalf("events = %+v, want [%d, %d] (created_at DESC, id DESC tie-break)", resp.Events, second, first)
	}
}

func TestSecurityEvents_Pagination(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)
	cookie := loginRegularAdminForSecurityEvents(t, r, adminAccounts, pool)
	client, _ := testutil.NewAPIClient(t, pool)

	// Offsets into the past, not the future: the default "to" the handler
	// resolves is its own time.Now() call, a few milliseconds after these
	// inserts — an event timestamped seconds into the future relative to
	// that would fall outside the range and never match.
	now := time.Now()
	for i := 0; i < 3; i++ {
		insertSecurityEvent(t, pool, client.ID, "", "login", "password", "bad_credentials", "", "", "", now.Add(-time.Duration(i)*time.Second))
	}

	rec := adminPanelRequest(r, http.MethodGet, "/admin/security/events?tenant="+client.ID+"&page=1&page_size=2", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/security/events page 1: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var page1 listSecurityEventsJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &page1); err != nil {
		t.Fatalf("decoding page 1: %v", err)
	}
	if len(page1.Events) != 2 || page1.Total != 3 || page1.Page != 1 {
		t.Fatalf("page 1 = %+v, want 2 events, total=3, page=1", page1)
	}

	rec = adminPanelRequest(r, http.MethodGet, "/admin/security/events?tenant="+client.ID+"&page=2&page_size=2", cookie)
	var page2 listSecurityEventsJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &page2); err != nil {
		t.Fatalf("decoding page 2: %v", err)
	}
	if len(page2.Events) != 1 || page2.Total != 3 || page2.Page != 2 {
		t.Fatalf("page 2 = %+v, want 1 event, total=3, page=2", page2)
	}
}

func TestSecurityEvents_EventWithoutTenantOrUser_DoesNotBreakJSON(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)
	cookie := loginRegularAdminForSecurityEvents(t, r, adminAccounts, pool)

	now := time.Now()
	id := insertSecurityEvent(t, pool, "", "", "login", "password", "bad_credentials", "", "", "", now)

	rec := adminPanelRequest(r, http.MethodGet, "/admin/security/events?kind=login&result=bad_credentials", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/security/events: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp listSecurityEventsJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	var found *securityEventJSON
	for i := range resp.Events {
		if resp.Events[i].ID == id {
			found = &resp.Events[i]
		}
	}
	if found == nil {
		t.Fatalf("no event with id %d in response", id)
	}
	if found.User != nil {
		t.Fatalf("User = %+v, want nil for an event with no user_id", found.User)
	}
	if id, present := found.Tenant["id"]; present && id != "" {
		t.Fatalf(`Tenant["id"] = %v, want absent or "" for an event with no api_client_id`, id)
	}
}

func TestSecurityEvents_UserPresentWhenAttributed(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)
	cookie := loginRegularAdminForSecurityEvents(t, r, adminAccounts, pool)
	client, _ := testutil.NewAPIClient(t, pool)
	u := testutil.NewUser(t, pool, client.ID, "correcthorsebattery")

	id := insertSecurityEvent(t, pool, client.ID, u.ID, "login", "password", "success", "", "", "", time.Now())

	rec := adminPanelRequest(r, http.MethodGet, "/admin/security/events?tenant="+client.ID+"&result=success", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/security/events: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp listSecurityEventsJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	var found *securityEventJSON
	for i := range resp.Events {
		if resp.Events[i].ID == id {
			found = &resp.Events[i]
		}
	}
	if found == nil {
		t.Fatalf("no event with id %d in response", id)
	}
	if found.User == nil || found.User["id"] != u.ID || found.User["email"] != u.Email {
		t.Fatalf("User = %+v, want {id: %q, email: %q}", found.User, u.ID, u.Email)
	}
}

func TestSecurityEvents_BanFields_NullOutsideBanKinds(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)
	cookie := loginRegularAdminForSecurityEvents(t, r, adminAccounts, pool)
	client, _ := testutil.NewAPIClient(t, pool)

	loginID := insertSecurityEvent(t, pool, client.ID, "", "login", "password", "bad_credentials", "", "", "", time.Now())
	banID := insertSecurityEvent(t, pool, client.ID, "", "ip_ban", "", "banned", "203.0.113.50", "automatic", "", time.Now())

	rec := adminPanelRequest(r, http.MethodGet, "/admin/security/events?tenant="+client.ID, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/security/events: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp listSecurityEventsJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	var loginEvt, banEvt *securityEventJSON
	for i := range resp.Events {
		switch resp.Events[i].ID {
		case loginID:
			loginEvt = &resp.Events[i]
		case banID:
			banEvt = &resp.Events[i]
		}
	}
	if loginEvt == nil || banEvt == nil {
		t.Fatalf("missing expected events in %+v", resp.Events)
	}
	if loginEvt.BanOrigin != nil || loginEvt.Method == nil {
		t.Fatalf("login event = %+v, want ban_origin nil and method present", loginEvt)
	}
	if banEvt.BanOrigin == nil || *banEvt.BanOrigin != "automatic" || banEvt.Method != nil {
		t.Fatalf("ip_ban event = %+v, want ban_origin \"automatic\" and method nil", banEvt)
	}
}

func TestSecurityEvents_EmailHashNeverInResponse(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)
	cookie := loginRegularAdminForSecurityEvents(t, r, adminAccounts, pool)
	client, _ := testutil.NewAPIClient(t, pool)

	id := insertSecurityEvent(t, pool, client.ID, "", "login", "password", "bad_credentials", "", "", "", time.Now())
	// email_hash isn't settable through insertSecurityEvent's own columns —
	// write it directly, same as a real unresolved-identifier attempt would.
	if _, err := pool.Exec(context.Background(), `UPDATE auth_events SET email_hash = 'deadbeef' WHERE id = $1`, id); err != nil {
		t.Fatalf("setting email_hash: %v", err)
	}

	rec := adminPanelRequest(r, http.MethodGet, "/admin/security/events?tenant="+client.ID, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/security/events: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if containsEmailHashKey(rec.Body.Bytes()) {
		t.Fatalf("response contains an email_hash key, want it never exposed: %s", rec.Body.String())
	}
}

func containsEmailHashKey(body []byte) bool {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return false
	}
	eventsRaw, ok := raw["events"]
	if !ok {
		return false
	}
	var events []map[string]json.RawMessage
	if err := json.Unmarshal(eventsRaw, &events); err != nil {
		return false
	}
	for _, e := range events {
		if _, present := e["email_hash"]; present {
			return true
		}
	}
	return false
}

func TestSecurityEvents_InvalidTenant_Returns400(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)
	cookie := loginRegularAdminForSecurityEvents(t, r, adminAccounts, pool)

	rec := adminPanelRequest(r, http.MethodGet, "/admin/security/events?tenant=not-a-uuid", cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("GET with tenant=not-a-uuid: status = %d, body = %s, want 400 (never 500 from a Postgres syntax error)", rec.Code, rec.Body.String())
	}
}

func TestSecurityEvents_InvalidIP_Returns400(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)
	cookie := loginRegularAdminForSecurityEvents(t, r, adminAccounts, pool)

	rec := adminPanelRequest(r, http.MethodGet, "/admin/security/events?ip=not-an-ip", cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("GET with ip=not-an-ip: status = %d, want 400", rec.Code)
	}
}

func TestSecurityEvents_InvalidFromOrTo_Returns400(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)
	cookie := loginRegularAdminForSecurityEvents(t, r, adminAccounts, pool)

	for _, q := range []string{"from=not-a-date", "to=not-a-date"} {
		rec := adminPanelRequest(r, http.MethodGet, "/admin/security/events?"+q, cookie)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("GET with %s: status = %d, want 400", q, rec.Code)
		}
	}
}

// Unknown kind/method/result/ip (well-formed, just no matches) must return
// an empty list, never an error — the opposite of the malformed-input
// cases above.
func TestSecurityEvents_WellFormedNoMatches_ReturnsEmptyList(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)
	cookie := loginRegularAdminForSecurityEvents(t, r, adminAccounts, pool)

	rec := adminPanelRequest(r, http.MethodGet, "/admin/security/events?kind=not_a_real_kind", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET with an unknown kind: status = %d, body = %s, want 200", rec.Code, rec.Body.String())
	}
	var resp listSecurityEventsJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if len(resp.Events) != 0 {
		t.Fatalf("events = %+v, want empty", resp.Events)
	}
}

func TestSecurityEvents_Range_ToWithoutFrom_DefaultsTo7DaysEndingAtTo(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)
	cookie := loginRegularAdminForSecurityEvents(t, r, adminAccounts, pool)
	client, _ := testutil.NewAPIClient(t, pool)

	to := time.Now().Add(-30 * 24 * time.Hour) // far enough in the past that "now" would never accidentally include it
	inside := insertSecurityEvent(t, pool, client.ID, "", "login", "password", "bad_credentials", "", "", "", to.Add(-time.Hour))
	outside := insertSecurityEvent(t, pool, client.ID, "", "login", "password", "bad_credentials", "", "", "", to.Add(-8*24*time.Hour))

	url := "/admin/security/events?tenant=" + client.ID + "&to=" + to.UTC().Format(time.RFC3339)
	rec := adminPanelRequest(r, http.MethodGet, url, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: status = %d, body = %s", url, rec.Code, rec.Body.String())
	}
	var resp listSecurityEventsJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	var sawInside, sawOutside bool
	for _, e := range resp.Events {
		if e.ID == inside {
			sawInside = true
		}
		if e.ID == outside {
			sawOutside = true
		}
	}
	if !sawInside {
		t.Fatalf("event within the 7-day window ending at to (id=%d) missing from %+v", inside, resp.Events)
	}
	if sawOutside {
		t.Fatalf("event 8 days before to (id=%d) present in %+v, want excluded (default window is 7 days ending at to, not at now)", outside, resp.Events)
	}
}

func TestSecurityEvents_Range_FromWithoutTo_DefaultsToToNow(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)
	cookie := loginRegularAdminForSecurityEvents(t, r, adminAccounts, pool)
	client, _ := testutil.NewAPIClient(t, pool)

	from := time.Now().Add(-time.Hour)
	id := insertSecurityEvent(t, pool, client.ID, "", "login", "password", "bad_credentials", "", "", "", time.Now())

	url := "/admin/security/events?tenant=" + client.ID + "&from=" + from.UTC().Format(time.RFC3339)
	rec := adminPanelRequest(r, http.MethodGet, url, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: status = %d, body = %s", url, rec.Code, rec.Body.String())
	}
	var resp listSecurityEventsJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	var found bool
	for _, e := range resp.Events {
		if e.ID == id {
			found = true
		}
	}
	if !found {
		t.Fatalf("event created just now (id=%d) missing from %+v — to should default to now", id, resp.Events)
	}
}

func TestSecurityEvents_Range_ExceedsMax90Days_Returns400(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)
	cookie := loginRegularAdminForSecurityEvents(t, r, adminAccounts, pool)

	to := time.Now()
	from := to.Add(-91 * 24 * time.Hour)
	url := "/admin/security/events?from=" + from.UTC().Format(time.RFC3339) + "&to=" + to.UTC().Format(time.RFC3339)
	rec := adminPanelRequest(r, http.MethodGet, url, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("GET with a 91-day range: status = %d, body = %s, want 400 (never silently clamped)", rec.Code, rec.Body.String())
	}
}

func TestSecurityEvents_Range_FromAfterTo_Returns400(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)
	cookie := loginRegularAdminForSecurityEvents(t, r, adminAccounts, pool)

	to := time.Now().Add(-24 * time.Hour)
	from := time.Now()
	url := "/admin/security/events?from=" + from.UTC().Format(time.RFC3339) + "&to=" + to.UTC().Format(time.RFC3339)
	rec := adminPanelRequest(r, http.MethodGet, url, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("GET with from after to: status = %d, body = %s, want 400", rec.Code, rec.Body.String())
	}
}
