package httpserver_test

// Covers GET /admin/audit and the audit-log wiring threaded through every
// mutating /admin/* handler — see internal/audit's own package doc comment
// for the design (never blocks the real action, never holds secrets).

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/pquerna/otp"

	"auth-2fa-api/internal/adminauth"
	"auth-2fa-api/internal/apiclient"
	"auth-2fa-api/internal/audit"
	"auth-2fa-api/internal/testutil"
)

// expectedAdminRoutes is the full inventory of mutating (non-GET)
// /admin/* routes, each marked either "audited" (logUserAction/
// logAction/logAccountAction/logOperatorAction fires on success — see
// their own doc comments) or "excluded" (a deliberate, documented
// decision not to write an entry). A route discovered by chi.Walk that
// isn't in this map — or a map entry whose route no longer exists — fails
// the test: a future /admin/* mutation can't be added without someone
// consciously updating this list, which is the whole point (see the
// relayed spec's "test que falle si una ruta... no registra auditoría").
var expectedAdminRoutes = map[string]string{
	"POST /admin/accounts/":                            "audited", // account.create
	"POST /admin/accounts/{id}/reactivate":             "audited", // account.reactivate
	"POST /admin/accounts/{id}/revoke":                 "audited", // account.revoke
	"POST /admin/accounts/{id}/pin/reset":              "audited", // account.pin_reset
	"POST /admin/auth/login":                           "audited", // admin.login / admin.login_failed, logged specially (no session yet)
	"POST /admin/auth/logout":                          "excluded: ending a session isn't a moderation action worth auditing",
	"POST /admin/auth/password":                        "audited", // account.password_change
	"PUT /admin/auth/pin":                              "audited", // account.pin_set / account.pin_change
	"POST /admin/auth/totp/rotate":                     "excluded: step one of two — generates a pending secret but changes nothing real yet; only /rotate/confirm does",
	"POST /admin/auth/totp/rotate/confirm":             "audited", // account.totp_rotate
	"POST /admin/blacklist/allowlist/":                 "audited", // allowlist.add
	"DELETE /admin/blacklist/allowlist/{ip}":           "audited", // allowlist.remove
	"DELETE /admin/blacklist/{ip}":                     "audited", // blacklist.unban
	"POST /admin/clients/":                             "audited", // client.create
	"POST /admin/clients/{id}/activate":                "audited", // client.activate
	"POST /admin/clients/{id}/deactivate":              "audited", // client.deactivate
	"PUT /admin/clients/{id}/panel-base-url":           "audited", // client.set_panel_base_url
	"POST /admin/clients/{id}/rotate":                  "audited", // client.rotate_key
	"DELETE /admin/clients/{id}/system-admin-key":      "audited", // client.system_admin_key_revoke
	"POST /admin/clients/{id}/system-admin-key/rotate": "audited", // client.system_admin_key_rotate
	"POST /admin/users/{id}/ban":                       "audited", // user.ban
	"POST /admin/users/{id}/change-email":              "audited", // user.email_change_request
	"POST /admin/users/{id}/clear-lockouts":            "audited", // user.lockouts_cleared
	"POST /admin/users/{id}/disable-totp":              "audited", // user.totp_disable
	"PUT /admin/users/{id}/login-pin-required":         "audited", // user.login_pin_required_set
	"POST /admin/users/{id}/reset-pin":                 "audited", // user.pin_reset
	"POST /admin/users/{id}/revoke-sessions":           "audited", // user.sessions_revoke
	"POST /admin/users/{id}/unban":                     "audited", // user.unban
}

func TestAdminMutatingRoutesAreAllAudited(t *testing.T) {
	r, _, _, _ := newTestRouterWithAdminPanel(t)
	mux, ok := r.(chi.Routes)
	if !ok {
		t.Fatal("router doesn't implement chi.Routes — can't walk it")
	}

	found := map[string]bool{}
	err := chi.Walk(mux, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if method == http.MethodGet || method == http.MethodOptions || method == http.MethodHead {
			return nil
		}
		if len(route) < len("/admin/") || route[:len("/admin/")] != "/admin/" {
			return nil
		}
		found[method+" "+route] = true
		return nil
	})
	if err != nil {
		t.Fatalf("chi.Walk: %v", err)
	}

	for route := range found {
		if _, known := expectedAdminRoutes[route]; !known {
			t.Errorf("mutating route %q exists but isn't in expectedAdminRoutes — decide whether it should write an audit entry, then add it there", route)
		}
	}
	for route := range expectedAdminRoutes {
		if !found[route] {
			t.Errorf("expectedAdminRoutes lists %q but it's no longer a registered route — remove it from the map", route)
		}
	}
}

func TestAdminAudit_RequiresSuperAdmin(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)

	email := "audit-regular-" + testutil.UniqueSuffix(t) + "@example.com"
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
	cookie := loginAsAdmin(t, r, email, "correct-horse-battery", key.Secret())

	if rec := adminPanelRequest(r, http.MethodGet, "/admin/audit", cookie); rec.Code != http.StatusForbidden {
		t.Fatalf("GET /admin/audit as regular admin: status = %d, want 403", rec.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/audit", nil)
	req.Header.Set("X-Admin-Panel", "1")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /admin/audit with no session: status = %d, want 401", rec.Code)
	}
}

type auditEntryJSON struct {
	ID          string `json:"id"`
	CreatedAt   string `json:"created_at"`
	ActorEmail  string `json:"actor_email"`
	ActorRole   string `json:"actor_role"`
	Action      string `json:"action"`
	TargetType  string `json:"target_type"`
	TargetID    string `json:"target_id"`
	TargetLabel string `json:"target_label"`
	ActorIP     string `json:"actor_ip"`
}

type listAuditJSON struct {
	Entries []auditEntryJSON `json:"entries"`
	Page    int              `json:"page"`
	Total   int              `json:"total"`
}

func getAudit(t *testing.T, r http.Handler, cookie *http.Cookie, query string) listAuditJSON {
	t.Helper()
	rec := adminPanelRequest(r, http.MethodGet, "/admin/audit"+query, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/audit%s: status = %d, body = %s", query, rec.Code, rec.Body.String())
	}
	var resp listAuditJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding /admin/audit response: %v", err)
	}
	return resp
}

// findEntry returns the first entry matching action+targetID, or nil.
func findEntry(entries []auditEntryJSON, action, targetID string) *auditEntryJSON {
	for i := range entries {
		if entries[i].Action == action && entries[i].TargetID == targetID {
			return &entries[i]
		}
	}
	return nil
}

func TestAdminAudit_RecordsClientAndUserActions(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)

	operatorEmail := "audit-super-" + testutil.UniqueSuffix(t) + "@example.com"
	account, otpauthURL, err := adminAccounts.CreateAccount(t.Context(), operatorEmail, "correct-horse-battery", adminauth.RoleSuperAdmin)
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
	cookie := loginAsAdmin(t, r, operatorEmail, "correct-horse-battery", key.Secret())
	mustSetPin(t, r, cookie, "correct-horse-battery", "123456")

	// client.create, with a human-readable target_label (the name).
	clientName := "audit-client-" + testutil.UniqueSuffix(t)
	createRec := adminPanelRequestWithBody(r, http.MethodPost, "/admin/clients", cookie, map[string]string{"name": clientName})
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create client: status = %d, body = %s", createRec.Code, createRec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decoding create client response: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM api_clients WHERE id = $1`, created.ID)
	})

	// user.ban, on a real user row — target_label should be the user's
	// email, resolved server-side (never sent by the client).
	targetClient, _ := testutil.NewAPIClient(t, pool)
	targetUser := testutil.NewUser(t, pool, targetClient.ID, "correcthorsebattery")
	banRec := adminPanelRequestWithBodyAndPin(r, http.MethodPost, "/admin/users/"+targetUser.ID+"/ban", cookie, nil, "123456")
	if banRec.Code != http.StatusNoContent {
		t.Fatalf("ban user: status = %d, body = %s", banRec.Code, banRec.Body.String())
	}

	resp := getAudit(t, r, cookie, "?actor="+operatorEmail+"&page_size=50")

	createEntry := findEntry(resp.Entries, audit.ActionClientCreate, created.ID)
	if createEntry == nil {
		t.Fatalf("no audit entry for client.create (target_id=%s) — entries: %+v", created.ID, resp.Entries)
	}
	if createEntry.ActorEmail != operatorEmail || createEntry.ActorRole != string(adminauth.RoleSuperAdmin) ||
		createEntry.TargetType != audit.TargetTypeClient || createEntry.TargetLabel != clientName {
		t.Fatalf("client.create entry = %+v, want actor=%q role=%q target_type=%q target_label=%q",
			createEntry, operatorEmail, adminauth.RoleSuperAdmin, audit.TargetTypeClient, clientName)
	}
	if _, err := time.Parse(time.RFC3339, createEntry.CreatedAt); err != nil {
		t.Fatalf("created_at = %q is not RFC 3339: %v", createEntry.CreatedAt, err)
	}

	banEntry := findEntry(resp.Entries, audit.ActionUserBan, targetUser.ID)
	if banEntry == nil {
		t.Fatalf("no audit entry for user.ban (target_id=%s) — entries: %+v", targetUser.ID, resp.Entries)
	}
	if banEntry.TargetType != audit.TargetTypeUser || banEntry.TargetLabel != targetUser.Email {
		t.Fatalf("user.ban entry = %+v, want target_type=%q target_label=%q (the user's email)",
			banEntry, audit.TargetTypeUser, targetUser.Email)
	}

	// action filter alone narrows correctly.
	onlyBans := getAudit(t, r, cookie, "?actor="+operatorEmail+"&action="+audit.ActionUserBan)
	for _, e := range onlyBans.Entries {
		if e.Action != audit.ActionUserBan {
			t.Fatalf("action=%s filter returned a %q entry", audit.ActionUserBan, e.Action)
		}
	}
	if findEntry(onlyBans.Entries, audit.ActionUserBan, targetUser.ID) == nil {
		t.Fatal("action filter excluded the ban entry it should have included")
	}
}

// The exact same handler backs /system-admin/users/{id}/ban — called with
// a tenant's own scoped credential, not an operator identity. That's
// never "an operator's own action" in the sense this audit log exists
// for (see AdminHandlers.logUserAction's doc comment), so it must not
// write an entry.
func TestAdminAudit_SystemAdminActionsAreNotLogged(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)

	operatorEmail := "audit-super2-" + testutil.UniqueSuffix(t) + "@example.com"
	account, otpauthURL, err := adminAccounts.CreateAccount(t.Context(), operatorEmail, "correct-horse-battery", adminauth.RoleSuperAdmin)
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
	cookie := loginAsAdmin(t, r, operatorEmail, "correct-horse-battery", key.Secret())

	apiClients := apiclient.NewService(apiclient.NewRepository(pool))
	client, _ := testutil.NewAPIClient(t, pool)
	systemAdminKey, err := apiClients.RotateSystemAdminKey(t.Context(), client.ID)
	if err != nil {
		t.Fatalf("RotateSystemAdminKey: %v", err)
	}
	targetUser := testutil.NewUser(t, pool, client.ID, "correcthorsebattery")

	req := httptest.NewRequest(http.MethodPost, "/system-admin/users/"+targetUser.ID+"/ban", bytes.NewReader(nil))
	req.Header.Set("X-System-Admin-Token", systemAdminKey)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("system-admin ban: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	resp := getAudit(t, r, cookie, "?action="+audit.ActionUserBan+"&page_size=100")
	if findEntry(resp.Entries, audit.ActionUserBan, targetUser.ID) != nil {
		t.Fatal("a /system-admin/* ban wrote an audit entry — it should not, that's not an operator action")
	}
}

func TestAdminAudit_LoginSuccessAndFailure(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)

	loginEmail := "audit-login-" + testutil.UniqueSuffix(t) + "@example.com"
	account, otpauthURL, err := adminAccounts.CreateAccount(t.Context(), loginEmail, "correct-horse-battery", adminauth.RoleSuperAdmin)
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

	// A wrong password first.
	badBody, _ := json.Marshal(map[string]string{"email": loginEmail, "password": "nope", "totp_code": "000000"})
	badReq := httptest.NewRequest(http.MethodPost, "/admin/auth/login", bytes.NewReader(badBody))
	badReq.Header.Set("Content-Type", "application/json")
	badRec := httptest.NewRecorder()
	r.ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusUnauthorized {
		t.Fatalf("bad login: status = %d, want 401", badRec.Code)
	}

	// Then a real login — also the easiest way to get a cookie to read
	// /admin/audit with afterward.
	cookie := loginAsAdmin(t, r, loginEmail, "correct-horse-battery", key.Secret())

	resp := getAudit(t, r, cookie, "?actor="+loginEmail+"&page_size=50")

	var sawFailed, sawSucceeded bool
	for _, e := range resp.Entries {
		if e.Action == audit.ActionAdminLoginFailed && e.TargetLabel == loginEmail {
			sawFailed = true
		}
		if e.Action == audit.ActionAdminLogin && e.TargetLabel == loginEmail && e.ActorRole == string(adminauth.RoleSuperAdmin) {
			sawSucceeded = true
		}
	}
	if !sawFailed {
		t.Fatalf("no admin.login_failed entry for the wrong-password attempt — entries: %+v", resp.Entries)
	}
	if !sawSucceeded {
		t.Fatalf("no admin.login entry (with role) for the successful login — entries: %+v", resp.Entries)
	}
}

func TestAdminAudit_SelfServicePasswordChange(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)

	email := "audit-selfservice-" + testutil.UniqueSuffix(t) + "@example.com"
	account, otpauthURL, err := adminAccounts.CreateAccount(t.Context(), email, "old-password-1", adminauth.RoleAdmin)
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
	cookie := loginAsAdmin(t, r, email, "old-password-1", key.Secret())
	mustSetPin(t, r, cookie, "old-password-1", "123456")

	rec := adminPanelRequestWithBodyAndPin(r, http.MethodPost, "/admin/auth/password", cookie,
		map[string]string{"current_password": "old-password-1", "new_password": "new-password-1"}, "123456")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("change password: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// A regular admin can't read /admin/audit (superadmin-only) — use a
	// fresh superadmin just to read the log back.
	superEmail := "audit-selfservice-reader-" + testutil.UniqueSuffix(t) + "@example.com"
	superAccount, superURL, err := adminAccounts.CreateAccount(t.Context(), superEmail, "correct-horse-battery", adminauth.RoleSuperAdmin)
	if err != nil {
		t.Fatalf("CreateAccount(reader): %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM admin_accounts WHERE id = $1`, superAccount.ID)
	})
	superKey, err := otp.NewKeyFromURL(superURL)
	if err != nil {
		t.Fatalf("parsing otpauth url: %v", err)
	}
	superCookie := loginAsAdmin(t, r, superEmail, "correct-horse-battery", superKey.Secret())

	resp := getAudit(t, r, superCookie, "?actor="+email+"&action="+audit.ActionAccountPasswordChange)
	if len(resp.Entries) != 1 || resp.Entries[0].TargetLabel != email {
		t.Fatalf("account.password_change entries for %s = %+v, want exactly one with target_label=%q", email, resp.Entries, email)
	}
}
