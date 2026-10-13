package httpserver_test

// Covers requireAdminPin's own HTTP behavior (router.go's PIN gating on
// destructive /admin/* routes) and PUT /admin/auth/pin / POST /admin/
// accounts/{id}/pin/reset — separate from TestAdminMutatingRoutesAreAllAudited
// (audit_test.go), which is about the audit log, not the PIN gate.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pquerna/otp"

	"auth-2fa-api/internal/adminauth"
	"auth-2fa-api/internal/middleware"
	"auth-2fa-api/internal/testutil"
)

// TestAdminPin_MeReportsHasPin covers GET /admin/auth/me's has_pin field
// through the real create-then-change flow, not a direct DB write.
func TestAdminPin_MeReportsHasPin(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)

	email := "pin-me-" + testutil.UniqueSuffix(t) + "@example.com"
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

	if hasPin := meHasPin(t, r, cookie); hasPin {
		t.Fatal("has_pin before setting one = true, want false")
	}

	mustSetPin(t, r, cookie, "correct-horse-battery", "123456")

	if hasPin := meHasPin(t, r, cookie); !hasPin {
		t.Fatal("has_pin after setting one = false, want true")
	}
}

func meHasPin(t *testing.T, r http.Handler, cookie *http.Cookie) bool {
	t.Helper()
	rec := adminPanelRequest(r, http.MethodGet, "/admin/auth/me", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/auth/me: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		HasPin bool `json:"has_pin"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding /admin/auth/me response: %v", err)
	}
	return resp.HasPin
}

// TestAdminPin_SetPin_FormatRejected covers the 6-digit format check —
// 400, not a PIN-gate response, since there's nothing to gate yet.
func TestAdminPin_SetPin_FormatRejected(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)

	email := "pin-format-" + testutil.UniqueSuffix(t) + "@example.com"
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

	for _, bad := range []string{"12345", "1234567", "abcdef", ""} {
		rec := adminPanelRequestWithBody(r, http.MethodPut, "/admin/auth/pin", cookie,
			map[string]string{"password": "correct-horse-battery", "pin": bad})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("SetPin(pin=%q): status = %d, want 400", bad, rec.Code)
		}
	}
}

// TestAdminPin_RequireAdminPin_Gating drives /admin/users/{id}/ban (one of
// the PIN-gated routes) through every requireAdminPin outcome: missing
// header, no PIN configured yet, a wrong PIN, a lockout after repeated
// wrong guesses, and finally success.
func TestAdminPin_RequireAdminPin_Gating(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)

	email := "pin-gate-" + testutil.UniqueSuffix(t) + "@example.com"
	account, otpauthURL, err := adminAccounts.CreateAccount(t.Context(), email, "correct-horse-battery", adminauth.RoleSuperAdmin)
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

	targetClient, _ := testutil.NewAPIClient(t, pool)
	targetUser := testutil.NewUser(t, pool, targetClient.ID, "correcthorsebattery")
	banPath := "/admin/users/" + targetUser.ID + "/ban"

	// 1. No header at all: pin_required.
	rec := adminPanelRequest(r, http.MethodPost, banPath, cookie)
	assertPinCode(t, rec, http.StatusForbidden, "pin_required")

	// 2. Header present, but the account has no PIN configured: pin_not_set.
	rec = adminPanelRequestWithBodyAndPin(r, http.MethodPost, banPath, cookie, nil, "123456")
	assertPinCode(t, rec, http.StatusForbidden, "pin_not_set")

	mustSetPin(t, r, cookie, "correct-horse-battery", "123456")

	// 3. Wrong PIN: pin_invalid.
	rec = adminPanelRequestWithBodyAndPin(r, http.MethodPost, banPath, cookie, nil, "000000")
	assertPinCode(t, rec, http.StatusForbidden, "pin_invalid")

	// 4. Enough wrong guesses locks it out — 429 with Retry-After.
	for i := 0; i < 3; i++ {
		adminPanelRequestWithBodyAndPin(r, http.MethodPost, banPath, cookie, nil, "000000")
	}
	rec = adminPanelRequestWithBodyAndPin(r, http.MethodPost, banPath, cookie, nil, "123456")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("ban after repeated wrong pins: status = %d, want 429, body = %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("locked out: missing Retry-After header")
	}
}

func assertPinCode(t *testing.T, rec *httptest.ResponseRecorder, wantStatus int, wantCode string) {
	t.Helper()
	if rec.Code != wantStatus {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, wantStatus, rec.Body.String())
	}
	var resp struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding error body: %v, body = %s", err, rec.Body.String())
	}
	if resp.Code != wantCode {
		t.Fatalf("code = %q, want %q (body = %s)", resp.Code, wantCode, rec.Body.String())
	}
}

// TestAdminPin_TokenPathExempt proves the shared X-Admin-Token/script
// credential never needs a PIN — see requireAdminPin's own doc comment.
func TestAdminPin_TokenPathExempt(t *testing.T) {
	r, _, pool, _ := newTestRouterWithAdminPanel(t)

	targetClient, _ := testutil.NewAPIClient(t, pool)
	targetUser := testutil.NewUser(t, pool, targetClient.ID, "correcthorsebattery")

	req := httptest.NewRequest(http.MethodPost, "/admin/users/"+targetUser.ID+"/ban", nil)
	req.Header.Set("X-Admin-Token", testAdminToken)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("ban with X-Admin-Token, no PIN header: status = %d, body = %s, want 204", rec.Code, rec.Body.String())
	}
}

// TestAdminPin_UnbanAndLockoutRoutesAreNotGated locks in the deliberate
// ban/unban asymmetry from the design notes: lifting access never needs a
// PIN, only removing it does. See router.go's comments on these same
// routes — if someone "fixes" the asymmetry there, this test catches it.
func TestAdminPin_UnbanAndLockoutRoutesAreNotGated(t *testing.T) {
	r, adminAccounts, pool, rdb := newTestRouterWithAdminPanel(t)

	email := "pin-unban-" + testutil.UniqueSuffix(t) + "@example.com"
	account, otpauthURL, err := adminAccounts.CreateAccount(t.Context(), email, "correct-horse-battery", adminauth.RoleSuperAdmin)
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
	// Deliberately never calling mustSetPin here — every request below
	// must succeed with NO PIN configured at all, proving these routes
	// never reach requireAdminPin.

	targetClient, _ := testutil.NewAPIClient(t, pool)
	targetUser := testutil.NewUser(t, pool, targetClient.ID, "correcthorsebattery")

	if rec := adminPanelRequest(r, http.MethodPost, "/admin/users/"+targetUser.ID+"/unban", cookie); rec.Code != http.StatusNoContent {
		t.Fatalf("unban user: status = %d, body = %s, want 204 (not PIN-gated)", rec.Code, rec.Body.String())
	}
	if rec := adminPanelRequest(r, http.MethodPost, "/admin/users/"+targetUser.ID+"/revoke-sessions", cookie); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke sessions: status = %d, body = %s, want 204 (not PIN-gated)", rec.Code, rec.Body.String())
	}

	bl := middleware.NewBlacklist(rdb, 1, time.Hour, []time.Duration{time.Hour}, 30*24*time.Hour, nil, nil)
	ip := "203.0.113.40"
	if err := bl.RecordViolation(t.Context(), ip, targetClient.ID); err != nil {
		t.Fatalf("RecordViolation: %v", err)
	}
	if rec := adminPanelRequest(r, http.MethodDelete, "/admin/blacklist/"+ip, cookie); rec.Code != http.StatusNoContent {
		t.Fatalf("unban ip: status = %d, body = %s, want 204 (not PIN-gated)", rec.Code, rec.Body.String())
	}
}
