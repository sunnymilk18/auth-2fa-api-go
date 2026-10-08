package httpserver_test

// Covers GET /admin/stats: range/tz validation, that it needs no PIN, and
// that operator_actions_per_day/operator_actions_by_type only ever appear
// for a superadmin — see internal/stats for the underlying computation,
// already covered by its own test suite; these tests are about the HTTP
// wiring and the role-conditional response shape.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp"

	"auth-2fa-api/internal/adminauth"
	"auth-2fa-api/internal/testutil"
)

type statsResponseJSON struct {
	Range          string           `json:"range"`
	TZ             string           `json:"tz"`
	UsersTotal     int              `json:"users_total"`
	UsersBanned    int              `json:"users_banned"`
	UsersPerDay    []map[string]any `json:"users_per_day"`
	UsersPerTenant []map[string]any `json:"users_per_tenant"`
}

// loginRegularAdminForStats creates a fresh regular ("admin", not
// "superadmin") account and logs it in — used by every test below that
// just needs a valid non-superadmin session, not the account itself.
func loginRegularAdminForStats(t *testing.T, r http.Handler, adminAccounts *adminauth.Service, pool *pgxpool.Pool) *http.Cookie {
	t.Helper()
	email := "stats-admin-" + testutil.UniqueSuffix(t) + "@example.com"
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

func TestAdminStats_InvalidRange_Returns400(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)
	cookie := loginRegularAdminForStats(t, r, adminAccounts, pool)

	for _, bad := range []string{"", "7", "90d", "1y"} {
		rec := adminPanelRequest(r, http.MethodGet, "/admin/stats?range="+bad, cookie)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("GET /admin/stats?range=%q: status = %d, want 400", bad, rec.Code)
		}
	}
}

func TestAdminStats_InvalidTimezone_Returns400(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)
	cookie := loginRegularAdminForStats(t, r, adminAccounts, pool)

	for _, bad := range []string{"Not/A_Zone", "Local", "local", "+03:00"} {
		rec := adminPanelRequest(r, http.MethodGet, "/admin/stats?range=7d&tz="+bad, cookie)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("GET /admin/stats?range=7d&tz=%q: status = %d, want 400", bad, rec.Code)
		}
	}
}

func TestAdminStats_MissingTimezoneDefaultsToUTC(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)
	cookie := loginRegularAdminForStats(t, r, adminAccounts, pool)

	rec := adminPanelRequest(r, http.MethodGet, "/admin/stats?range=7d", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/stats?range=7d: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp statsResponseJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.TZ != "UTC" {
		t.Fatalf("tz = %q, want %q", resp.TZ, "UTC")
	}
	if resp.Range != "7d" {
		t.Fatalf("range = %q, want %q", resp.Range, "7d")
	}
	if len(resp.UsersPerDay) != 7 {
		t.Fatalf("len(users_per_day) = %d, want 7 (zero-filled)", len(resp.UsersPerDay))
	}
}

// No X-Admin-Pin header anywhere in these requests — GET /admin/stats is
// read-only and must never be gated behind requireAdminPin.
func TestAdminStats_NoPinRequired(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)
	cookie := loginRegularAdminForStats(t, r, adminAccounts, pool)

	rec := adminPanelRequest(r, http.MethodGet, "/admin/stats?range=30d", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/stats without X-Admin-Pin: status = %d, body = %s, want 200", rec.Code, rec.Body.String())
	}
}

// A regular admin gets the same access GET /admin/users already gives
// them, but never the operator-activity fields — those stay superadmin-
// only, same tier as GET /admin/audit itself.
func TestAdminStats_RegularAdminDoesNotGetOperatorFields(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)
	cookie := loginRegularAdminForStats(t, r, adminAccounts, pool)

	rec := adminPanelRequest(r, http.MethodGet, "/admin/stats?range=7d", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/stats as regular admin: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if _, present := raw["operator_actions_per_day"]; present {
		t.Fatal("operator_actions_per_day present for a regular admin, want absent")
	}
	if _, present := raw["operator_actions_by_type"]; present {
		t.Fatal("operator_actions_by_type present for a regular admin, want absent")
	}
	// The rest of the response must still be there — this isn't a
	// superadmin-only endpoint, just two superadmin-only fields.
	if _, present := raw["users_total"]; !present {
		t.Fatal("users_total absent for a regular admin, want present")
	}
}

func TestAdminStats_SuperAdminGetsOperatorFields(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)

	email := "stats-super-" + testutil.UniqueSuffix(t) + "@example.com"
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

	rec := adminPanelRequest(r, http.MethodGet, "/admin/stats?range=7d", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/stats as superadmin: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	perDay, present := raw["operator_actions_per_day"]
	if !present {
		t.Fatal("operator_actions_per_day absent for a superadmin, want present")
	}
	var perDayDecoded []map[string]any
	if err := json.Unmarshal(perDay, &perDayDecoded); err != nil {
		t.Fatalf("decoding operator_actions_per_day: %v", err)
	}
	if len(perDayDecoded) != 7 {
		t.Fatalf("len(operator_actions_per_day) = %d, want 7 (zero-filled)", len(perDayDecoded))
	}
	if _, present := raw["operator_actions_by_type"]; !present {
		t.Fatal("operator_actions_by_type absent for a superadmin, want present")
	}
}
