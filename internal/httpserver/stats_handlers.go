package httpserver

import (
	"encoding/json"
	"net/http"
	"time"

	"auth-2fa-api/internal/adminctx"
	"auth-2fa-api/internal/audit"
	"auth-2fa-api/internal/middleware"
	"auth-2fa-api/internal/stats"
)

// statsHandlers backs GET /admin/stats — read-only, no PIN (see router.go's
// wiring: same access level as GET /admin/users, not superadmin-only on
// its own), but two fields of its response are superadmin-only — see
// Overview's own doc comment.
type statsHandlers struct {
	svc *stats.Service
}

type dayCountResponse struct {
	Day   string `json:"day"`
	Count int    `json:"count"`
}

type dayActionCountResponse struct {
	Day    string `json:"day"`
	Count  int    `json:"count"`
	Failed int    `json:"failed"`
}

type tenantCountResponse struct {
	APIClientID   string `json:"api_client_id"`
	APIClientName string `json:"api_client_name"`
	Total         int    `json:"total"`
	NewInRange    int    `json:"new_in_range"`
}

type actionTypeCountResponse struct {
	Action string `json:"action"`
	Count  int    `json:"count"`
}

type loginDayCountResponse struct {
	Day     string `json:"day"`
	Success int    `json:"success"`
	Failed  int    `json:"failed"`
}

type tenantLoginCountResponse struct {
	APIClientID string `json:"api_client_id"`
	Name        string `json:"name"`
	Success     int    `json:"success"`
	Failed      int    `json:"failed"`
}

type ipFailureCountResponse struct {
	IP     string `json:"ip"`
	Failed int    `json:"failed"`
	LastAt string `json:"last_at"`
}

type banDayCountResponse struct {
	Day  string `json:"day"`
	Bans int    `json:"bans"`
}

// statsResponse is what GET /admin/stats returns. OperatorActionsPerDay/
// OperatorActionsByType are pointers, not plain slices: a regular admin
// gets these fields OMITTED from the JSON entirely (pointer left nil), a
// superadmin always gets them PRESENT, even as an empty array when there
// were no operator actions in range — a plain slice with `omitempty`
// can't tell those two cases apart (encoding/json's omitempty elides a
// nil OR empty slice alike), which is exactly the distinction the design
// calls for.
type statsResponse struct {
	Range          string                `json:"range"`
	TZ             string                `json:"tz"`
	UsersTotal     int                   `json:"users_total"`
	UsersBanned    int                   `json:"users_banned"`
	UsersPerDay    []dayCountResponse    `json:"users_per_day"`
	UsersPerTenant []tenantCountResponse `json:"users_per_tenant"`

	// LoginsByDay/FailuresByTenant/TopFailingIPs/BansByDay are "tanda 2" —
	// end-user authentication activity — visible to admin and superadmin
	// alike, same as everything above (never behind includeOperatorStats,
	// see stats.Overview's own doc comment).
	LoginsByDay      []loginDayCountResponse    `json:"logins_by_day"`
	FailuresByTenant []tenantLoginCountResponse `json:"failures_by_tenant"`
	TopFailingIPs    []ipFailureCountResponse   `json:"top_failing_ips"`
	BansByDay        []banDayCountResponse      `json:"bans_by_day"`

	OperatorActionsPerDay *[]dayActionCountResponse  `json:"operator_actions_per_day,omitempty"`
	OperatorActionsByType *[]actionTypeCountResponse `json:"operator_actions_by_type,omitempty"`
}

// statsFailedActions are the audit.Action* values OperatorActionsPerDay's
// "failed" field counts — a failed login attempt and a wrong PIN on a
// destructive-action confirmation, the only two "something went wrong"
// entries the audit log records today (see audit.go's Action* list: every
// other entry is only ever written on success — see AdminHandlers.
// logUserAction's doc comment). Kept here, not in internal/stats, so that
// package never needs to import internal/audit just for two strings.
var statsFailedActions = []string{audit.ActionAdminLoginFailed, audit.ActionAccountPinFailed}

// Overview handles GET /admin/stats?range=7d|30d&tz=<IANA zone>. range is
// required and must be exactly "7d" or "30d" (400 otherwise, no default —
// unlike tz, there's no sensible implicit choice between the two). tz is
// optional (UTC if omitted) and, when present, must be a real IANA zone
// name — "Local" is refused even though Go itself treats it as a valid
// special case, see stats.LoadLocation's doc comment for why.
// OperatorActionsPerDay/OperatorActionsByType only appear in the response
// for a superadmin — a regular admin can see day-to-day user numbers
// (same access GET /admin/users already gives them) but not
// platform-wide operator activity, which is what GET /admin/audit itself
// is already restricted to superadmins for.
func (h *statsHandlers) Overview(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	rangeParam := q.Get("range")
	days, ok := stats.ParseRangeDays(rangeParam)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, `range debe ser "7d" o "30d"`)
		return
	}

	loc, err := stats.LoadLocation(q.Get("tz"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "tz debe ser una zona horaria IANA válida")
		return
	}

	rng := stats.ResolveRange(days, loc, time.Now())
	role, _ := adminctx.Role(r.Context())
	includeOperatorStats := role == middleware.AdminRoleSuperAdmin

	overview, err := h.svc.Overview(r.Context(), rangeParam, rng, includeOperatorStats, statsFailedActions)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "no se pudieron calcular las estadísticas")
		return
	}

	resp := statsResponse{
		Range:            overview.RangeParam,
		TZ:               overview.TZName,
		UsersTotal:       overview.UsersTotal,
		UsersBanned:      overview.UsersBanned,
		UsersPerDay:      toDayCountResponses(overview.UsersPerDay),
		UsersPerTenant:   toTenantCountResponses(overview.UsersPerTenant),
		LoginsByDay:      toLoginDayCountResponses(overview.LoginsByDay),
		FailuresByTenant: toTenantLoginCountResponses(overview.FailuresByTenant),
		TopFailingIPs:    toIPFailureCountResponses(overview.TopFailingIPs),
		BansByDay:        toBanDayCountResponses(overview.BansByDay),
	}
	if includeOperatorStats {
		perDay := toDayActionCountResponses(overview.OperatorActionsPerDay)
		byType := toActionTypeCountResponses(overview.OperatorActionsByType)
		resp.OperatorActionsPerDay = &perDay
		resp.OperatorActionsByType = &byType
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func toDayCountResponses(in []stats.DayCount) []dayCountResponse {
	out := make([]dayCountResponse, 0, len(in))
	for _, d := range in {
		out = append(out, dayCountResponse{Day: d.Day, Count: d.Count})
	}
	return out
}

func toDayActionCountResponses(in []stats.DayActionCount) []dayActionCountResponse {
	out := make([]dayActionCountResponse, 0, len(in))
	for _, d := range in {
		out = append(out, dayActionCountResponse{Day: d.Day, Count: d.Count, Failed: d.Failed})
	}
	return out
}

func toTenantCountResponses(in []stats.TenantCount) []tenantCountResponse {
	out := make([]tenantCountResponse, 0, len(in))
	for _, t := range in {
		out = append(out, tenantCountResponse{
			APIClientID: t.APIClientID, APIClientName: t.APIClientName,
			Total: t.Total, NewInRange: t.NewInRange,
		})
	}
	return out
}

func toLoginDayCountResponses(in []stats.LoginDayCount) []loginDayCountResponse {
	out := make([]loginDayCountResponse, 0, len(in))
	for _, d := range in {
		out = append(out, loginDayCountResponse{Day: d.Day, Success: d.Success, Failed: d.Failed})
	}
	return out
}

func toTenantLoginCountResponses(in []stats.TenantLoginCount) []tenantLoginCountResponse {
	out := make([]tenantLoginCountResponse, 0, len(in))
	for _, t := range in {
		out = append(out, tenantLoginCountResponse{
			APIClientID: t.APIClientID, Name: t.APIClientName, Success: t.Success, Failed: t.Failed,
		})
	}
	return out
}

func toIPFailureCountResponses(in []stats.IPFailureCount) []ipFailureCountResponse {
	out := make([]ipFailureCountResponse, 0, len(in))
	for _, f := range in {
		out = append(out, ipFailureCountResponse{IP: f.IP, Failed: f.Failed, LastAt: f.LastAt.Format(time.RFC3339)})
	}
	return out
}

func toBanDayCountResponses(in []stats.DayCount) []banDayCountResponse {
	out := make([]banDayCountResponse, 0, len(in))
	for _, d := range in {
		out = append(out, banDayCountResponse{Day: d.Day, Bans: d.Count})
	}
	return out
}

func toActionTypeCountResponses(in []stats.ActionTypeCount) []actionTypeCountResponse {
	out := make([]actionTypeCountResponse, 0, len(in))
	for _, a := range in {
		out = append(out, actionTypeCountResponse{Action: a.Action, Count: a.Count})
	}
	return out
}
