package httpserver

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"auth-2fa-api/internal/authevents"
)

// securityEventsHandlers backs GET /admin/security/events — read-only
// detail behind the "tanda 2" blocks in GET /admin/stats, one row per
// auth_events entry. Separate file/type from auditHandlers for the same
// reason stats/audit already are: a distinct concern (end-user auth
// activity, not operator actions) gets its own small handler.
type securityEventsHandlers struct {
	svc *authevents.Service
}

type securityEventTenantResponse struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type securityEventUserResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// securityEventResponse never carries email_hash — that field exists in
// auth_events precisely so this response doesn't have to, see
// internal/authevents' own package doc comment.
type securityEventResponse struct {
	ID         int64                       `json:"id"`
	CreatedAt  string                      `json:"created_at"`
	Kind       string                      `json:"kind"`
	Method     *string                     `json:"method"`
	Result     string                      `json:"result"`
	Tenant     securityEventTenantResponse `json:"tenant"`
	User       *securityEventUserResponse  `json:"user"`
	IP         string                      `json:"ip"`
	UserAgent  string                      `json:"user_agent"`
	BanOrigin  *string                     `json:"ban_origin"`
	ActorEmail *string                     `json:"actor_email"`
	IsDecoy    bool                        `json:"is_decoy"`
}

type listSecurityEventsResponse struct {
	Events []securityEventResponse `json:"events"`
	Page   int                     `json:"page"`
	Total  int                     `json:"total"`
}

// nullableString turns "" (this package's NULL-column convention — see
// authevents.ListedEvent's own doc comment) back into a real JSON null,
// for the three response fields the contract says must be null rather
// than an empty string: method, ban_origin, actor_email.
func nullableString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// List returns one page of auth_events, most recent first — see
// authevents.Service.ListEvents for the page/page_size clamping,
// authevents.EventFilter for what tenant/kind/method/result/ip do, and
// authevents.ResolveEventRange for from/to's defaulting and 90-day cap.
//
// Unlike GET /admin/audit, a malformed tenant/ip/from/to is rejected with
// 400 rather than silently ignored — this endpoint exists to investigate
// incidents, and a typo'd filter that quietly matches "everything" instead
// of "nothing" would be actively misleading to whoever is looking at it. A
// well-formed value that simply matches nothing (an unknown kind/method/
// result, or a valid IP with no events) returns an empty list, not an
// error.
func (h *securityEventsHandlers) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	pageSize, _ := strconv.Atoi(q.Get("page_size"))

	f := authevents.EventFilter{
		Kind:   q.Get("kind"),
		Method: q.Get("method"),
		Result: q.Get("result"),
	}

	if v := q.Get("tenant"); v != "" {
		if _, err := uuid.Parse(v); err != nil {
			writeJSONError(w, http.StatusBadRequest, "tenant debe ser un UUID válido")
			return
		}
		f.APIClientID = v
	}

	if v := q.Get("ip"); v != "" {
		if net.ParseIP(v) == nil {
			writeJSONError(w, http.StatusBadRequest, "ip no es una dirección IP válida")
			return
		}
		f.IP = v
	}

	var fromPtr, toPtr *time.Time
	if v := q.Get("from"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "from debe ser una fecha en formato RFC 3339")
			return
		}
		fromPtr = &t
	}
	if v := q.Get("to"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "to debe ser una fecha en formato RFC 3339")
			return
		}
		toPtr = &t
	}
	from, to, err := authevents.ResolveEventRange(fromPtr, toPtr, time.Now())
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	f.From, f.To = from, to

	events, total, effectivePage, _, err := h.svc.ListEvents(r.Context(), f, page, pageSize)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "no se pudieron listar los eventos de autenticación")
		return
	}

	out := make([]securityEventResponse, 0, len(events))
	for _, e := range events {
		resp := securityEventResponse{
			ID:         e.ID,
			CreatedAt:  e.CreatedAt.UTC().Format(time.RFC3339),
			Kind:       e.Kind,
			Method:     nullableString(e.Method),
			Result:     e.Result,
			Tenant:     securityEventTenantResponse{ID: e.APIClientID, Name: e.APIClientName},
			IP:         e.IP,
			UserAgent:  e.UserAgent,
			BanOrigin:  nullableString(e.BanOrigin),
			ActorEmail: nullableString(e.ActorEmail),
			IsDecoy:    e.IsDecoy,
		}
		if e.UserID != "" {
			resp.User = &securityEventUserResponse{ID: e.UserID, Email: e.UserEmail}
		}
		out = append(out, resp)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(listSecurityEventsResponse{Events: out, Page: effectivePage, Total: total})
}
