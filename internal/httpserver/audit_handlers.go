package httpserver

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"auth-2fa-api/internal/audit"
)

// auditHandlers backs GET /admin/audit — read-only visibility into what
// every operator action did, across every tenant. Separate file/type from
// blacklistHandlers/adminAuthHandlers for the same reason those are
// already split: a distinct concern (here, read-only history) gets its
// own small handler rather than growing an unrelated one.
type auditHandlers struct {
	svc *audit.Service
}

type auditEntryResponse struct {
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

type listAuditResponse struct {
	Entries []auditEntryResponse `json:"entries"`
	Page    int                  `json:"page"`
	Total   int                  `json:"total"`
}

// List returns one page of the activity log, most recent first — see
// audit.Service.List for the page/page_size clamping and audit.Filter for
// what actor/action/from/to do. created_at is RFC 3339 (not a Unix
// timestamp, unlike some older /admin/* responses in this codebase — see
// this endpoint's own contract note) so the panel parses it with a single
// convention platform-wide going forward. from/to, if present, must also
// be RFC 3339; a value that doesn't parse is ignored rather than
// rejected, same "best-effort optional filter" treatment page/page_size
// already get elsewhere in this codebase.
func (h *auditHandlers) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	pageSize, _ := strconv.Atoi(q.Get("page_size"))

	f := audit.Filter{
		Actor:  q.Get("actor"),
		Action: q.Get("action"),
	}
	if v := q.Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.From = &t
		}
	}
	if v := q.Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.To = &t
		}
	}

	entries, total, effectivePage, _, err := h.svc.List(r.Context(), f, page, pageSize)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "no se pudo listar el registro de actividad")
		return
	}

	out := make([]auditEntryResponse, 0, len(entries))
	for _, e := range entries {
		out = append(out, auditEntryResponse{
			ID:          e.ID,
			CreatedAt:   e.CreatedAt.UTC().Format(time.RFC3339),
			ActorEmail:  e.ActorEmail,
			ActorRole:   e.ActorRole,
			Action:      e.Action,
			TargetType:  e.TargetType,
			TargetID:    e.TargetID,
			TargetLabel: e.TargetLabel,
			ActorIP:     e.ActorIP,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(listAuditResponse{Entries: out, Page: effectivePage, Total: total})
}
