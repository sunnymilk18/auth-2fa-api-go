package httpserver

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"

	"github.com/go-chi/chi/v5"

	"auth-2fa-api/internal/auth"
	"auth-2fa-api/internal/middleware"
)

// blacklistHandlers exposes a tenant's own banned-IP view over HTTP — backs
// /system-admin/blacklist. Kept separate from auth.AdminHandlers because
// middleware.Blacklist is an IP/rate-limiting concept, not an auth-domain
// one; this just adapts it to HTTP, the same way NewRouter's own inline
// /admin/blacklist closure already does for the operator's unscoped route
// (see its doc comment there).
type blacklistHandlers struct {
	bl     *middleware.Blacklist
	logger *slog.Logger
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

type banInfoResponse struct {
	IP          string  `json:"ip"`
	Reference   *string `json:"reference,omitempty"`
	BannedAt    int64   `json:"banned_at"`
	BannedUntil int64   `json:"banned_until"`
	Level       int64   `json:"level"`
	Strikes     int64   `json:"strikes"`
}

type listBlacklistResponse struct {
	Bans []banInfoResponse `json:"bans"`
}

// maxBlacklistListing caps GET /system-admin/blacklist — no pagination yet
// (see the feature's own design notes), just a reasonable ceiling so one
// tenant's listing can't become unbounded.
const maxBlacklistListing = 200

// List returns the caller's own currently-banned IPs, soonest-to-expire
// bans included alongside the rest — see middleware.Blacklist.ListOwned's
// doc comment for the ordering and pruning behavior. Bans created before
// ownership tracking existed, or whose triggering request couldn't resolve
// an api_client_id, never appear here (operator-only, via /admin/blacklist
// — see RecordViolation's doc comment).
func (h *blacklistHandlers) List(w http.ResponseWriter, r *http.Request) {
	apiClientID, _ := auth.APIClientIDFromContext(r.Context())

	bans, err := h.bl.ListOwned(r.Context(), apiClientID, maxBlacklistListing)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "no se pudieron listar los baneos")
		return
	}

	out := make([]banInfoResponse, 0, len(bans))
	for _, b := range bans {
		item := banInfoResponse{
			IP:          b.IP,
			BannedAt:    b.BannedAt.Unix(),
			BannedUntil: b.BannedUntil.Unix(),
			Level:       b.Level,
			Strikes:     b.Strikes,
		}
		if b.HasRef {
			ref := b.Reference
			item.Reference = &ref
		}
		out = append(out, item)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(listBlacklistResponse{Bans: out})
}

type unbanRequest struct {
	Reason string `json:"reason"`
}

// Unban lifts ip's ban — but only when it's owned by the caller's own
// tenant (see middleware.Blacklist.UnbanOwned's doc comment); 404 rather
// than 403 otherwise, same "never confirm or deny what exists for someone
// else" rule every other /system-admin/* route already follows. reason in
// the body is optional, logged alongside the action when present.
func (h *blacklistHandlers) Unban(w http.ResponseWriter, r *http.Request) {
	apiClientID, _ := auth.APIClientIDFromContext(r.Context())
	ip := chi.URLParam(r, "ip")

	if net.ParseIP(ip) == nil {
		writeJSONError(w, http.StatusBadRequest, "la IP no tiene un formato válido")
		return
	}

	var req unbanRequest
	_ = json.NewDecoder(r.Body).Decode(&req) // optional body — a missing/empty one is fine

	found, err := h.bl.UnbanOwned(r.Context(), apiClientID, ip)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "no se pudo levantar el baneo")
		return
	}
	if !found {
		writeJSONError(w, http.StatusNotFound, "no hay un baneo de esa IP para este sistema")
		return
	}

	h.logger.Info("ip ban lifted", "api_client_id", apiClientID, "ip", ip, "reason", req.Reason)
	w.WriteHeader(http.StatusNoContent)
}
