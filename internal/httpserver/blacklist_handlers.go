package httpserver

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"

	"github.com/go-chi/chi/v5"

	"auth-2fa-api/internal/apiclient"
	"auth-2fa-api/internal/auth"
	"auth-2fa-api/internal/middleware"
)

// blacklistHandlers exposes a tenant's own banned-IP view over HTTP — backs
// /system-admin/blacklist. Kept separate from auth.AdminHandlers because
// middleware.Blacklist is an IP/rate-limiting concept, not an auth-domain
// one; this just adapts it to HTTP, the same way NewRouter's own inline
// /admin/blacklist closure already does for the operator's unscoped route
// (see its doc comment there). apiClients is only used by ListAll, to
// attach api_client_name to each ban — every tenant-scoped handler here
// (List, Unban, ...) already has its api_client_id from the caller's own
// token and has no need to resolve a name for it.
type blacklistHandlers struct {
	bl         *middleware.Blacklist
	apiClients *apiclient.Service
	logger     *slog.Logger
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

type adminBanInfoResponse struct {
	IP          string  `json:"ip"`
	Reference   *string `json:"reference,omitempty"`
	BannedAt    int64   `json:"banned_at"`
	BannedUntil int64   `json:"banned_until"`
	Level       int64   `json:"level"`
	Strikes     int64   `json:"strikes"`
	// APIClientID is "" when the ban has no resolvable owner (see
	// middleware.Blacklist.ListAll's doc comment) — always present,
	// never omitted, so the panel can tell "no owner" apart from a
	// field it forgot to render.
	APIClientID string `json:"api_client_id"`
	// APIClientName rides alongside APIClientID the same way userListItem.
	// APIClientName does for GET /admin/users — "" when APIClientID is ""
	// (no owner at all) or when the owner id no longer resolves to a
	// client row (e.g. deleted directly in Postgres, bypassing this API's
	// own deactivate-don't-delete convention). Always present, never
	// omitted, same reasoning as APIClientID.
	APIClientName string `json:"api_client_name"`
}

type listAllBlacklistResponse struct {
	Bans []adminBanInfoResponse `json:"bans"`
}

// ListAll returns every currently-banned IP across every tenant — the
// operator's unscoped counterpart to List (the tenant-scoped
// /system-admin/blacklist above). See middleware.Blacklist.ListAll's doc
// comment for what "every" does and doesn't cover.
func (h *blacklistHandlers) ListAll(w http.ResponseWriter, r *http.Request) {
	bans, err := h.bl.ListAll(r.Context(), maxBlacklistListing)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "no se pudieron listar los baneos")
		return
	}

	// One query for every distinct owner across the whole listing, not one
	// per ban — see apiclient.Repository.FindByIDs's doc comment.
	ownerIDs := make([]string, 0, len(bans))
	seen := make(map[string]bool, len(bans))
	for _, b := range bans {
		if b.OwnerAPIClientID == "" || seen[b.OwnerAPIClientID] {
			continue
		}
		seen[b.OwnerAPIClientID] = true
		ownerIDs = append(ownerIDs, b.OwnerAPIClientID)
	}
	names, err := h.apiClients.FindByIDs(r.Context(), ownerIDs)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "no se pudieron listar los baneos")
		return
	}

	out := make([]adminBanInfoResponse, 0, len(bans))
	for _, b := range bans {
		item := adminBanInfoResponse{
			IP:            b.IP,
			BannedAt:      b.BannedAt.Unix(),
			BannedUntil:   b.BannedUntil.Unix(),
			Level:         b.Level,
			Strikes:       b.Strikes,
			APIClientID:   b.OwnerAPIClientID,
			APIClientName: names[b.OwnerAPIClientID],
		}
		if b.HasRef {
			ref := b.Reference
			item.Reference = &ref
		}
		out = append(out, item)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(listAllBlacklistResponse{Bans: out})
}

type unbanRequest struct {
	Reason string `json:"reason"`
}

// maxUnbanReasonLength caps the optional reason field — it's never read
// back, only written to the log line below, so nothing past this length
// adds any value; truncated rather than rejected since it's informational,
// not something worth a 400 over.
const maxUnbanReasonLength = 500

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
	if runes := []rune(req.Reason); len(runes) > maxUnbanReasonLength {
		req.Reason = string(runes[:maxUnbanReasonLength])
	}

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

// allowlistOwner is the value ListAllowlist/AddAllowlist/RemoveAllowlist
// pass as the "owner" to middleware.Blacklist's allowlist methods. Always
// "" (the operator) — these three handlers only ever sit behind
// /admin/blacklist/allowlist (middleware.RequireAdminToken), deliberately
// never under /system-admin/* — see router.go's own comment on why: the
// exemption an allowlist entry grants is global (protects an IP against
// every system's strikes, not just whoever added it), so letting any one
// tenant's own X-System-Admin-Token control it would let that tenant
// weaken protection for every other tenant on the platform, unlike every
// other /system-admin/* action (which can only ever affect its own
// tenant's own data). middleware.Blacklist's allowlist methods still take
// an explicit owner parameter — shared code with the tenant-scoped ban
// methods above — so this is a literal "", not read from request context,
// since RequireAdminToken never sets a tenant there to begin with.
const allowlistOwner = ""

type listAllowlistResponse struct {
	IPs []string `json:"ips"`
}

// ListAllowlist returns every IP the operator has allowlisted — see
// allowlistOwner's doc comment and middleware.Blacklist.AllowlistList's.
func (h *blacklistHandlers) ListAllowlist(w http.ResponseWriter, r *http.Request) {
	ips, err := h.bl.AllowlistList(r.Context(), allowlistOwner)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "no se pudo listar la lista blanca")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(listAllowlistResponse{IPs: ips})
}

type addAllowlistRequest struct {
	IP string `json:"ip"`
}

// AddAllowlist exempts an IP from ever being struck or banned — see
// allowlistOwner's doc comment and middleware.Blacklist.AllowlistAdd's for
// what that means (global once added) and why it also lifts any ban that
// IP is currently serving.
func (h *blacklistHandlers) AddAllowlist(w http.ResponseWriter, r *http.Request) {
	var req addAllowlistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "cuerpo de la solicitud inválido")
		return
	}
	if net.ParseIP(req.IP) == nil {
		writeJSONError(w, http.StatusBadRequest, "la IP no tiene un formato válido")
		return
	}

	if err := h.bl.AllowlistAdd(r.Context(), allowlistOwner, req.IP); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "no se pudo agregar a la lista blanca")
		return
	}

	h.logger.Info("ip added to blacklist allowlist", "ip", req.IP)
	w.WriteHeader(http.StatusNoContent)
}

// RemoveAllowlist takes an IP off the allowlist — see allowlistOwner's doc
// comment and middleware.Blacklist.AllowlistRemove's.
func (h *blacklistHandlers) RemoveAllowlist(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")

	if net.ParseIP(ip) == nil {
		writeJSONError(w, http.StatusBadRequest, "la IP no tiene un formato válido")
		return
	}

	found, err := h.bl.AllowlistRemove(r.Context(), allowlistOwner, ip)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "no se pudo quitar de la lista blanca")
		return
	}
	if !found {
		writeJSONError(w, http.StatusNotFound, "esa IP no está en la lista blanca")
		return
	}

	h.logger.Info("ip removed from blacklist allowlist", "ip", ip)
	w.WriteHeader(http.StatusNoContent)
}
