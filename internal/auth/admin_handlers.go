package auth

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"auth-2fa-api/internal/user"
)

// AdminHandlers exposes account-level moderation over HTTP. The exact same
// handlers back two route trees: /admin/users/* (gated by
// middleware.RequireAdminToken, unscoped — the operator's own token) and
// /system-admin/users/* (gated by middleware.RequireSystemAdminToken,
// scoped to one tenant). Which one a request came through is read from the
// context each middleware sets identically (see auth.APIClientIDFromContext)
// — "" (not present) means unscoped, a real id means scoped to it — so
// there's only ever one code path per action, not two.
type AdminHandlers struct {
	svc *Service
}

func NewAdminHandlers(svc *Service) *AdminHandlers {
	return &AdminHandlers{svc: svc}
}

// Ban deactivates the account and revokes all of its sessions — see
// Service.AdminBanUser's doc comment.
func (h *AdminHandlers) Ban(w http.ResponseWriter, r *http.Request) {
	apiClientID, _ := APIClientIDFromContext(r.Context())
	id := chi.URLParam(r, "id")
	if err := h.svc.AdminBanUser(r.Context(), apiClientID, id); err != nil {
		writeAdminUserActionError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Unban reverses a previous Ban.
func (h *AdminHandlers) Unban(w http.ResponseWriter, r *http.Request) {
	apiClientID, _ := APIClientIDFromContext(r.Context())
	id := chi.URLParam(r, "id")
	if err := h.svc.AdminUnbanUser(r.Context(), apiClientID, id); err != nil {
		writeAdminUserActionError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// DisableTOTP turns off the account's authenticator-app factor — see
// Service.AdminDisableTOTP's doc comment.
func (h *AdminHandlers) DisableTOTP(w http.ResponseWriter, r *http.Request) {
	apiClientID, _ := APIClientIDFromContext(r.Context())
	id := chi.URLParam(r, "id")
	if err := h.svc.AdminDisableTOTP(r.Context(), apiClientID, id); err != nil {
		writeAdminUserActionError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// RevokeSessions revokes every refresh token and trusted device the
// account has, without banning it — see Service.AdminRevokeAllSessions.
func (h *AdminHandlers) RevokeSessions(w http.ResponseWriter, r *http.Request) {
	apiClientID, _ := APIClientIDFromContext(r.Context())
	id := chi.URLParam(r, "id")
	if err := h.svc.AdminRevokeAllSessions(r.Context(), apiClientID, id); err != nil {
		writeAdminUserActionError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeAdminUserActionError(w http.ResponseWriter, err error) {
	if errors.Is(err, user.ErrNotFound) {
		writeError(w, http.StatusNotFound, "usuario no encontrado")
		return
	}
	writeError(w, http.StatusInternalServerError, "no se pudo completar la operación")
}
