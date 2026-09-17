package user

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// AdminHandlers exposes account-level moderation over HTTP, under
// /admin/users — gated by middleware.RequireAdminToken, same as
// apiclient.Handlers under /admin/clients. Deliberately separate from
// AuthHandlers/auth.Handlers: those act on behalf of the account owner
// (with their own credentials or token), these act on any account on the
// operator's say-so alone.
type AdminHandlers struct {
	svc *Service
}

func NewAdminHandlers(svc *Service) *AdminHandlers {
	return &AdminHandlers{svc: svc}
}

type adminErrorResponse struct {
	Error string `json:"error"`
}

func writeAdminError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(adminErrorResponse{Error: msg})
}

// Ban deactivates the account — see Service.Ban's doc comment for why this
// is manual-only, never automatic.
func (h *AdminHandlers) Ban(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.svc.Ban(r.Context(), id); err != nil {
		writeAdminUserActionError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Unban reverses a previous Ban.
func (h *AdminHandlers) Unban(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.svc.Unban(r.Context(), id); err != nil {
		writeAdminUserActionError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeAdminUserActionError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrNotFound) {
		writeAdminError(w, http.StatusNotFound, "usuario no encontrado")
		return
	}
	writeAdminError(w, http.StatusInternalServerError, "no se pudo completar la operación")
}
