package auth

import (
	"errors"
	"net/http"
	"strconv"
	"time"

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

// userListItem is deliberately a narrow projection of user.User — no
// PasswordHash, no TOTP secret (it isn't even on user.User — see its doc
// comment), same "never leaves the server" rule the rest of this package
// already follows for sensitive fields.
type userListItem struct {
	ID                    string    `json:"id"`
	Email                 string    `json:"email"`
	Username              string    `json:"username"`
	RUT                   string    `json:"rut"`
	IsActive              bool      `json:"is_active"`
	EmailVerified         bool      `json:"email_verified"`
	TwoFactorMethodChosen bool      `json:"two_factor_method_chosen"`
	CreatedAt             time.Time `json:"created_at"`
}

type listUsersResponse struct {
	Users    []userListItem `json:"users"`
	Page     int            `json:"page"`
	PageSize int            `json:"page_size"`
	Total    int            `json:"total"`
}

// ListUsers returns one page of the caller's own tenant's registered
// users — see Service.AdminListUsers's doc comment for why this is the
// only Admin* handler with no {id} in its path. page/page_size/q are read
// from the query string; missing or invalid page/page_size fall back to
// Service.AdminListUsers' own defaults/clamping rather than rejecting the
// request outright. q is optional — omitted or empty behaves exactly like
// the plain paginated listing did before q existed.
func (h *AdminHandlers) ListUsers(w http.ResponseWriter, r *http.Request) {
	apiClientID, _ := APIClientIDFromContext(r.Context())
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	q := r.URL.Query().Get("q")

	users, total, effectivePage, effectivePageSize, err := h.svc.AdminListUsers(r.Context(), apiClientID, page, pageSize, q)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "no se pudo listar los usuarios")
		return
	}

	out := make([]userListItem, 0, len(users))
	for _, u := range users {
		out = append(out, userListItem{
			ID:                    u.ID,
			Email:                 u.Email,
			Username:              u.Username,
			RUT:                   u.RUT,
			IsActive:              u.IsActive,
			EmailVerified:         u.EmailVerified,
			TwoFactorMethodChosen: u.TwoFactorMethodChosen,
			CreatedAt:             u.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, listUsersResponse{
		Users:    out,
		Page:     effectivePage,
		PageSize: effectivePageSize,
		Total:    total,
	})
}

func writeAdminUserActionError(w http.ResponseWriter, err error) {
	if errors.Is(err, user.ErrNotFound) {
		writeError(w, http.StatusNotFound, "usuario no encontrado")
		return
	}
	writeError(w, http.StatusInternalServerError, "no se pudo completar la operación")
}
