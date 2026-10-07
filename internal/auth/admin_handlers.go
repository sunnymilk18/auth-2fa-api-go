package auth

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"auth-2fa-api/internal/adminctx"
	"auth-2fa-api/internal/audit"
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
	svc   *Service
	audit *audit.Service
}

func NewAdminHandlers(svc *Service, auditSvc *audit.Service) *AdminHandlers {
	return &AdminHandlers{svc: svc, audit: auditSvc}
}

// logUserAction writes an audit entry for a mutating action on a user
// account — but ONLY when the request came through /admin/* (an operator
// identity set by middleware.RequireAdminAccess in adminctx): the exact
// same handlers also back /system-admin/* (a tenant's own scoped
// credential, see this file's own doc comment), which never sets that
// context value and isn't "an operator's own action" in the sense this
// audit log is for — see the audit log's own design notes. Best-effort
// everywhere: a failed email lookup becomes "" rather than blocking the
// write, and audit.Service.Log itself never blocks or fails the caller.
func (h *AdminHandlers) logUserAction(r *http.Request, apiClientID, userID, action string) {
	actor, ok := adminctx.Actor(r.Context())
	if !ok {
		return
	}
	role, _ := adminctx.Role(r.Context())
	email, _ := h.svc.UserEmail(r.Context(), apiClientID, userID)
	h.audit.Log(r.Context(), audit.Entry{
		ActorEmail: actor, ActorRole: role, Action: action,
		TargetType: audit.TargetTypeUser, TargetID: userID, TargetLabel: email,
		ActorIP: audit.RemoteIP(r),
	})
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
	h.logUserAction(r, apiClientID, id, audit.ActionUserBan)
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
	h.logUserAction(r, apiClientID, id, audit.ActionUserUnban)
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
	h.logUserAction(r, apiClientID, id, audit.ActionUserTOTPDisable)
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
	h.logUserAction(r, apiClientID, id, audit.ActionUserSessionsRevoke)
	w.WriteHeader(http.StatusNoContent)
}

type setLoginPinRequiredRequest struct {
	Required bool `json:"required"`
}

// SetLoginPinRequired flips the account's PinRequiredAtLogin switch — see
// Service.AdminSetLoginPinRequired's doc comment.
func (h *AdminHandlers) SetLoginPinRequired(w http.ResponseWriter, r *http.Request) {
	apiClientID, _ := APIClientIDFromContext(r.Context())
	id := chi.URLParam(r, "id")

	var req setLoginPinRequiredRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "cuerpo de la solicitud inválido")
		return
	}

	if err := h.svc.AdminSetLoginPinRequired(r.Context(), apiClientID, id, req.Required); err != nil {
		writeAdminUserActionError(w, err)
		return
	}
	h.logUserAction(r, apiClientID, id, audit.ActionUserLoginPinRequiredSet)
	w.WriteHeader(http.StatusNoContent)
}

type lockoutStatusResponse struct {
	Locked            bool  `json:"locked"`
	RetryAfterSeconds int64 `json:"retry_after_seconds"`
}

type lockoutsResponse struct {
	Login lockoutStatusResponse `json:"login"`
	Pin   lockoutStatusResponse `json:"pin"`
}

// GetLockouts reports whether the account's login throttle and/or PIN
// lockout are currently active — see Service.AdminGetLockouts' doc comment.
func (h *AdminHandlers) GetLockouts(w http.ResponseWriter, r *http.Request) {
	apiClientID, _ := APIClientIDFromContext(r.Context())
	id := chi.URLParam(r, "id")

	login, pin, err := h.svc.AdminGetLockouts(r.Context(), apiClientID, id)
	if err != nil {
		writeAdminUserActionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, lockoutsResponse{
		Login: lockoutStatusResponse{Locked: login.Locked, RetryAfterSeconds: int64(login.RetryAfter.Seconds())},
		Pin:   lockoutStatusResponse{Locked: pin.Locked, RetryAfterSeconds: int64(pin.RetryAfter.Seconds())},
	})
}

type clearLockoutsRequest struct {
	Which string `json:"which"`
}

// ClearLockouts resets the account's login and/or PIN failed-attempt
// counters — see Service.AdminClearLockouts' doc comment for exactly what
// this does and doesn't touch.
func (h *AdminHandlers) ClearLockouts(w http.ResponseWriter, r *http.Request) {
	apiClientID, _ := APIClientIDFromContext(r.Context())
	id := chi.URLParam(r, "id")

	var req clearLockoutsRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "cuerpo de la solicitud inválido")
		return
	}
	var clearLogin, clearPin bool
	switch req.Which {
	case "login":
		clearLogin = true
	case "pin":
		clearPin = true
	case "all":
		clearLogin, clearPin = true, true
	default:
		writeError(w, http.StatusBadRequest, `which debe ser "login", "pin" o "all"`)
		return
	}

	if err := h.svc.AdminClearLockouts(r.Context(), apiClientID, id, clearLogin, clearPin); err != nil {
		writeAdminUserActionError(w, err)
		return
	}
	h.logUserAction(r, apiClientID, id, audit.ActionUserLockoutsCleared)
	w.WriteHeader(http.StatusNoContent)
}

// ResetPin clears the account's PIN and revokes its trusted devices and
// sessions — see Service.AdminResetPin's doc comment.
func (h *AdminHandlers) ResetPin(w http.ResponseWriter, r *http.Request) {
	apiClientID, _ := APIClientIDFromContext(r.Context())
	id := chi.URLParam(r, "id")
	if err := h.svc.AdminResetPin(r.Context(), apiClientID, id); err != nil {
		writeAdminUserActionError(w, err)
		return
	}
	h.logUserAction(r, apiClientID, id, audit.ActionUserPINReset)
	w.WriteHeader(http.StatusNoContent)
}

type changeEmailRequest struct {
	NewEmail string `json:"new_email"`
}

// ChangeEmail starts an email correction — see Service.AdminChangeEmail's
// doc comment for why this only sends a code and never changes anything
// itself.
func (h *AdminHandlers) ChangeEmail(w http.ResponseWriter, r *http.Request) {
	apiClientID, _ := APIClientIDFromContext(r.Context())
	id := chi.URLParam(r, "id")

	var req changeEmailRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "cuerpo de la solicitud inválido")
		return
	}
	if req.NewEmail == "" {
		writeError(w, http.StatusBadRequest, "new_email es obligatorio")
		return
	}

	if err := h.svc.AdminChangeEmail(r.Context(), apiClientID, id, req.NewEmail); err != nil {
		switch {
		case errors.Is(err, user.ErrInvalidEmail):
			writeError(w, http.StatusBadRequest, "el correo no tiene un formato válido")
		case errors.Is(err, user.ErrEmailTaken):
			writeError(w, http.StatusConflict, "ese correo ya está en uso en este sistema")
		case errors.Is(err, ErrEmailSendFailed):
			writeError(w, http.StatusBadGateway, "no se pudo enviar el correo, intenta de nuevo más tarde")
		default:
			writeAdminUserActionError(w, err)
		}
		return
	}
	h.logUserAction(r, apiClientID, id, audit.ActionUserEmailChangeRequest)
	w.WriteHeader(http.StatusNoContent)
}

// userListItem is deliberately a narrow projection of user.User — no
// PasswordHash, no TOTP secret (it isn't even on user.User — see its doc
// comment), same "never leaves the server" rule the rest of this package
// already follows for sensitive fields. APIClientID is included because
// ListUsers is the one Admin* route that can return results spanning
// multiple tenants (see ListUsers' doc comment) — without it, a result
// from /admin/users wouldn't say which tenant it belongs to. APIClientName
// rides alongside it (see user.ListedUser) so the panel doesn't have to
// separately fetch the full client list — which only a superadmin can do
// — just to show which tenant each row belongs to; always present, never
// omitted, "" when the tenant can't be resolved.
type userListItem struct {
	ID                    string    `json:"id"`
	APIClientID           string    `json:"api_client_id"`
	APIClientName         string    `json:"api_client_name"`
	Email                 string    `json:"email"`
	Username              string    `json:"username"`
	RUT                   string    `json:"rut"`
	IsActive              bool      `json:"is_active"`
	EmailVerified         bool      `json:"email_verified"`
	TwoFactorMethodChosen bool      `json:"two_factor_method_chosen"`
	PinRequiredAtLogin    bool      `json:"pin_required_at_login"`
	CreatedAt             time.Time `json:"created_at"`
}

type listUsersResponse struct {
	Users    []userListItem `json:"users"`
	Page     int            `json:"page"`
	PageSize int            `json:"page_size"`
	Total    int            `json:"total"`
}

// ListUsers returns one page of registered users — see Service.
// AdminListUsers's doc comment for why this is the only Admin* handler
// with no {id} in its path. Through /system-admin/users, apiClientID
// (read from context, same as every other Admin* handler) is always a
// real tenant id, so results are scoped to the caller's own tenant, same
// as the other four actions. Through /admin/users, apiClientID is always
// "" (the operator's unscoped X-Admin-Token sets no tenant in context),
// so this instead spans every tenant — the one Admin* route where that's
// true. page/page_size/q are read from the query string; missing or
// invalid page/page_size fall back to Service.AdminListUsers' own
// defaults/clamping rather than rejecting the request outright. q is
// optional — omitted or empty behaves exactly like the plain paginated
// listing did before q existed.
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
			APIClientID:           u.APIClientID,
			APIClientName:         u.APIClientName,
			Email:                 u.Email,
			Username:              u.Username,
			RUT:                   u.RUT,
			IsActive:              u.IsActive,
			EmailVerified:         u.EmailVerified,
			TwoFactorMethodChosen: u.TwoFactorMethodChosen,
			PinRequiredAtLogin:    u.PinRequiredAtLogin,
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
