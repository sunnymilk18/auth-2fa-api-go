package httpserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"auth-2fa-api/internal/adminauth"
	"auth-2fa-api/internal/adminctx"
	"auth-2fa-api/internal/audit"
	"auth-2fa-api/internal/auth"
	"auth-2fa-api/internal/middleware"
)

// adminAuthHandlers backs the operator panel's own login (/admin/auth/*)
// and admin-account management (/admin/accounts/*) — separate from
// blacklistHandlers/AdminHandlers the same way adminauth.Service is
// separate from middleware.Blacklist/auth.Service: this is about *who* is
// allowed to act as the operator, not about what the operator can do to
// tenants/users once logged in.
type adminAuthHandlers struct {
	svc        *adminauth.Service
	audit      *audit.Service
	sessionTTL time.Duration
	// cookieSameSite is http.SameSiteNoneMode while the panel and the API
	// live on different registrable domains (e.g. today's sslip.io
	// addresses, which are on the Public Suffix List — the panel and the
	// API count as different "sites" to the browser even though both
	// hostnames contain "sslip.io") and http.SameSiteStrictMode once both
	// move under one real domain the operator controls (e.g.
	// panel.example.com + api.example.com — same registrable domain, so
	// "same site" to the browser). Driven by config.Config.
	// AdminSessionCrossSite so switching it later is a single env var, not
	// a code change — see middleware.AdminPanelHeader's doc comment for
	// the CSRF mitigation that's required to stay on while this is None.
	cookieSameSite http.SameSite
	logger         *slog.Logger
}

func newAdminAuthHandlers(svc *adminauth.Service, auditSvc *audit.Service, sessionTTL time.Duration, cookieSameSite http.SameSite, logger *slog.Logger) *adminAuthHandlers {
	return &adminAuthHandlers{svc: svc, audit: auditSvc, sessionTTL: sessionTTL, cookieSameSite: cookieSameSite, logger: logger}
}

// accountLabel is a best-effort lookup of id's email for an audit entry —
// "" (never an error) if it can't be resolved, since a label lookup
// failing must never block the real action it describes.
func (h *adminAuthHandlers) accountLabel(r *http.Request, id string) string {
	a, err := h.svc.FindAccountByID(r.Context(), id)
	if err != nil {
		return ""
	}
	return a.Email
}

// logAccountAction writes an audit entry for a mutating /admin/accounts or
// self-service action — actor/role from adminctx, same as every other
// /admin/* handler. target is the admin account the action was about
// (itself, for the self-service endpoints).
func (h *adminAuthHandlers) logAccountAction(r *http.Request, action, targetID, targetEmail string) {
	actor, _ := adminctx.Actor(r.Context())
	role, _ := adminctx.Role(r.Context())
	h.audit.Log(r.Context(), audit.Entry{
		ActorEmail: actor, ActorRole: role, Action: action,
		TargetType: audit.TargetTypeAdminAccount, TargetID: targetID, TargetLabel: targetEmail,
		ActorIP: audit.RemoteIP(r),
	})
}

func (h *adminAuthHandlers) setSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     middleware.AdminSessionCookieName,
		Value:    token,
		Path:     "/admin",
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   true,
		SameSite: h.cookieSameSite,
	})
}

func (h *adminAuthHandlers) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     middleware.AdminSessionCookieName,
		Value:    "",
		Path:     "/admin",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: h.cookieSameSite,
	})
}

type adminLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	TOTPCode string `json:"totp_code"`
}

// Login authenticates an individual admin (email + password + mandatory
// TOTP) and, on success, sets the httpOnly session cookie the panel's
// subsequent requests ride on — see adminauth.Service.Login and this
// file's own doc comment for why this exists alongside X-Admin-Token.
func (h *adminAuthHandlers) Login(w http.ResponseWriter, r *http.Request) {
	var req adminLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "cuerpo de la solicitud inválido")
		return
	}

	// Logged by email, not account id — a failed attempt (wrong email,
	// wrong password, locked out) never proves an account by that email
	// even exists, so there's no id to log in that case; the attempted
	// email itself is exactly what's useful for "did someone keep trying
	// to get into this account". See audit.Entry's doc comment: never a
	// secret, and a plaintext email here is the same thing GET /admin/users
	// already shows for the exact same account.
	logLoginAttempt := func(ok bool, role string) {
		action := audit.ActionAdminLogin
		if !ok {
			action = audit.ActionAdminLoginFailed
		}
		h.audit.Log(r.Context(), audit.Entry{
			ActorEmail: req.Email, ActorRole: role, Action: action,
			TargetType: audit.TargetTypeAdminAccount, TargetLabel: req.Email,
			ActorIP: audit.RemoteIP(r),
		})
	}

	token, expiresAt, err := h.svc.Login(r.Context(), req.Email, req.Password, req.TOTPCode)
	if err != nil {
		var locked *auth.LockedOutError
		if errors.As(err, &locked) {
			logLoginAttempt(false, "")
			w.Header().Set("Retry-After", fmt.Sprintf("%.0f", locked.RetryAfter.Seconds()))
			writeJSONError(w, http.StatusTooManyRequests, "demasiados intentos fallidos, vuelve a intentar más tarde")
			return
		}
		if errors.Is(err, adminauth.ErrInvalidCredentials) {
			logLoginAttempt(false, "")
			writeJSONError(w, http.StatusUnauthorized, "credenciales inválidas")
			return
		}
		h.logger.Error("admin login failed", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "no se pudo iniciar sesión")
		return
	}

	_, role, _, _ := h.svc.ValidateSession(r.Context(), token)
	logLoginAttempt(true, role)

	h.setSessionCookie(w, token, expiresAt)
	h.logger.Info("admin logged in", "email", req.Email)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"email": req.Email})
}

// Logout revokes the session the caller's cookie points to and clears it —
// every other session the same admin holds elsewhere is untouched.
func (h *adminAuthHandlers) Logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(middleware.AdminSessionCookieName); err == nil && cookie.Value != "" {
		if err := h.svc.Logout(r.Context(), cookie.Value); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "no se pudo cerrar sesión")
			return
		}
	}
	h.clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

type meResponse struct {
	Actor string `json:"actor"`
	Role  string `json:"role"`
}

// Me reports who the caller is currently authenticated as (actor — the
// admin's own email, or middleware.AdminActorToken for the shared
// X-Admin-Token/script path — and role) without performing any action.
// Sits behind the same middleware.RequireAdminAccess as every other
// /admin/* route, not RequireSuperAdmin — any valid session can ask who
// it is. This is what the panel calls on load/refresh to restore "am I
// logged in, and with which role" without the browser ever exposing the
// session cookie's value to JavaScript (it's httpOnly), and what it uses
// to decide which superadmin-only controls to show or hide in the UI —
// the backend still enforces the real boundary on every actual request
// regardless of what the UI shows.
func (h *adminAuthHandlers) Me(w http.ResponseWriter, r *http.Request) {
	actor, _ := adminctx.Actor(r.Context())
	role, _ := adminctx.Role(r.Context())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meResponse{Actor: actor, Role: role})
}

type adminAccountResponse struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	Active    bool   `json:"active"`
	CreatedAt int64  `json:"created_at"`
}

type listAdminAccountsResponse struct {
	Accounts []adminAccountResponse `json:"accounts"`
}

// ListAccounts returns every admin account — never PasswordHash or
// TOTPSecretEnc, same "never leak the credential itself" rule every other
// listing in this codebase already follows for API keys/password hashes.
func (h *adminAuthHandlers) ListAccounts(w http.ResponseWriter, r *http.Request) {
	accounts, err := h.svc.ListAccounts(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "no se pudieron listar los administradores")
		return
	}

	out := make([]adminAccountResponse, 0, len(accounts))
	for _, a := range accounts {
		out = append(out, adminAccountResponse{
			ID:        a.ID,
			Email:     a.Email,
			Role:      string(a.Role),
			Active:    a.Active,
			CreatedAt: a.CreatedAt.Unix(),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(listAdminAccountsResponse{Accounts: out})
}

type createAdminAccountRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type createAdminAccountResponse struct {
	ID         string `json:"id"`
	Email      string `json:"email"`
	Role       string `json:"role"`
	OTPAuthURL string `json:"otpauth_url"`
}

// CreateAccount provisions a new admin account — callable only by an
// already-authenticated superadmin (see router.go's RequireSuperAdmin
// wiring on this route), so this is how a second, third, etc. admin gets
// onboarded once the first one exists (that first one still has to come
// from cmd/createadmin — see its own doc comment for why). role must be
// exactly "admin" or "superadmin" — no default, picking the wrong one
// silently would be a real privilege mistake, not a cosmetic one (see
// migration 0016_admin_account_role.sql's doc comment). otpauth_url is
// shown exactly once, same one-time-visibility rule as an API key: the
// panel renders it as a QR code for the new admin to scan immediately,
// and it's never retrievable again afterward.
func (h *adminAuthHandlers) CreateAccount(w http.ResponseWriter, r *http.Request) {
	var req createAdminAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "cuerpo de la solicitud inválido")
		return
	}
	if req.Email == "" || len(req.Password) < 8 {
		writeJSONError(w, http.StatusBadRequest, "email requerido y contraseña de al menos 8 caracteres")
		return
	}

	account, otpauthURL, err := h.svc.CreateAccount(r.Context(), req.Email, req.Password, adminauth.Role(req.Role))
	if err != nil {
		switch {
		case errors.Is(err, adminauth.ErrDuplicateEmail):
			writeJSONError(w, http.StatusConflict, "ya existe un administrador con ese email")
		case errors.Is(err, adminauth.ErrInvalidRole):
			writeJSONError(w, http.StatusBadRequest, `el rol debe ser "admin" o "superadmin"`)
		default:
			writeJSONError(w, http.StatusInternalServerError, "no se pudo crear el administrador")
		}
		return
	}

	actor, _ := adminctx.Actor(r.Context())
	h.logger.Info("admin account created", "actor", actor, "new_admin_email", req.Email, "role", req.Role)
	h.logAccountAction(r, audit.ActionAccountCreate, account.ID, account.Email)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(createAdminAccountResponse{
		ID:         account.ID,
		Email:      account.Email,
		Role:       string(account.Role),
		OTPAuthURL: otpauthURL,
	})
}

// RevokeAccount deactivates an admin account and kills every session it
// currently holds — see adminauth.Service.RevokeAccount, including the
// "can't revoke yourself" / "can't revoke the last active admin" rules.
// The former only applies when the caller is an actual logged-in admin
// (middleware.AdminActorToken means the X-Admin-Token/script path, which
// has no "self" to protect — Service.RevokeAccount treats "" the same
// way).
func (h *adminAuthHandlers) RevokeAccount(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	label := h.accountLabel(r, id)

	actor, _ := adminctx.Actor(r.Context())
	actorEmail := actor
	if actor == middleware.AdminActorToken {
		actorEmail = ""
	}

	if err := h.svc.RevokeAccount(r.Context(), actorEmail, id); err != nil {
		switch {
		case errors.Is(err, adminauth.ErrNotFound):
			writeJSONError(w, http.StatusNotFound, "administrador no encontrado")
		case errors.Is(err, adminauth.ErrCannotRevokeSelf):
			writeJSONError(w, http.StatusConflict, "no puedes revocar tu propia cuenta")
		case errors.Is(err, adminauth.ErrLastSuperAdminAccount):
			writeJSONError(w, http.StatusConflict, "no puedes revocar al único superadministrador activo")
		default:
			writeJSONError(w, http.StatusInternalServerError, "no se pudo revocar el administrador")
		}
		return
	}

	h.logger.Info("admin account revoked", "actor", actor, "revoked_admin_id", id)
	h.logAccountAction(r, audit.ActionAccountRevoke, id, label)
	w.WriteHeader(http.StatusNoContent)
}

type reactivateAccountRequest struct {
	Password string `json:"password"`
}

// Reactivate brings a revoked admin account back with a brand-new
// password and TOTP secret — never the ones it had before, see
// adminauth.Service.ReactivateAccount's doc comment for why. Only
// meaningful on a currently-revoked account (409 otherwise); the response
// shape and one-time-visibility rule for otpauth_url are identical to
// CreateAccount's, since reactivating is effectively re-provisioning from
// scratch.
func (h *adminAuthHandlers) Reactivate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var req reactivateAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "cuerpo de la solicitud inválido")
		return
	}
	if len(req.Password) < 8 {
		writeJSONError(w, http.StatusBadRequest, "contraseña de al menos 8 caracteres")
		return
	}

	account, otpauthURL, err := h.svc.ReactivateAccount(r.Context(), id, req.Password)
	if err != nil {
		switch {
		case errors.Is(err, adminauth.ErrNotFound):
			writeJSONError(w, http.StatusNotFound, "administrador no encontrado")
		case errors.Is(err, adminauth.ErrAccountAlreadyActive):
			writeJSONError(w, http.StatusConflict, "la cuenta ya está activa")
		default:
			writeJSONError(w, http.StatusInternalServerError, "no se pudo reactivar el administrador")
		}
		return
	}

	actor, _ := adminctx.Actor(r.Context())
	h.logger.Info("admin account reactivated", "actor", actor, "reactivated_admin_id", id)
	h.logAccountAction(r, audit.ActionAccountReactivate, account.ID, account.Email)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(createAdminAccountResponse{
		ID:         account.ID,
		Email:      account.Email,
		Role:       string(account.Role),
		OTPAuthURL: otpauthURL,
	})
}

// selfServiceActor resolves the caller's own email for the three
// self-service handlers below (ChangePassword, RotateTOTP,
// ConfirmRotateTOTP) and the raw session token to keep alive (see
// adminauth.Service.ChangeOwnPassword's doc comment on why one session
// survives). Refuses outright when the caller authenticated with the
// shared X-Admin-Token (middleware.AdminActorToken) rather than an
// individual session — there's no "own account" to act on in that case,
// and none of these three actions make sense for the script/automation
// credential.
func selfServiceActor(w http.ResponseWriter, r *http.Request) (email, sessionToken string, ok bool) {
	actor, _ := adminctx.Actor(r.Context())
	if actor == "" || actor == middleware.AdminActorToken {
		writeJSONError(w, http.StatusBadRequest, "esta acción requiere una sesión de administrador individual, no el token compartido")
		return "", "", false
	}
	cookie, err := r.Cookie(middleware.AdminSessionCookieName)
	if err != nil || cookie.Value == "" {
		writeJSONError(w, http.StatusBadRequest, "esta acción requiere una sesión de administrador individual")
		return "", "", false
	}
	return actor, cookie.Value, true
}

// writeSelfServiceError maps the handful of errors ChangeOwnPassword/
// StartTOTPRotation/ConfirmTOTPRotation can return to HTTP. Deliberately
// never 401 for a wrong password/code — see adminauth.
// ErrCurrentPasswordIncorrect's doc comment for why: the panel treats 401
// as "the session ended" and redirects to the login screen, which would
// be wrong here (the session is fine, only the typed secret was wrong).
func writeSelfServiceError(w http.ResponseWriter, err error) {
	var locked *auth.LockedOutError
	switch {
	case errors.As(err, &locked):
		w.Header().Set("Retry-After", fmt.Sprintf("%.0f", locked.RetryAfter.Seconds()))
		writeJSONError(w, http.StatusTooManyRequests, "demasiados intentos fallidos, vuelve a intentar más tarde")
	case errors.Is(err, adminauth.ErrCurrentPasswordIncorrect):
		writeJSONError(w, http.StatusForbidden, "la contraseña actual no es correcta")
	case errors.Is(err, adminauth.ErrTOTPCodeIncorrect):
		writeJSONError(w, http.StatusForbidden, "el código no es válido")
	case errors.Is(err, adminauth.ErrNoPendingTOTPRotation):
		writeJSONError(w, http.StatusNotFound, "no hay una rotación de TOTP pendiente, vuelve a iniciarla")
	default:
		writeJSONError(w, http.StatusInternalServerError, "no se pudo completar la operación")
	}
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// ChangePassword lets the caller change their own password — see
// adminauth.Service.ChangeOwnPassword's doc comment for the verification,
// throttling, and "keep this session, kill every other one" behavior.
func (h *adminAuthHandlers) ChangePassword(w http.ResponseWriter, r *http.Request) {
	email, sessionToken, ok := selfServiceActor(w, r)
	if !ok {
		return
	}

	var req changePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "cuerpo de la solicitud inválido")
		return
	}
	if len(req.NewPassword) < 8 {
		writeJSONError(w, http.StatusBadRequest, "la contraseña nueva debe tener al menos 8 caracteres")
		return
	}

	if err := h.svc.ChangeOwnPassword(r.Context(), email, sessionToken, req.CurrentPassword, req.NewPassword); err != nil {
		writeSelfServiceError(w, err)
		return
	}

	h.logger.Info("admin changed own password", "actor", email)
	h.logAccountAction(r, audit.ActionAccountPasswordChange, "", email)
	w.WriteHeader(http.StatusNoContent)
}

type rotateTOTPRequest struct {
	Password string `json:"password"`
}

type rotateTOTPResponse struct {
	OTPAuthURL string `json:"otpauth_url"`
}

// RotateTOTP is step one of two for replacing the caller's own TOTP
// secret — see adminauth.Service.StartTOTPRotation's doc comment. Does
// NOT touch the account's active secret; nothing changes until
// ConfirmRotateTOTP succeeds.
func (h *adminAuthHandlers) RotateTOTP(w http.ResponseWriter, r *http.Request) {
	email, _, ok := selfServiceActor(w, r)
	if !ok {
		return
	}

	var req rotateTOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "cuerpo de la solicitud inválido")
		return
	}

	otpauthURL, err := h.svc.StartTOTPRotation(r.Context(), email, req.Password)
	if err != nil {
		writeSelfServiceError(w, err)
		return
	}

	h.logger.Info("admin started totp rotation", "actor", email)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rotateTOTPResponse{OTPAuthURL: otpauthURL})
}

type confirmRotateTOTPRequest struct {
	Code string `json:"code"`
}

// ConfirmRotateTOTP is step two: a valid code from the secret RotateTOTP
// just generated replaces the account's real one — see adminauth.Service.
// ConfirmTOTPRotation's doc comment, including why a wrong code doesn't
// consume the pending rotation (safe to retry) and why every other
// session gets revoked on success.
func (h *adminAuthHandlers) ConfirmRotateTOTP(w http.ResponseWriter, r *http.Request) {
	email, sessionToken, ok := selfServiceActor(w, r)
	if !ok {
		return
	}

	var req confirmRotateTOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "cuerpo de la solicitud inválido")
		return
	}

	if err := h.svc.ConfirmTOTPRotation(r.Context(), email, sessionToken, req.Code); err != nil {
		writeSelfServiceError(w, err)
		return
	}

	h.logger.Info("admin confirmed totp rotation", "actor", email)
	h.logAccountAction(r, audit.ActionAccountTOTPRotate, "", email)
	w.WriteHeader(http.StatusNoContent)
}
