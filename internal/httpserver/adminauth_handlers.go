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

func newAdminAuthHandlers(svc *adminauth.Service, sessionTTL time.Duration, cookieSameSite http.SameSite, logger *slog.Logger) *adminAuthHandlers {
	return &adminAuthHandlers{svc: svc, sessionTTL: sessionTTL, cookieSameSite: cookieSameSite, logger: logger}
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

	token, expiresAt, err := h.svc.Login(r.Context(), req.Email, req.Password, req.TOTPCode)
	if err != nil {
		var locked *auth.LockedOutError
		if errors.As(err, &locked) {
			w.Header().Set("Retry-After", fmt.Sprintf("%.0f", locked.RetryAfter.Seconds()))
			writeJSONError(w, http.StatusTooManyRequests, "demasiados intentos fallidos, vuelve a intentar más tarde")
			return
		}
		if errors.Is(err, adminauth.ErrInvalidCredentials) {
			writeJSONError(w, http.StatusUnauthorized, "credenciales inválidas")
			return
		}
		h.logger.Error("admin login failed", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "no se pudo iniciar sesión")
		return
	}

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

type adminAccountResponse struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
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
}

type createAdminAccountResponse struct {
	ID         string `json:"id"`
	Email      string `json:"email"`
	OTPAuthURL string `json:"otpauth_url"`
}

// CreateAccount provisions a new admin account — callable only by an
// already-authenticated admin (same as every other /admin/accounts route),
// so this is how a second, third, etc. admin gets onboarded once the first
// one exists (that first one still has to come from cmd/createadmin — see
// its own doc comment for why). otpauth_url is shown exactly once, same
// one-time-visibility rule as an API key: the panel renders it as a QR
// code for the new admin to scan immediately, and it's never retrievable
// again afterward.
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

	account, otpauthURL, err := h.svc.CreateAccount(r.Context(), req.Email, req.Password)
	if err != nil {
		if errors.Is(err, adminauth.ErrDuplicateEmail) {
			writeJSONError(w, http.StatusConflict, "ya existe un administrador con ese email")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "no se pudo crear el administrador")
		return
	}

	actor, _ := auth.AdminActorFromContext(r.Context())
	h.logger.Info("admin account created", "actor", actor, "new_admin_email", req.Email)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(createAdminAccountResponse{
		ID:         account.ID,
		Email:      account.Email,
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

	actor, _ := auth.AdminActorFromContext(r.Context())
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
		case errors.Is(err, adminauth.ErrLastAdminAccount):
			writeJSONError(w, http.StatusConflict, "no puedes revocar al único administrador activo")
		default:
			writeJSONError(w, http.StatusInternalServerError, "no se pudo revocar el administrador")
		}
		return
	}

	h.logger.Info("admin account revoked", "actor", actor, "revoked_admin_id", id)
	w.WriteHeader(http.StatusNoContent)
}
