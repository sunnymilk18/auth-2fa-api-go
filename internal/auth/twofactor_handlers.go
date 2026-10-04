package auth

import (
	"errors"
	"log"
	"net/http"
)

// This file holds every HTTP handler specific to the optional second
// factor: the "email" branch of the first-login method choice
// (SendLoginEmailCode), and TOTP enrollment/confirmation/disabling — the
// "authenticator app" branch of that same choice lives in ConfirmTOTP too,
// via its login_token mode. Login/VerifyOTP in handlers.go own the core
// login flow itself and hand off here only by way of the login_token
// they issue — see handlers.go's own doc comments for that half.

// --- First-login "choose your method" (see auth.Service.LoginStep1) ---

type sendLoginEmailCodeRequest struct {
	LoginToken string `json:"login_token"`
}

// SendLoginEmailCode is the "email" branch: the client got needs_2fa_setup
// from Login and picked email. From here on the same login_token behaves
// exactly like any other email login — VerifyOTP finishes it.
func (h *Handlers) SendLoginEmailCode(w http.ResponseWriter, r *http.Request) {
	var req sendLoginEmailCodeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "cuerpo de la solicitud inválido")
		return
	}
	if req.LoginToken == "" {
		writeError(w, http.StatusBadRequest, "login_token es obligatorio")
		return
	}

	if err := h.svc.SendLoginEmailCode(r.Context(), req.LoginToken); err != nil {
		switch {
		case errors.Is(err, ErrLoginSessionNotFound):
			writeError(w, http.StatusUnauthorized, "la sesión de login no existe o expiró, vuelve a iniciar sesión")
		case errors.Is(err, ErrTOTPNotConfigured):
			writeError(w, http.StatusNotFound, "la verificación por app autenticadora no está disponible")
		default:
			log.Printf("send login email code error: %v", err)
			writeError(w, http.StatusInternalServerError, "no se pudo enviar el código")
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "código de verificación enviado por correo"})
}

// --- TOTP (authenticator app) — opt-in alternative to the emailed OTP ---

type totpEnrollResponse struct {
	// OTPAuthURL is what a client renders as a QR code (or shows as a
	// manual-entry secret) — it embeds the secret itself, so nothing else
	// needs to be returned separately.
	OTPAuthURL string `json:"otpauth_url"`
}

type totpEnrollRequest struct {
	// LoginToken is only used in the first-login setup flow (see
	// auth.Service.LoginStep1's doc comment) — omitted (and ignored) when
	// calling this with a Bearer token, the normal "change method later"
	// path from an already-authenticated settings screen.
	LoginToken string `json:"login_token,omitempty"`
}

// EnrollTOTP starts activating an authenticator app for an account. Two
// ways to prove it's really that account's request, same underlying
// service call either way:
//   - Authorization: Bearer <access_token> — a completed login already
//     happened (password+OTP, device login, or this same first-login flow
//     for a different method previously), same bar as RegisterDevice.
//   - {"login_token": "..."} in the body — the pending-setup token
//     LoginStep1 just handed back on this account's very first login,
//     before any access_token exists yet.
//
// Not yet active for login until ConfirmTOTP proves the code the app
// produces actually matches.
func (h *Handlers) EnrollTOTP(w http.ResponseWriter, r *http.Request) {
	if userID, ok := UserIDFromContext(r.Context()); ok {
		email, _ := EmailFromContext(r.Context())
		h.startTOTPEnrollment(w, r, userID, email)
		return
	}

	var req totpEnrollRequest
	_ = decodeJSON(r, &req) // no Bearer path has no body at all; an empty/absent one here just fails the LoginToken=="" check below
	if req.LoginToken == "" {
		writeError(w, http.StatusUnauthorized, "no autorizado")
		return
	}

	userID, email, err := h.svc.PeekTwoFactorSetup(r.Context(), req.LoginToken)
	if err != nil {
		switch {
		case errors.Is(err, ErrLoginSessionNotFound):
			writeError(w, http.StatusUnauthorized, "la sesión de login no existe o expiró, vuelve a iniciar sesión")
		case errors.Is(err, ErrTOTPNotConfigured):
			writeError(w, http.StatusNotFound, "la verificación por app autenticadora no está disponible")
		default:
			log.Printf("enroll totp (setup flow) error: %v", err)
			writeError(w, http.StatusInternalServerError, "no se pudo iniciar la activación")
		}
		return
	}
	h.startTOTPEnrollment(w, r, userID, email)
}

func (h *Handlers) startTOTPEnrollment(w http.ResponseWriter, r *http.Request, userID, email string) {
	otpauthURL, err := h.svc.StartTOTPEnrollment(r.Context(), userID, email)
	if err != nil {
		if errors.Is(err, ErrTOTPNotConfigured) {
			writeError(w, http.StatusNotFound, "la verificación por app autenticadora no está disponible")
			return
		}
		log.Printf("enroll totp error: %v", err)
		writeError(w, http.StatusInternalServerError, "no se pudo iniciar la activación")
		return
	}
	writeJSON(w, http.StatusOK, totpEnrollResponse{OTPAuthURL: otpauthURL})
}

type totpConfirmRequest struct {
	Code string `json:"code"`
	// LoginToken: same meaning as in totpEnrollRequest — only used in the
	// first-login setup flow.
	LoginToken string `json:"login_token,omitempty"`
}

// ConfirmTOTP finishes activating the authenticator app started by
// EnrollTOTP. Two different outcomes depending on which of EnrollTOTP's two
// modes this follows:
//   - Bearer token (changing method from an already-authenticated
//     settings screen): 204, no tokens — the caller already has a session.
//   - login_token (first-login setup flow): activating TOTP also completes
//     the login right here — 200 with a fresh access/refresh token pair,
//     no separate VerifyOTP call needed.
func (h *Handlers) ConfirmTOTP(w http.ResponseWriter, r *http.Request) {
	var req totpConfirmRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "cuerpo de la solicitud inválido")
		return
	}
	if req.Code == "" {
		writeError(w, http.StatusBadRequest, "el código es obligatorio")
		return
	}

	if userID, ok := UserIDFromContext(r.Context()); ok {
		if err := h.svc.ConfirmTOTPEnrollment(r.Context(), userID, req.Code); err != nil {
			writeConfirmTOTPError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if req.LoginToken == "" {
		writeError(w, http.StatusUnauthorized, "no autorizado")
		return
	}
	result, err := h.svc.ConfirmTOTPEnrollmentAndLogin(r.Context(), req.LoginToken, req.Code)
	if err != nil {
		if errors.Is(err, ErrLoginSessionNotFound) {
			writeError(w, http.StatusUnauthorized, "la sesión de login no existe o expiró, vuelve a iniciar sesión")
			return
		}
		writeConfirmTOTPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, loginResultResponse(result))
}

func writeConfirmTOTPError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrTOTPNotConfigured):
		writeError(w, http.StatusNotFound, "la verificación por app autenticadora no está disponible")
	case errors.Is(err, ErrInvalidTOTPCode):
		writeError(w, http.StatusUnauthorized, "código inválido")
	default:
		log.Printf("confirm totp error: %v", err)
		writeError(w, http.StatusInternalServerError, "no se pudo confirmar la activación")
	}
}

// DisableTOTP turns the authenticator-app factor off — login falls back to
// the emailed OTP. No code required, same bar as RevokeDevice.
func (h *Handlers) DisableTOTP(w http.ResponseWriter, r *http.Request) {
	userID, ok := UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "no autorizado")
		return
	}

	if err := h.svc.DisableTOTP(r.Context(), userID); err != nil {
		log.Printf("disable totp error: %v", err)
		writeError(w, http.StatusInternalServerError, "no se pudo desactivar")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
