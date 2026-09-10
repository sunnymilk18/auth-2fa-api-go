package auth

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"

	"auth-2fa-api/internal/device"
	"auth-2fa-api/internal/user"
)

type Handlers struct {
	svc *Service
}

func NewHandlers(svc *Service) *Handlers {
	return &Handlers{svc: svc}
}

type errorResponse struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorResponse{Error: msg})
}

func decodeJSON(r *http.Request, dst interface{}) error {
	return json.NewDecoder(r.Body).Decode(dst)
}

// --- Register ---

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *Handlers) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "cuerpo de la solicitud inválido")
		return
	}
	if req.Email == "" || len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "el correo es obligatorio y la contraseña debe tener al menos 8 caracteres")
		return
	}

	apiClientID, ok := APIClientIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "falta la API key o no es válida")
		return
	}

	u, err := h.svc.Register(r.Context(), apiClientID, req.Email, req.Password)
	if err != nil {
		if errors.Is(err, user.ErrEmailTaken) {
			writeError(w, http.StatusConflict, "el correo ya está registrado")
			return
		}
		log.Printf("register error: %v", err)
		writeError(w, http.StatusInternalServerError, "no se pudo registrar el usuario")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{
		"id":    u.ID,
		"email": u.Email,
	})
}

// --- Login step 1: password -> OTP sent by email ---

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	LoginToken string `json:"login_token"`
	Message    string `json:"message"`
}

func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "cuerpo de la solicitud inválido")
		return
	}

	apiClientID, ok := APIClientIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "falta la API key o no es válida")
		return
	}

	loginToken, err := h.svc.LoginStep1(r.Context(), apiClientID, req.Email, req.Password)
	if err != nil {
		switch {
		case errors.Is(err, user.ErrInvalidCredentials):
			writeError(w, http.StatusUnauthorized, "correo o contraseña incorrectos")
		case errors.Is(err, ErrTooManyFailedLogins):
			writeError(w, http.StatusTooManyRequests, "demasiados intentos fallidos para esta cuenta, intenta de nuevo más tarde")
		default:
			log.Printf("login error: %v", err)
			writeError(w, http.StatusInternalServerError, "no se pudo iniciar el proceso de login")
		}
		return
	}

	writeJSON(w, http.StatusOK, loginResponse{
		LoginToken: loginToken,
		Message:    "código de verificación enviado por correo",
	})
}

// --- Login step 2: OTP -> tokens ---

type verifyRequest struct {
	LoginToken string `json:"login_token"`
	Code       string `json:"code"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

func (h *Handlers) VerifyOTP(w http.ResponseWriter, r *http.Request) {
	var req verifyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "cuerpo de la solicitud inválido")
		return
	}

	access, refresh, err := h.svc.LoginStep2(r.Context(), req.LoginToken, req.Code)
	if err != nil {
		switch {
		case errors.Is(err, ErrLoginSessionNotFound):
			writeError(w, http.StatusUnauthorized, "la sesión de login no existe o expiró, vuelve a iniciar sesión")
		case errors.Is(err, ErrInvalidCode):
			writeError(w, http.StatusUnauthorized, "código inválido")
		case errors.Is(err, ErrTooManyAttempts):
			writeError(w, http.StatusTooManyRequests, "demasiados intentos, vuelve a iniciar sesión")
		default:
			log.Printf("verify otp error: %v", err)
			writeError(w, http.StatusInternalServerError, "no se pudo verificar el código")
		}
		return
	}

	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  access,
		RefreshToken: refresh,
		TokenType:    "Bearer",
	})
}

// --- Refresh ---

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *Handlers) Refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "cuerpo de la solicitud inválido")
		return
	}

	access, refresh, err := h.svc.Refresh(r.Context(), req.RefreshToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "refresh token inválido o expirado")
		return
	}

	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  access,
		RefreshToken: refresh,
		TokenType:    "Bearer",
	})
}

// --- Logout ---

func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "cuerpo de la solicitud inválido")
		return
	}

	if err := h.svc.Logout(r.Context(), req.RefreshToken); err != nil {
		writeError(w, http.StatusInternalServerError, "no se pudo cerrar sesión")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Password reset ---

type passwordResetRequestRequest struct {
	Email string `json:"email"`
}

type passwordResetConfirmRequest struct {
	Email       string `json:"email"`
	Code        string `json:"code"`
	NewPassword string `json:"new_password"`
}

// RequestPasswordReset emails a reset code if the address matches an
// account. The response is identical either way — it must not reveal
// whether a given email is registered.
func (h *Handlers) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req passwordResetRequestRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "cuerpo de la solicitud inválido")
		return
	}
	if req.Email == "" {
		writeError(w, http.StatusBadRequest, "el correo es obligatorio")
		return
	}

	apiClientID, ok := APIClientIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "falta la API key o no es válida")
		return
	}

	if err := h.svc.RequestPasswordReset(r.Context(), apiClientID, req.Email); err != nil {
		log.Printf("request password reset error: %v", err)
		writeError(w, http.StatusInternalServerError, "no se pudo procesar la solicitud")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "si el correo está registrado, se envió un código para restablecer la contraseña",
	})
}

// ConfirmPasswordReset consumes a reset code and sets a new password.
func (h *Handlers) ConfirmPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req passwordResetConfirmRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "cuerpo de la solicitud inválido")
		return
	}
	if req.Email == "" || req.Code == "" {
		writeError(w, http.StatusBadRequest, "el correo y el código son obligatorios")
		return
	}
	if len(req.NewPassword) < 8 {
		writeError(w, http.StatusBadRequest, "la contraseña debe tener al menos 8 caracteres")
		return
	}

	apiClientID, ok := APIClientIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "falta la API key o no es válida")
		return
	}

	if err := h.svc.ResetPassword(r.Context(), apiClientID, req.Email, req.Code, req.NewPassword); err != nil {
		switch {
		case errors.Is(err, ErrPasswordResetNotFound):
			writeError(w, http.StatusUnauthorized, "no hay un restablecimiento pendiente para ese correo, o expiró")
		case errors.Is(err, ErrPasswordResetInvalidCode):
			writeError(w, http.StatusUnauthorized, "código inválido")
		case errors.Is(err, ErrPasswordResetTooManyTries):
			writeError(w, http.StatusTooManyRequests, "demasiados intentos, solicita un código nuevo")
		default:
			log.Printf("reset password error: %v", err)
			writeError(w, http.StatusInternalServerError, "no se pudo restablecer la contraseña")
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Trusted devices + PIN (shortcut around password+OTP on a known device) ---

type registerDeviceRequest struct {
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
	Pin        string `json:"pin"`
}

type registerDeviceResponse struct {
	DeviceToken string `json:"device_token"`
}

// RegisterDevice marks the caller's device as trusted. Requires a valid
// access token — i.e. the client must have just completed a full
// password+OTP login before calling this.
func (h *Handlers) RegisterDevice(w http.ResponseWriter, r *http.Request) {
	userID, ok := UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "no autorizado")
		return
	}

	var req registerDeviceRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "cuerpo de la solicitud inválido")
		return
	}
	if req.DeviceID == "" {
		writeError(w, http.StatusBadRequest, "device_id es obligatorio")
		return
	}

	deviceToken, err := h.svc.RegisterDevice(r.Context(), userID, req.DeviceID, req.DeviceName, req.Pin)
	if err != nil {
		if errors.Is(err, device.ErrInvalidPinFormat) {
			writeError(w, http.StatusBadRequest, "el PIN debe tener exactamente 6 dígitos")
			return
		}
		log.Printf("register device error: %v", err)
		writeError(w, http.StatusInternalServerError, "no se pudo registrar el dispositivo")
		return
	}

	writeJSON(w, http.StatusCreated, registerDeviceResponse{DeviceToken: deviceToken})
}

type deviceLoginRequest struct {
	DeviceID    string `json:"device_id"`
	DeviceToken string `json:"device_token"`
	Pin         string `json:"pin"`
}

type deviceLoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	DeviceToken  string `json:"device_token"` // rotated — replace the client's stored copy
	TokenType    string `json:"token_type"`
}

// DeviceLogin lets a previously trusted device skip password+OTP by
// presenting its device_token (possession) + pin (knowledge) instead.
func (h *Handlers) DeviceLogin(w http.ResponseWriter, r *http.Request) {
	var req deviceLoginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "cuerpo de la solicitud inválido")
		return
	}

	access, refresh, newDeviceToken, err := h.svc.DeviceLogin(r.Context(), req.DeviceID, req.DeviceToken, req.Pin)
	if err != nil {
		switch {
		case errors.Is(err, device.ErrDeviceNotTrusted):
			writeError(w, http.StatusUnauthorized, "dispositivo no confiable, inicia sesión con tu contraseña y el código de correo")
		case errors.Is(err, device.ErrInvalidPin):
			writeError(w, http.StatusUnauthorized, "PIN inválido")
		case errors.Is(err, device.ErrTooManyPinTries):
			writeError(w, http.StatusTooManyRequests, "demasiados intentos de PIN fallidos, vuelve a iniciar sesión")
		default:
			log.Printf("device login error: %v", err)
			writeError(w, http.StatusInternalServerError, "no se pudo iniciar sesión con el dispositivo")
		}
		return
	}

	writeJSON(w, http.StatusOK, deviceLoginResponse{
		AccessToken:  access,
		RefreshToken: refresh,
		DeviceToken:  newDeviceToken,
		TokenType:    "Bearer",
	})
}

type deviceInfoResponse struct {
	ID         string `json:"id"`
	DeviceName string `json:"device_name"`
	TrustedAt  string `json:"trusted_at"`
	LastUsedAt string `json:"last_used_at"`
	ExpiresAt  string `json:"expires_at"`
}

// ListDevices returns the authenticated user's trusted devices.
func (h *Handlers) ListDevices(w http.ResponseWriter, r *http.Request) {
	userID, ok := UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "no autorizado")
		return
	}

	devices, err := h.svc.ListDevices(r.Context(), userID)
	if err != nil {
		log.Printf("list devices error: %v", err)
		writeError(w, http.StatusInternalServerError, "no se pudieron listar los dispositivos")
		return
	}

	resp := make([]deviceInfoResponse, 0, len(devices))
	for _, d := range devices {
		resp = append(resp, deviceInfoResponse{
			ID:         d.ID,
			DeviceName: d.DeviceName,
			TrustedAt:  d.TrustedAt.Format(timeFormat),
			LastUsedAt: d.LastUsedAt.Format(timeFormat),
			ExpiresAt:  d.ExpiresAt.Format(timeFormat),
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"devices": resp})
}

// RevokeDevice revokes one of the authenticated user's trusted devices.
func (h *Handlers) RevokeDevice(w http.ResponseWriter, r *http.Request) {
	userID, ok := UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "no autorizado")
		return
	}

	id := chi.URLParam(r, "id")
	if err := h.svc.RevokeDevice(r.Context(), userID, id); err != nil {
		if errors.Is(err, device.ErrNotFound) {
			writeError(w, http.StatusNotFound, "dispositivo no encontrado")
			return
		}
		log.Printf("revoke device error: %v", err)
		writeError(w, http.StatusInternalServerError, "no se pudo revocar el dispositivo")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

const timeFormat = "2006-01-02T15:04:05Z07:00"
