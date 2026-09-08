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
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Email == "" || len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "email is required and password must be at least 8 characters")
		return
	}

	apiClientID, ok := APIClientIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing or invalid api key")
		return
	}

	u, err := h.svc.Register(r.Context(), apiClientID, req.Email, req.Password)
	if err != nil {
		if errors.Is(err, user.ErrEmailTaken) {
			writeError(w, http.StatusConflict, "email already registered")
			return
		}
		log.Printf("register error: %v", err)
		writeError(w, http.StatusInternalServerError, "could not register user")
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
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	apiClientID, ok := APIClientIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing or invalid api key")
		return
	}

	loginToken, err := h.svc.LoginStep1(r.Context(), apiClientID, req.Email, req.Password)
	if err != nil {
		if errors.Is(err, user.ErrInvalidCredentials) {
			writeError(w, http.StatusUnauthorized, "invalid email or password")
			return
		}
		log.Printf("login error: %v", err)
		writeError(w, http.StatusInternalServerError, "could not start login")
		return
	}

	writeJSON(w, http.StatusOK, loginResponse{
		LoginToken: loginToken,
		Message:    "verification code sent to email",
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
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	access, refresh, err := h.svc.LoginStep2(r.Context(), req.LoginToken, req.Code)
	if err != nil {
		switch {
		case errors.Is(err, ErrLoginSessionNotFound):
			writeError(w, http.StatusUnauthorized, "login session not found or expired, please login again")
		case errors.Is(err, ErrInvalidCode):
			writeError(w, http.StatusUnauthorized, "invalid code")
		case errors.Is(err, ErrTooManyAttempts):
			writeError(w, http.StatusTooManyRequests, "too many attempts, please login again")
		default:
			log.Printf("verify otp error: %v", err)
			writeError(w, http.StatusInternalServerError, "could not verify code")
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
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	access, refresh, err := h.svc.Refresh(r.Context(), req.RefreshToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or expired refresh token")
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
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.svc.Logout(r.Context(), req.RefreshToken); err != nil {
		writeError(w, http.StatusInternalServerError, "could not logout")
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
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req registerDeviceRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.DeviceID == "" {
		writeError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	deviceToken, err := h.svc.RegisterDevice(r.Context(), userID, req.DeviceID, req.DeviceName, req.Pin)
	if err != nil {
		if errors.Is(err, device.ErrInvalidPinFormat) {
			writeError(w, http.StatusBadRequest, "pin must be exactly 6 digits")
			return
		}
		log.Printf("register device error: %v", err)
		writeError(w, http.StatusInternalServerError, "could not register device")
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
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	access, refresh, newDeviceToken, err := h.svc.DeviceLogin(r.Context(), req.DeviceID, req.DeviceToken, req.Pin)
	if err != nil {
		switch {
		case errors.Is(err, device.ErrDeviceNotTrusted):
			writeError(w, http.StatusUnauthorized, "device not trusted, please login with password and email code")
		case errors.Is(err, device.ErrInvalidPin):
			writeError(w, http.StatusUnauthorized, "invalid pin")
		case errors.Is(err, device.ErrTooManyPinTries):
			writeError(w, http.StatusTooManyRequests, "too many failed pin attempts, please login again")
		default:
			log.Printf("device login error: %v", err)
			writeError(w, http.StatusInternalServerError, "could not login with device")
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
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	devices, err := h.svc.ListDevices(r.Context(), userID)
	if err != nil {
		log.Printf("list devices error: %v", err)
		writeError(w, http.StatusInternalServerError, "could not list devices")
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
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	id := chi.URLParam(r, "id")
	if err := h.svc.RevokeDevice(r.Context(), userID, id); err != nil {
		if errors.Is(err, device.ErrNotFound) {
			writeError(w, http.StatusNotFound, "device not found")
			return
		}
		log.Printf("revoke device error: %v", err)
		writeError(w, http.StatusInternalServerError, "could not revoke device")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

const timeFormat = "2006-01-02T15:04:05Z07:00"
