package auth

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

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

	u, err := h.svc.Register(r.Context(), req.Email, req.Password)
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

	loginToken, err := h.svc.LoginStep1(r.Context(), req.Email, req.Password)
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
