package apiclient

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

// Handlers exposes the same operations as cmd/createclient over HTTP,
// under /admin/clients — gated by middleware.RequireAdminToken, never by
// RequireAPIKey (a tenant must never be able to provision other tenants).
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

// clientResponse deliberately omits APIKeyHash — even hashed, there's no
// reason for it to ever leave the server.
type clientResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func toResponse(c *APIClient) clientResponse {
	return clientResponse{ID: c.ID, Name: c.Name, Active: c.Active, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt}
}

// --- Create ---

type createRequest struct {
	Name string `json:"name"`
}

type createResponse struct {
	clientResponse
	// Shown exactly once — same as cmd/createclient's own output. Nothing
	// server-side keeps the plaintext key around to show it again later.
	APIKey string `json:"api_key"`
}

func (h *Handlers) Create(w http.ResponseWriter, r *http.Request) {
	var req createRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "cuerpo de la solicitud inválido")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "el campo name es obligatorio")
		return
	}

	client, plaintextKey, err := h.svc.Create(r.Context(), req.Name)
	if err != nil {
		if errors.Is(err, ErrNameTaken) {
			writeError(w, http.StatusConflict, "ya existe un cliente con ese nombre")
			return
		}
		writeError(w, http.StatusInternalServerError, "no se pudo crear el cliente")
		return
	}

	writeJSON(w, http.StatusCreated, createResponse{clientResponse: toResponse(client), APIKey: plaintextKey})
}

// --- List ---

func (h *Handlers) List(w http.ResponseWriter, r *http.Request) {
	clients, err := h.svc.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "no se pudo listar los clientes")
		return
	}

	out := make([]clientResponse, 0, len(clients))
	for _, c := range clients {
		out = append(out, toResponse(c))
	}
	writeJSON(w, http.StatusOK, out)
}

// --- Deactivate / Activate ---

func (h *Handlers) Deactivate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.svc.Deactivate(r.Context(), id); err != nil {
		writeClientActionError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) Activate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.svc.Activate(r.Context(), id); err != nil {
		writeClientActionError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Rotate ---

type rotateResponse struct {
	// Same one-time-visibility rule as Create.
	APIKey string `json:"api_key"`
}

func (h *Handlers) Rotate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	plaintextKey, err := h.svc.Rotate(r.Context(), id)
	if err != nil {
		writeClientActionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rotateResponse{APIKey: plaintextKey})
}

func writeClientActionError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrNotFound) {
		writeError(w, http.StatusNotFound, "cliente no encontrado")
		return
	}
	writeError(w, http.StatusInternalServerError, "no se pudo completar la operación")
}
