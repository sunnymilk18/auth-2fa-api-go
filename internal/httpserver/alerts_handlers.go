package httpserver

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"auth-2fa-api/internal/adminctx"
	"auth-2fa-api/internal/audit"
	"auth-2fa-api/internal/authevents"
	"auth-2fa-api/internal/detector"
)

// alertsHandlers respalda /admin/alerts: las alertas que deja el detector de
// accesos anómalos (internal/detector). Lectura y cierre de alertas, nada
// más — el detector las crea por su cuenta, no hay ruta para crearlas.
type alertsHandlers struct {
	repo  *detector.AlertRepository
	audit *audit.Service
}

// maxAlertNoteLength acota la nota opcional al cerrar una alerta.
const maxAlertNoteLength = 1000

// maxAlertBodyBytes acota el cuerpo de dismiss/resolve: solo lleva una nota.
const maxAlertBodyBytes = 8 << 10

type alertTenantResponse struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type alertResponse struct {
	ID          string              `json:"id"`
	Tenant      alertTenantResponse `json:"tenant"`
	IP          *string             `json:"ip"`
	WindowStart string              `json:"window_start"`
	WindowEnd   string              `json:"window_end"`
	Source      string              `json:"source"`
	Score       *float64            `json:"score"`
	Features    detector.Features   `json:"features"`
	Motives     []string            `json:"motives"`
	State       string              `json:"state"`
	CreatedAt   string              `json:"created_at"`
	ResolvedAt  *string             `json:"resolved_at"`
	ResolvedBy  *string             `json:"resolved_by"`
	Note        *string             `json:"note"`
}

type listAlertsResponse struct {
	Items    []alertResponse `json:"items"`
	Total    int             `json:"total"`
	Page     int             `json:"page"`
	PageSize int             `json:"page_size"`
}

func toAlertResponse(a *detector.Alert) alertResponse {
	resp := alertResponse{
		ID:          a.ID,
		Tenant:      alertTenantResponse{ID: a.TenantID, Name: a.TenantName},
		IP:          nullableString(a.IP),
		WindowStart: a.WindowStart.UTC().Format(time.RFC3339),
		WindowEnd:   a.WindowEnd.UTC().Format(time.RFC3339),
		Source:      a.Source,
		Score:       a.Score,
		Features:    a.Features,
		Motives:     a.Motives,
		State:       a.State,
		CreatedAt:   a.CreatedAt.UTC().Format(time.RFC3339),
		// resolved_by es el correo del operador (null si sigue abierta o si
		// la cerró la credencial compartida X-Admin-Token).
		ResolvedBy: nullableString(a.ResolvedBy),
		Note:       nullableString(a.Note),
	}
	if a.ResolvedAt != nil {
		s := a.ResolvedAt.UTC().Format(time.RFC3339)
		resp.ResolvedAt = &s
	}
	return resp
}

// parseAlertDate lee una fecha AAAA-MM-DD (UTC).
func parseAlertDate(v string) (time.Time, bool) {
	t, err := time.Parse("2006-01-02", v)
	return t, err == nil
}

// List devuelve una página de alertas, la más reciente primero.
//
// Filtros: state (abierta | descartada | resuelta), tenant (UUID), from/to
// (AAAA-MM-DD, UTC; to incluye ese día completo) y page/page_size. Sin
// fechas, los últimos 7 días; el rango nunca puede pasar de 90 — las mismas
// reglas que GET /admin/security/events (authevents.ResolveEventRange). Igual
// que ahí, un filtro mal formado da 400 en vez de ignorarse: un filtro mal
// escrito que de pronto devuelve "todo" confunde más que un error. Las fechas
// se comparan contra el inicio de la ventana de la alerta, no contra cuándo
// se generó (ver detector.AlertFilter).
func (h *alertsHandlers) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	pageSize, _ := strconv.Atoi(q.Get("page_size"))

	var f detector.AlertFilter
	if v := q.Get("state"); v != "" {
		if !detector.IsValidState(v) {
			writeJSONError(w, http.StatusBadRequest, "state debe ser abierta, descartada o resuelta")
			return
		}
		f.State = v
	}
	if v := q.Get("tenant"); v != "" {
		if _, err := uuid.Parse(v); err != nil {
			writeJSONError(w, http.StatusBadRequest, "tenant debe ser un UUID válido")
			return
		}
		f.TenantID = v
	}

	var fromPtr, toPtr *time.Time
	if v := q.Get("from"); v != "" {
		t, ok := parseAlertDate(v)
		if !ok {
			writeJSONError(w, http.StatusBadRequest, "from debe tener el formato AAAA-MM-DD")
			return
		}
		fromPtr = &t
	}
	if v := q.Get("to"); v != "" {
		t, ok := parseAlertDate(v)
		if !ok {
			writeJSONError(w, http.StatusBadRequest, "to debe tener el formato AAAA-MM-DD")
			return
		}
		// El día de to entra completo: el límite es el comienzo del siguiente.
		t = t.AddDate(0, 0, 1)
		toPtr = &t
	}
	from, to, err := authevents.ResolveEventRange(fromPtr, toPtr, time.Now())
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	f.From, f.To = from, to

	alerts, total, effectivePage, effectivePageSize, err := h.repo.List(r.Context(), f, page, pageSize)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "no se pudieron listar las alertas")
		return
	}

	items := make([]alertResponse, 0, len(alerts))
	for _, a := range alerts {
		items = append(items, toAlertResponse(a))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(listAlertsResponse{Items: items, Total: total, Page: effectivePage, PageSize: effectivePageSize})
}

// alertIDParam lee y valida el {id} de la ruta; escribe el 400 si no es un UUID.
func alertIDParam(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := chi.URLParam(r, "id")
	if _, err := uuid.Parse(id); err != nil {
		writeJSONError(w, http.StatusBadRequest, "id debe ser un UUID válido")
		return "", false
	}
	return id, true
}

// Get devuelve una alerta por id.
func (h *alertsHandlers) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := alertIDParam(w, r)
	if !ok {
		return
	}
	a, err := h.repo.Get(r.Context(), id)
	if err != nil {
		writeAlertError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toAlertResponse(a))
}

// Dismiss marca la alerta como descartada (falsa alarma).
func (h *alertsHandlers) Dismiss(w http.ResponseWriter, r *http.Request) {
	h.closeAlert(w, r, detector.StateDescartada, audit.ActionAlertDismissed)
}

// Resolve marca la alerta como resuelta (era real y ya se atendió).
func (h *alertsHandlers) Resolve(w http.ResponseWriter, r *http.Request) {
	h.closeAlert(w, r, detector.StateResuelta, audit.ActionAlertResolved)
}

// closeAlert implementa dismiss y resolve: cuerpo opcional {"note": "..."},
// sin PIN de operador — cerrar una alerta no le quita acceso a nadie (la
// misma lógica que unban: lo que RESTAURA o solo marca no se confirma con
// PIN). Queda en el registro de actividad solo cuando salió bien.
func (h *alertsHandlers) closeAlert(w http.ResponseWriter, r *http.Request, newState, action string) {
	id, ok := alertIDParam(w, r)
	if !ok {
		return
	}
	note, ok := readAlertNote(w, r)
	if !ok {
		return
	}

	actor, _ := adminctx.Actor(r.Context())
	a, err := h.repo.Close(r.Context(), id, newState, actor, note)
	if err != nil {
		writeAlertError(w, err)
		return
	}

	role, _ := adminctx.Role(r.Context())
	h.audit.Log(r.Context(), audit.Entry{
		ActorEmail: actor, ActorRole: role, Action: action,
		TargetType: audit.TargetTypeAlert, TargetID: a.ID, TargetLabel: alertLabel(a),
		ActorIP: audit.RemoteIP(r),
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toAlertResponse(a))
}

// alertLabel es la descripción corta que queda en el registro de actividad,
// por ejemplo "regla · 2026-11-20 14:00 UTC".
func alertLabel(a *detector.Alert) string {
	return a.Source + " · " + a.WindowStart.UTC().Format("2006-01-02 15:04") + " UTC"
}

// readAlertNote lee el cuerpo opcional {"note": "..."}. Un cuerpo vacío es
// válido (sin nota); un JSON roto, o una nota demasiado larga, da 400.
func readAlertNote(w http.ResponseWriter, r *http.Request) (string, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxAlertBodyBytes))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "cuerpo de la solicitud inválido")
		return "", false
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return "", true
	}
	var in struct {
		Note *string `json:"note"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		writeJSONError(w, http.StatusBadRequest, "el cuerpo debe ser JSON, por ejemplo {\"note\": \"...\"}")
		return "", false
	}
	if in.Note == nil {
		return "", true
	}
	note := strings.TrimSpace(*in.Note)
	if utf8.RuneCountInString(note) > maxAlertNoteLength {
		writeJSONError(w, http.StatusBadRequest, "note no puede superar los "+strconv.Itoa(maxAlertNoteLength)+" caracteres")
		return "", false
	}
	return note, true
}

func writeAlertError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, detector.ErrAlertNotFound):
		writeJSONError(w, http.StatusNotFound, "alerta no encontrada")
	case errors.Is(err, detector.ErrAlertNotOpen):
		writeJSONError(w, http.StatusConflict, "la alerta ya no está abierta")
	default:
		writeJSONError(w, http.StatusInternalServerError, "no se pudo completar la operación")
	}
}
