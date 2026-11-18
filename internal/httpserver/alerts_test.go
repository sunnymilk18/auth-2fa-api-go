package httpserver_test

// Cubre /admin/alerts: roles, filtros y su validación (400), forma de la
// respuesta (el contrato con el panel), 404/409 y el registro de actividad.
// Las alertas se insertan a mano con detector.AlertRepository: aquí importa el
// contrato HTTP, no cómo se generan (eso lo cubre internal/detector).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp"

	"auth-2fa-api/internal/adminauth"
	"auth-2fa-api/internal/audit"
	"auth-2fa-api/internal/detector"
	"auth-2fa-api/internal/testutil"
)

type alertJSON struct {
	ID          string            `json:"id"`
	Tenant      map[string]string `json:"tenant"`
	IP          *string           `json:"ip"`
	WindowStart string            `json:"window_start"`
	WindowEnd   string            `json:"window_end"`
	Source      string            `json:"source"`
	Score       *float64          `json:"score"`
	Features    map[string]int    `json:"features"`
	Motives     []string          `json:"motives"`
	State       string            `json:"state"`
	CreatedAt   string            `json:"created_at"`
	ResolvedAt  *string           `json:"resolved_at"`
	ResolvedBy  *string           `json:"resolved_by"`
	Note        *string           `json:"note"`
}

type listAlertsJSON struct {
	Items    []alertJSON `json:"items"`
	Total    int         `json:"total"`
	Page     int         `json:"page"`
	PageSize int         `json:"page_size"`
}

func newOperator(t *testing.T, r http.Handler, adminAccounts *adminauth.Service, pool *pgxpool.Pool, role adminauth.Role) (*http.Cookie, string) {
	t.Helper()
	email := fmt.Sprintf("alerts-%s-%s@example.com", role, testutil.UniqueSuffix(t))
	account, otpauthURL, err := adminAccounts.CreateAccount(t.Context(), email, "correct-horse-battery", role)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM admin_accounts WHERE id = $1`, account.ID) })
	key, err := otp.NewKeyFromURL(otpauthURL)
	if err != nil {
		t.Fatalf("parsing otpauth url: %v", err)
	}
	return loginAsAdmin(t, r, email, "correct-horse-battery", key.Secret()), email
}

// seedAlert inserta una alerta y devuelve su id. Si el id de tenant va vacío,
// la alerta no tiene tenant (una alerta por IP que tocó a varios).
func seedAlert(t *testing.T, pool *pgxpool.Pool, a detector.NewAlert) string {
	t.Helper()
	repo := detector.NewAlertRepository(pool)
	if ok, err := repo.Insert(t.Context(), a); err != nil || !ok {
		t.Fatalf("insertando alerta de prueba: ok=%v err=%v", ok, err)
	}
	var id string
	if err := pool.QueryRow(t.Context(), `
		SELECT id FROM alerts
		WHERE window_start = $1 AND source = $2 AND COALESCE(tenant_id::text, '') = $3 AND COALESCE(host(ip), '') = $4`,
		a.WindowStart, a.Source, a.TenantID, a.IP).Scan(&id); err != nil {
		t.Fatalf("buscando la alerta insertada: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM alerts WHERE id = $1`, id) })
	return id
}

func alertsRequest(r http.Handler, method, path string, cookie *http.Cookie, rawBody string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader([]byte(rawBody)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Panel", "1")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func decodeList(t *testing.T, rec *httptest.ResponseRecorder) listAlertsJSON {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var out listAlertsJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decodificando: %v", err)
	}
	return out
}

func recentWindow(minutesAgo int) time.Time {
	return detector.WindowStartOf(time.Now().Add(-time.Duration(minutesAgo) * time.Minute))
}

func TestAlerts_AccesoPorRol(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)

	if rec := adminPanelRequest(r, http.MethodGet, "/admin/alerts", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("sin sesión: status = %d, want 401", rec.Code)
	}
	for _, route := range []string{
		"GET /admin/alerts/" + uuid.NewString(),
		"POST /admin/alerts/" + uuid.NewString() + "/dismiss",
		"POST /admin/alerts/" + uuid.NewString() + "/resolve",
	} {
		parts := strings.SplitN(route, " ", 2)
		if rec := adminPanelRequest(r, parts[0], parts[1], nil); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s sin sesión: status = %d, want 401", route, rec.Code)
		}
	}

	for _, role := range []adminauth.Role{adminauth.RoleAdmin, adminauth.RoleSuperAdmin} {
		cookie, _ := newOperator(t, r, adminAccounts, pool, role)
		if rec := adminPanelRequest(r, http.MethodGet, "/admin/alerts", cookie); rec.Code != http.StatusOK {
			t.Fatalf("rol %s: status = %d, body = %s, want 200", role, rec.Code, rec.Body.String())
		}
	}

	// La credencial compartida de scripts también entra (mismo middleware).
	req := httptest.NewRequest(http.MethodGet, "/admin/alerts", nil)
	req.Header.Set("X-Admin-Token", testAdminToken)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("con X-Admin-Token: status = %d, want 200", rec.Code)
	}
}

func TestAlerts_ContratoDeLaRespuesta(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)
	cookie, _ := newOperator(t, r, adminAccounts, pool, adminauth.RoleAdmin)
	client, _ := testutil.NewAPIClient(t, pool)

	score := 0.7132
	w1 := recentWindow(120)
	forestID := seedAlert(t, pool, detector.NewAlert{
		TenantID: client.ID, IP: "203.0.113.7", WindowStart: w1, WindowEnd: w1.Add(detector.WindowSize),
		Source: detector.SourceIsolationForest, Score: &score,
		Features: detector.Features{Fallos: 42, IPsDistintasConFallos: 1, CuentasDistintasAtacadas: 17, IntentosCuentaInexistente: 5},
		Motives:  []string{"17 cuentas distintas atacadas en 10 min (lo normal es 2)", "42 fallos en 10 min (lo normal es 3)"},
	})
	w2 := recentWindow(60)
	noTenantID := seedAlert(t, pool, detector.NewAlert{
		IP: "198.51.100.9", WindowStart: w2, WindowEnd: w2.Add(detector.WindowSize),
		Source: detector.SourceRegla, Features: detector.Features{Fallos: 30}, Motives: []string{"30 fallos en 10 min (umbral de la regla: 20)"},
	})

	// Detalle de la alerta del bosque: todos los campos del contrato.
	rec := adminPanelRequest(r, http.MethodGet, "/admin/alerts/"+forestID, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET detalle: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"id", "tenant", "ip", "window_start", "window_end", "source", "score", "features", "motives", "state", "created_at", "resolved_at", "resolved_by", "note"} {
		if _, ok := raw[k]; !ok {
			t.Fatalf("falta el campo %q en la respuesta: %s", k, rec.Body.String())
		}
	}
	var a alertJSON
	_ = json.Unmarshal(rec.Body.Bytes(), &a)
	if a.ID != forestID || a.Tenant["id"] != client.ID || a.Tenant["name"] != client.Name {
		t.Fatalf("tenant = %v, want id y nombre de %s", a.Tenant, client.Name)
	}
	if a.IP == nil || *a.IP != "203.0.113.7" || a.Source != "isolation_forest" || a.Score == nil || *a.Score != score || a.State != "abierta" {
		t.Fatalf("alerta = %+v", a)
	}
	if a.WindowStart != w1.UTC().Format(time.RFC3339) || a.WindowEnd != w1.Add(detector.WindowSize).UTC().Format(time.RFC3339) {
		t.Fatalf("ventana = %s – %s", a.WindowStart, a.WindowEnd)
	}
	wantFeatures := map[string]int{"fallos": 42, "correctos": 0, "ips_distintas_con_fallos": 1, "cuentas_distintas_atacadas": 17, "intentos_cuenta_inexistente": 5, "intentos_contra_senuelos": 0}
	if fmt.Sprint(a.Features) != fmt.Sprint(wantFeatures) {
		t.Fatalf("features = %v, want %v", a.Features, wantFeatures)
	}
	if len(a.Motives) != 2 || a.ResolvedAt != nil || a.ResolvedBy != nil || a.Note != nil {
		t.Fatalf("motivos/cierre = %+v", a)
	}
	if _, err := time.Parse(time.RFC3339, a.CreatedAt); err != nil {
		t.Fatalf("created_at = %q: %v", a.CreatedAt, err)
	}

	// Sin tenant: "tenant" llega como {} (no null, no ausente); sin puntaje, null.
	rec = adminPanelRequest(r, http.MethodGet, "/admin/alerts/"+noTenantID, cookie)
	if !strings.Contains(rec.Body.String(), `"tenant":{}`) {
		t.Fatalf("una alerta sin tenant debe traer \"tenant\":{} — %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"score":null`) {
		t.Fatalf("una alerta de regla debe traer \"score\":null — %s", rec.Body.String())
	}

	// Listado: la forma {items,total,page,page_size}, más reciente primero.
	list := decodeList(t, adminPanelRequest(r, http.MethodGet, "/admin/alerts?tenant="+client.ID, cookie))
	if list.Total != 1 || len(list.Items) != 1 || list.Page != 1 || list.PageSize != 50 {
		t.Fatalf("listado por tenant = %+v", list)
	}
	both := decodeList(t, adminPanelRequest(r, http.MethodGet, "/admin/alerts?page_size=100", cookie))
	var posNoTenant, posForest = -1, -1
	for i, it := range both.Items {
		switch it.ID {
		case noTenantID:
			posNoTenant = i
		case forestID:
			posForest = i
		}
	}
	if posNoTenant < 0 || posForest < 0 || posNoTenant > posForest {
		t.Fatalf("orden por fecha descendente roto: la de hace 60 min en %d, la de hace 120 en %d", posNoTenant, posForest)
	}
}

func TestAlerts_FiltrosYValidacion(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)
	cookie, _ := newOperator(t, r, adminAccounts, pool, adminauth.RoleAdmin)
	client, _ := testutil.NewAPIClient(t, pool)

	recent := recentWindow(30)
	old := time.Date(2019, 5, 1, 10, 0, 0, 0, time.UTC)
	seedAlert(t, pool, detector.NewAlert{TenantID: client.ID, WindowStart: recent, WindowEnd: recent.Add(detector.WindowSize), Source: detector.SourceRegla, Motives: []string{"m"}})
	seedAlert(t, pool, detector.NewAlert{TenantID: client.ID, WindowStart: old, WindowEnd: old.Add(detector.WindowSize), Source: detector.SourceRegla, Motives: []string{"m"}})
	older := old.Add(-detector.WindowSize)
	seedAlert(t, pool, detector.NewAlert{TenantID: client.ID, WindowStart: older, WindowEnd: older.Add(detector.WindowSize), Source: detector.SourceRegla, Motives: []string{"m"}})

	base := "/admin/alerts?tenant=" + client.ID

	// Sin fechas: últimos 7 días — la de 2019 queda fuera.
	if got := decodeList(t, adminPanelRequest(r, http.MethodGet, base, cookie)); got.Total != 1 || got.Items[0].WindowStart != recent.UTC().Format(time.RFC3339) {
		t.Fatalf("sin fechas debe traer solo la reciente: %+v", got)
	}
	// Con fechas: el día de "to" entra completo.
	if got := decodeList(t, adminPanelRequest(r, http.MethodGet, base+"&from=2019-05-01&to=2019-05-01", cookie)); got.Total != 2 || got.Items[0].WindowStart != old.Format(time.RFC3339) {
		t.Fatalf("from=to=2019-05-01 debe traer las de ese día: %+v", got)
	}
	if got := decodeList(t, adminPanelRequest(r, http.MethodGet, base+"&from=2019-05-02&to=2019-05-03", cookie)); got.Total != 0 {
		t.Fatalf("un rango sin alertas debe venir vacío: %+v", got)
	}
	// Estado.
	if got := decodeList(t, adminPanelRequest(r, http.MethodGet, base+"&state=abierta", cookie)); got.Total != 1 {
		t.Fatalf("state=abierta: %+v", got)
	}
	if got := decodeList(t, adminPanelRequest(r, http.MethodGet, base+"&state=resuelta", cookie)); got.Total != 0 || got.Items == nil {
		t.Fatalf("state=resuelta debe dar items [] (no null): %+v", got)
	}
	// Paginación.
	if got := decodeList(t, adminPanelRequest(r, http.MethodGet, base+"&from=2019-05-01&to=2019-05-02&page=2&page_size=1", cookie)); got.Total != 2 || len(got.Items) != 1 || got.Page != 2 || got.PageSize != 1 {
		t.Fatalf("página 2 de tamaño 1: %+v", got)
	}

	// Filtros mal formados: 400 con campo "error" en español.
	for name, query := range map[string]string{
		"estado desconocido":      "?state=otra",
		"tenant no UUID":          "?tenant=abc",
		"from mal formado":        "?from=2026-13-45",
		"from con formato RFC":    "?from=2026-11-20T00:00:00Z",
		"to mal formado":          "?to=ayer",
		"from posterior a to":     "?from=2026-11-20&to=2026-11-10",
		"rango de más de 90 días": "?from=2026-01-01&to=2026-11-01",
	} {
		rec := adminPanelRequest(r, http.MethodGet, "/admin/alerts"+query, cookie)
		var body struct {
			Error string `json:"error"`
		}
		if rec.Code != http.StatusBadRequest || json.Unmarshal(rec.Body.Bytes(), &body) != nil || body.Error == "" {
			t.Fatalf("%s: status = %d, body = %s, want 400 con campo error", name, rec.Code, rec.Body.String())
		}
	}
	// 90 días exactos sí se aceptan.
	if rec := adminPanelRequest(r, http.MethodGet, "/admin/alerts?from=2026-01-01&to=2026-03-31", cookie); rec.Code != http.StatusOK {
		t.Fatalf("90 días exactos: status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestAlerts_DetalleYNotFound(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)
	cookie, _ := newOperator(t, r, adminAccounts, pool, adminauth.RoleAdmin)

	if rec := adminPanelRequest(r, http.MethodGet, "/admin/alerts/"+uuid.NewString(), cookie); rec.Code != http.StatusNotFound {
		t.Fatalf("id inexistente: status = %d, want 404", rec.Code)
	}
	if rec := adminPanelRequest(r, http.MethodGet, "/admin/alerts/no-es-uuid", cookie); rec.Code != http.StatusBadRequest {
		t.Fatalf("id mal formado: status = %d, want 400", rec.Code)
	}
	for _, action := range []string{"dismiss", "resolve"} {
		if rec := adminPanelRequest(r, http.MethodPost, "/admin/alerts/"+uuid.NewString()+"/"+action, cookie); rec.Code != http.StatusNotFound {
			t.Fatalf("%s de un id inexistente: status = %d, want 404", action, rec.Code)
		}
	}
}

func TestAlerts_CerrarDejaEstadoNotaYRegistroDeActividad(t *testing.T) {
	r, adminAccounts, pool, _ := newTestRouterWithAdminPanel(t)
	operatorCookie, operatorEmail := newOperator(t, r, adminAccounts, pool, adminauth.RoleAdmin)
	superCookie, _ := newOperator(t, r, adminAccounts, pool, adminauth.RoleSuperAdmin)
	client, _ := testutil.NewAPIClient(t, pool)

	newAlert := func(minutesAgo int) string {
		w := recentWindow(minutesAgo)
		return seedAlert(t, pool, detector.NewAlert{TenantID: client.ID, WindowStart: w, WindowEnd: w.Add(detector.WindowSize), Source: detector.SourceRegla, Features: detector.Features{Fallos: 30}, Motives: []string{"m"}})
	}
	dismissID, resolveID, noNoteID, tokenID := newAlert(100), newAlert(90), newAlert(80), newAlert(70)

	// Descartar con nota — sin PIN (nada de X-Admin-Pin) y con rol admin.
	rec := alertsRequest(r, http.MethodPost, "/admin/alerts/"+dismissID+"/dismiss", operatorCookie, `{"note":"  falsa alarma de una oficina  "}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("dismiss: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var a alertJSON
	_ = json.Unmarshal(rec.Body.Bytes(), &a)
	if a.State != "descartada" || a.Note == nil || *a.Note != "falsa alarma de una oficina" || a.ResolvedAt == nil || a.ResolvedBy == nil || *a.ResolvedBy != operatorEmail {
		t.Fatalf("alerta descartada = %+v (note=%v by=%v)", a, a.Note, a.ResolvedBy)
	}

	// Resolver con nota.
	if rec := alertsRequest(r, http.MethodPost, "/admin/alerts/"+resolveID+"/resolve", operatorCookie, `{"note":"se bloqueó la IP"}`); rec.Code != http.StatusOK {
		t.Fatalf("resolve: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	// Sin cuerpo y con cuerpo {} son válidos: sin nota.
	if rec := alertsRequest(r, http.MethodPost, "/admin/alerts/"+noNoteID+"/resolve", operatorCookie, ``); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"note":null`) {
		t.Fatalf("resolve sin cuerpo: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec := alertsRequest(r, http.MethodPost, "/admin/alerts/"+tokenID+"/dismiss", nil, `{}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("sin sesión: status = %d, want 401", rec.Code)
	}

	// Una alerta que ya no está abierta responde 409, y el estado no cambia.
	for _, action := range []string{"dismiss", "resolve"} {
		rec := alertsRequest(r, http.MethodPost, "/admin/alerts/"+dismissID+"/"+action, operatorCookie, `{"note":"otra vez"}`)
		if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), `"error"`) {
			t.Fatalf("%s sobre una alerta cerrada: status = %d, body = %s, want 409", action, rec.Code, rec.Body.String())
		}
	}
	got := adminPanelRequest(r, http.MethodGet, "/admin/alerts/"+dismissID, operatorCookie)
	_ = json.Unmarshal(got.Body.Bytes(), &a)
	if a.State != "descartada" || a.Note == nil || *a.Note != "falsa alarma de una oficina" {
		t.Fatalf("el 409 modificó la alerta: %+v", a)
	}

	// Cuerpo inválido: 400, y la alerta sigue abierta.
	if rec := alertsRequest(r, http.MethodPost, "/admin/alerts/"+tokenID+"/resolve", operatorCookie, `{no es json`); rec.Code != http.StatusBadRequest {
		t.Fatalf("JSON roto: status = %d, want 400", rec.Code)
	}
	tooLong := `{"note":"` + strings.Repeat("a", 1001) + `"}`
	if rec := alertsRequest(r, http.MethodPost, "/admin/alerts/"+tokenID+"/resolve", operatorCookie, tooLong); rec.Code != http.StatusBadRequest {
		t.Fatalf("nota de 1001 caracteres: status = %d, want 400", rec.Code)
	}
	if got := decodeList(t, adminPanelRequest(r, http.MethodGet, "/admin/alerts?tenant="+client.ID+"&state=abierta", operatorCookie)); got.Total != 1 || got.Items[0].ID != tokenID {
		t.Fatalf("tras los 400 debe quedar abierta solo la última: %+v", got)
	}

	// Con la credencial compartida: se cierra, pero resolved_by queda null.
	req := httptest.NewRequest(http.MethodPost, "/admin/alerts/"+tokenID+"/resolve", strings.NewReader(`{"note":"script"}`))
	req.Header.Set("X-Admin-Token", testAdminToken)
	tokenRec := httptest.NewRecorder()
	r.ServeHTTP(tokenRec, req)
	if tokenRec.Code != http.StatusOK || !strings.Contains(tokenRec.Body.String(), `"resolved_by":null`) {
		t.Fatalf("resolve con X-Admin-Token: status = %d, body = %s", tokenRec.Code, tokenRec.Body.String())
	}

	// Registro de actividad: una entrada por cierre exitoso, con los códigos
	// del contrato, y ninguna por los 400/404/409.
	entries := getAudit(t, r, superCookie, "?page_size=100").Entries
	for id, action := range map[string]string{dismissID: "alert_dismissed", resolveID: "alert_resolved", noNoteID: "alert_resolved", tokenID: "alert_resolved"} {
		e := findEntry(entries, action, id)
		if e == nil {
			t.Fatalf("falta la entrada %s para la alerta %s", action, id)
		}
		if e.TargetType != audit.TargetTypeAlert || !strings.HasPrefix(e.TargetLabel, "regla · ") {
			t.Fatalf("entrada %s = %+v", action, e)
		}
	}
	if e := findEntry(entries, "alert_dismissed", dismissID); e.ActorEmail != operatorEmail || e.ActorRole != string(adminauth.RoleAdmin) {
		t.Fatalf("actor de alert_dismissed = %q/%q", e.ActorEmail, e.ActorRole)
	}
	if e := findEntry(entries, "alert_resolved", tokenID); e.ActorEmail != "token" {
		t.Fatalf("actor del cierre con script = %q, want token", e.ActorEmail)
	}
	n := 0
	for _, e := range entries {
		if e.TargetID == dismissID {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("la alerta descartada tiene %d entradas de actividad, want exactamente 1 (los 409 no registran)", n)
	}
}

// GET /admin/users: las cuentas señuelo quedan fuera del listado normal y solo
// salen con include_decoys=true, marcadas con is_decoy.
func TestAdminListUsers_DecoysOnlyWithIncludeDecoys(t *testing.T) {
	r := newTestRouterWithAdmin(t, testAdminToken)
	pool := testutil.PostgresPool(t)
	client, _ := testutil.NewAPIClient(t, pool)
	decoy := testutil.NewDecoyUser(t, pool, client.ID, "correcthorsebattery")
	real := testutil.NewUser(t, pool, client.ID, "correcthorsebattery")

	list := func(query string) map[string]bool {
		rec := adminRequest(r, http.MethodGet, "/admin/users/?page_size=100&q=user-"+query, testAdminToken, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Users []struct {
				ID      string `json:"id"`
				IsDecoy bool   `json:"is_decoy"`
			} `json:"users"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, u := range resp.Users {
			out[u.ID] = u.IsDecoy
		}
		return out
	}

	// q acota el listado a los usuarios de prueba (todos se llaman "user-…").
	normal := list("")
	if _, found := normal[decoy.ID]; found {
		t.Fatal("GET /admin/users sin include_decoys incluyó un señuelo")
	}
	if isDecoy, found := normal[real.ID]; !found || isDecoy {
		t.Fatalf("GET /admin/users perdió al usuario real o lo marcó señuelo: found=%v isDecoy=%v", found, isDecoy)
	}

	with := list("&include_decoys=true")
	if isDecoy, found := with[decoy.ID]; !found || !isDecoy {
		t.Fatalf("include_decoys=true no trajo el señuelo marcado: found=%v isDecoy=%v", found, isDecoy)
	}
}
