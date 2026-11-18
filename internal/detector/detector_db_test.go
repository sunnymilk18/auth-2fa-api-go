package detector

// Pruebas contra Postgres local (se omiten si no hay uno alcanzable, igual
// que el resto del proyecto — ver testutil.PostgresPool). Cada prueba crea su
// propio tenant y sus propias IPs, y sus ventanas caen en 2019 para no
// mezclarse con el tráfico "de hoy" que otras pruebas escriben en paralelo.

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"auth-2fa-api/internal/authevents"
	"auth-2fa-api/internal/testutil"
)

var dbBase = time.Date(2019, 5, 1, 10, 0, 0, 0, time.UTC)

// testIP devuelve una IP de documentación (198.18.0.0/15) distinta por prueba.
func testIP(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("198.18.%d.%d", rand.IntN(250)+1, rand.IntN(250)+1)
}

func insertAuthEvent(t *testing.T, pool *pgxpool.Pool, tenantID, result, emailHash, ip string, decoy bool, at time.Time) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO auth_events (api_client_id, kind, method, result, email_hash, ip, user_agent, is_decoy, created_at)
		VALUES (NULLIF($1, '')::uuid, 'login', 'password', $2, NULLIF($3, ''), $4::inet, '', $5, $6)`,
		tenantID, result, emailHash, ip, decoy, at)
	if err != nil {
		t.Fatalf("insertando evento de prueba: %v", err)
	}
}

// cleanupTenant borra las alertas y los eventos del tenant al terminar,
// antes de que NewAPIClient borre al tenant mismo (los cleanups van en orden
// inverso al de registro).
func cleanupTenant(t *testing.T, pool *pgxpool.Pool, tenantID, ip string) {
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = pool.Exec(ctx, `DELETE FROM alerts WHERE tenant_id = $1 OR ip = $2::inet`, tenantID, ip)
		_, _ = pool.Exec(ctx, `DELETE FROM auth_events WHERE api_client_id = $1 OR ip = $2::inet`, tenantID, ip)
	})
}

func alertsFor(t *testing.T, repo *AlertRepository, tenantID string) []*Alert {
	t.Helper()
	alerts, _, _, _, err := repo.List(context.Background(), AlertFilter{TenantID: tenantID, From: dbBase.Add(-24 * time.Hour), To: dbBase.Add(24 * time.Hour)}, 1, 100)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	return alerts
}

func TestAlertRepository_InsertDedupe(t *testing.T) {
	pool := testutil.PostgresPool(t)
	client, _ := testutil.NewAPIClient(t, pool)
	ip := testIP(t)
	cleanupTenant(t, pool, client.ID, ip)
	repo := NewAlertRepository(pool)
	ctx := context.Background()

	base := NewAlert{TenantID: client.ID, WindowStart: dbBase, WindowEnd: dbBase.Add(WindowSize), Source: SourceRegla, Features: Features{Fallos: 30}, Motives: []string{"x"}}
	if ok, err := repo.Insert(ctx, base); err != nil || !ok {
		t.Fatalf("primera inserción: ok=%v err=%v", ok, err)
	}
	if ok, err := repo.Insert(ctx, base); err != nil || ok {
		t.Fatalf("misma ventana+clave+fuente debe ser duplicado: ok=%v err=%v", ok, err)
	}
	other := base
	other.Source = SourceSenuelo
	if ok, err := repo.Insert(ctx, other); err != nil || !ok {
		t.Fatalf("otra fuente en la misma ventana y clave sí debe entrar: ok=%v err=%v", ok, err)
	}
	next := base
	next.WindowStart, next.WindowEnd = dbBase.Add(WindowSize), dbBase.Add(2*WindowSize)
	if ok, err := repo.Insert(ctx, next); err != nil || !ok {
		t.Fatalf("otra ventana sí debe entrar: ok=%v err=%v", ok, err)
	}

	// Alerta por IP sin tenant (NULL): el NULL tampoco debe permitir duplicados.
	ipAlert := NewAlert{IP: ip, WindowStart: dbBase, WindowEnd: dbBase.Add(WindowSize), Source: SourceRegla, Features: Features{Fallos: 30}, Motives: []string{"x"}}
	if ok, err := repo.Insert(ctx, ipAlert); err != nil || !ok {
		t.Fatalf("alerta por IP: ok=%v err=%v", ok, err)
	}
	if ok, err := repo.Insert(ctx, ipAlert); err != nil || ok {
		t.Fatalf("la alerta por IP con tenant NULL debe deduplicarse: ok=%v err=%v", ok, err)
	}
}

func TestAlertRepository_ListFiltrosOrdenYPaginas(t *testing.T) {
	pool := testutil.PostgresPool(t)
	client, _ := testutil.NewAPIClient(t, pool)
	ip := testIP(t)
	cleanupTenant(t, pool, client.ID, ip)
	repo := NewAlertRepository(pool)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		ws := dbBase.Add(time.Duration(i) * WindowSize)
		score := 0.7
		if _, err := repo.Insert(ctx, NewAlert{TenantID: client.ID, WindowStart: ws, WindowEnd: ws.Add(WindowSize), Source: SourceIsolationForest, Score: &score, Features: Features{Fallos: i}, Motives: []string{"m"}}); err != nil {
			t.Fatal(err)
		}
	}

	f := AlertFilter{TenantID: client.ID, From: dbBase.Add(-time.Hour), To: dbBase.Add(24 * time.Hour)}
	alerts, total, page, size, err := repo.List(ctx, f, 1, 2)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 5 || len(alerts) != 2 || page != 1 || size != 2 {
		t.Fatalf("total=%d len=%d page=%d size=%d, want 5/2/1/2", total, len(alerts), page, size)
	}
	if !alerts[0].WindowStart.After(alerts[1].WindowStart) {
		t.Fatalf("el orden debe ser por fecha descendente: %v luego %v", alerts[0].WindowStart, alerts[1].WindowStart)
	}
	if alerts[0].Score == nil || *alerts[0].Score != 0.7 || alerts[0].TenantName == "" || alerts[0].IP != "" {
		t.Fatalf("campos de la alerta mal leídos: %+v", alerts[0])
	}

	// Página fuera de rango: vacía, y el total no se pierde.
	alerts, _, _, _, _ = repo.List(ctx, f, 9, 2)
	if len(alerts) != 0 {
		t.Fatalf("página 9 debe venir vacía, trae %d", len(alerts))
	}
	// page_size se acota a 100, y valores raros caen a los valores por defecto.
	if _, _, p, s, _ := repo.List(ctx, f, 0, 5000); p != 1 || s != 100 {
		t.Fatalf("page/page_size sin acotar: %d/%d", p, s)
	}
	if _, _, _, s, _ := repo.List(ctx, f, 1, 0); s != 50 {
		t.Fatalf("page_size 0 debe caer a 50, dio %d", s)
	}

	// Rango de fechas: To es exclusivo.
	f.From, f.To = dbBase, dbBase.Add(2*WindowSize)
	if _, total, _, _, _ := repo.List(ctx, f, 1, 50); total != 2 {
		t.Fatalf("rango [W0, W2) debe traer 2 alertas, trae %d", total)
	}
	// Estado.
	f.From, f.To = dbBase.Add(-time.Hour), dbBase.Add(24*time.Hour)
	f.State = StateResuelta
	if _, total, _, _, _ := repo.List(ctx, f, 1, 50); total != 0 {
		t.Fatalf("no hay alertas resueltas, trae %d", total)
	}
	// Otro tenant: nada.
	f.State, f.TenantID = "", uuid.NewString()
	if _, total, _, _, _ := repo.List(ctx, f, 1, 50); total != 0 {
		t.Fatalf("otro tenant no debe ver estas alertas, ve %d", total)
	}
}

func TestAlertRepository_Close(t *testing.T) {
	pool := testutil.PostgresPool(t)
	client, _ := testutil.NewAPIClient(t, pool)
	ip := testIP(t)
	cleanupTenant(t, pool, client.ID, ip)
	repo := NewAlertRepository(pool)
	ctx := context.Background()

	email := "alert-op-" + testutil.UniqueSuffix(t) + "@example.com"
	var accountID string
	if err := pool.QueryRow(ctx, `INSERT INTO admin_accounts (email, password_hash, totp_secret_enc, role) VALUES ($1, 'x', 'x', 'admin') RETURNING id`, email).Scan(&accountID); err != nil {
		t.Fatalf("creando cuenta de operador de prueba: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM admin_accounts WHERE id = $1`, accountID) })

	newOne := func(ws time.Time) string {
		if _, err := repo.Insert(ctx, NewAlert{TenantID: client.ID, WindowStart: ws, WindowEnd: ws.Add(WindowSize), Source: SourceRegla, Features: Features{Fallos: 50}, Motives: []string{"m"}}); err != nil {
			t.Fatal(err)
		}
		for _, a := range alertsFor(t, repo, client.ID) {
			if a.WindowStart.Equal(ws) {
				return a.ID
			}
		}
		t.Fatal("no se encontró la alerta recién creada")
		return ""
	}

	id := newOne(dbBase)
	a, err := repo.Close(ctx, id, StateResuelta, email, "era real")
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	if a.State != StateResuelta || a.ResolvedAt == nil || a.ResolvedBy != email || a.Note != "era real" {
		t.Fatalf("alerta cerrada = %+v, want resuelta con operador %q y su nota", a, email)
	}
	if _, err := repo.Close(ctx, id, StateDescartada, email, ""); !errors.Is(err, ErrAlertNotOpen) {
		t.Fatalf("cerrar una alerta ya cerrada: err = %v, want ErrAlertNotOpen", err)
	}
	if got, _ := repo.Get(ctx, id); got.State != StateResuelta {
		t.Fatalf("el segundo intento cambió el estado a %q", got.State)
	}
	if _, err := repo.Close(ctx, uuid.NewString(), StateResuelta, email, ""); !errors.Is(err, ErrAlertNotFound) {
		t.Fatalf("id inexistente: err = %v, want ErrAlertNotFound", err)
	}

	// Credencial compartida (X-Admin-Token): sin cuenta individual, resolved_by queda vacío.
	id2 := newOne(dbBase.Add(WindowSize))
	a, err = repo.Close(ctx, id2, StateDescartada, "token", "")
	if err != nil {
		t.Fatalf("Close con token: %v", err)
	}
	if a.State != StateDescartada || a.ResolvedBy != "" || a.Note != "" || a.ResolvedAt == nil {
		t.Fatalf("alerta cerrada por token = %+v", a)
	}
}

// syntheticModel calibra el umbral con un cuantil bajo (0,9) a propósito: el
// bosque no puntúa mucho más alto lo que está fuera del rango de entrenamiento
// que a sus valores más extremos, y estos datos sintéticos ya los tienen.
func syntheticModel(t *testing.T) *Model {
	t.Helper()
	data := syntheticNormal(600, rand.New(rand.NewPCG(31, 32)))
	m, err := TrainModel(append(unitsFrom(KeyTenant, data), unitsFrom(KeyIP, data)...), TrainParams{Trees: 50, SampleSize: 128, Seed: 5, ThresholdQuantile: 0.9})
	if err != nil {
		t.Fatalf("TrainModel: %v", err)
	}
	return m
}

func TestDetectorRun_ReglasYSenuelosSinModelo(t *testing.T) {
	pool := testutil.PostgresPool(t)
	client, _ := testutil.NewAPIClient(t, pool)
	ip := testIP(t)
	cleanupTenant(t, pool, client.ID, ip)

	// 25 fallos de una IP contra 25 cuentas inexistentes, más un intento contra un señuelo.
	for i := 0; i < 25; i++ {
		insertAuthEvent(t, pool, client.ID, authevents.ResultBadCredentials, fmt.Sprintf("h-%s-%d", client.ID[:8], i), ip, false, dbBase.Add(time.Duration(i)*20*time.Second))
	}
	insertAuthEvent(t, pool, client.ID, authevents.ResultBadCredentials, "", ip, true, dbBase.Add(9*time.Minute))
	// Y tráfico normal en otra ventana: no debe alertar.
	insertAuthEvent(t, pool, client.ID, authevents.ResultBadCredentials, "h-normal", testIP(t), false, dbBase.Add(3*WindowSize))

	d := New(pool, DefaultRules(), nil, 0, nil)
	if d.HasModel() {
		t.Fatal("sin modelo, HasModel debe ser false")
	}
	created, err := d.Run(context.Background(), dbBase.Add(-time.Hour), dbBase.Add(time.Hour))
	if err != nil {
		t.Fatalf("Run sin modelo: %v", err)
	}
	if created != 4 {
		t.Fatalf("alertas creadas = %d, want 4 (regla y señuelo, por tenant y por IP)", created)
	}

	bySource := map[string]int{}
	var ruleTenantAlert *Alert
	repo := NewAlertRepository(pool)
	for _, a := range alertsFor(t, repo, client.ID) {
		bySource[a.Source]++
		if a.Source == SourceRegla && a.IP == "" {
			ruleTenantAlert = a
		}
		if a.Source == SourceIsolationForest {
			t.Fatal("sin modelo no puede haber alertas del bosque")
		}
		if a.Score != nil {
			t.Fatalf("solo el bosque lleva puntaje: %+v", a)
		}
		if !a.WindowStart.Equal(dbBase) || !a.WindowEnd.Equal(dbBase.Add(WindowSize)) {
			t.Fatalf("ventana = %v–%v", a.WindowStart, a.WindowEnd)
		}
	}
	if bySource[SourceRegla] != 2 || bySource[SourceSenuelo] != 2 {
		t.Fatalf("alertas por fuente = %v", bySource)
	}
	if ruleTenantAlert == nil || ruleTenantAlert.Features.Fallos != 26 || ruleTenantAlert.Features.IntentosContraSenuelos != 1 || len(ruleTenantAlert.Motives) < 2 {
		t.Fatalf("alerta de regla por tenant = %+v", ruleTenantAlert)
	}

	// Volver a recorrer las mismas ventanas no duplica nada.
	created, err = d.Run(context.Background(), dbBase.Add(-time.Hour), dbBase.Add(time.Hour))
	if err != nil || created != 0 {
		t.Fatalf("segunda pasada: creadas=%d err=%v, want 0", created, err)
	}
}

func TestDetectorRun_BosqueAlertaLoQueLasReglasNoVen(t *testing.T) {
	pool := testutil.PostgresPool(t)
	client, _ := testutil.NewAPIClient(t, pool)
	ip := testIP(t)
	cleanupTenant(t, pool, client.ID, ip)

	// 19 fallos contra 9 cuentas inexistentes, uno bajo cada umbral de las
	// reglas (20 fallos, 10 cuentas, 10 inexistentes), pero muy lejos de un
	// tráfico normal de 0 a 5 fallos y ninguna cuenta inexistente.
	for i := 0; i < 9; i++ {
		insertAuthEvent(t, pool, client.ID, authevents.ResultBadCredentials, fmt.Sprintf("h-%s-%d", client.ID[:8], i), ip, false, dbBase.Add(time.Duration(i)*30*time.Second))
	}
	for i := 0; i < 10; i++ {
		insertAuthEvent(t, pool, client.ID, authevents.ResultBadTOTP, fmt.Sprintf("h-%s-%d", client.ID[:8], i%9), ip, false, dbBase.Add(time.Duration(5*60+i*20)*time.Second))
	}

	d := New(pool, DefaultRules(), syntheticModel(t), 0, nil)
	if !d.HasModel() {
		t.Fatal("con modelo, HasModel debe ser true")
	}
	if _, err := d.Run(context.Background(), dbBase.Add(-time.Hour), dbBase.Add(time.Hour)); err != nil {
		t.Fatalf("Run con modelo: %v", err)
	}

	var forest []*Alert
	for _, a := range alertsFor(t, NewAlertRepository(pool), client.ID) {
		if a.Source == SourceRegla {
			t.Fatalf("19 fallos bajo los umbrales no deberían disparar las reglas: %+v", a)
		}
		if a.Source == SourceIsolationForest {
			forest = append(forest, a)
		}
	}
	if len(forest) == 0 {
		t.Fatal("el bosque debió alertar")
	}
	for _, a := range forest {
		key := KeyIP
		if a.IP == "" {
			key = KeyTenant
		}
		if thr := d.IFThreshold(key); a.Score == nil || *a.Score < thr || *a.Score >= 1 {
			t.Fatalf("puntaje = %v, want en [%.3f, 1)", a.Score, thr)
		}
		if len(a.Motives) == 0 || a.Motives[0] == "" {
			t.Fatalf("la alerta del bosque debe explicarse: %+v", a)
		}
	}
	sort.Slice(forest, func(i, j int) bool { return forest[i].IP < forest[j].IP })
	t.Logf("motivos del bosque: %v", forest[0].Motives)
}

func TestDetectorRun_NoEvaluaLaVentanaEnCurso(t *testing.T) {
	pool := testutil.PostgresPool(t)
	client, _ := testutil.NewAPIClient(t, pool)
	ip := testIP(t)
	cleanupTenant(t, pool, client.ID, ip)

	for i := 0; i < 25; i++ {
		insertAuthEvent(t, pool, client.ID, authevents.ResultBadCredentials, fmt.Sprintf("h-%d", i), ip, false, dbBase.Add(time.Duration(i)*10*time.Second))
	}
	d := New(pool, DefaultRules(), nil, 0, nil)
	// "ahora" cae dentro de la ventana de los eventos: esa ventana aún no se completó.
	created, err := d.Run(context.Background(), dbBase.Add(-time.Hour), dbBase.Add(5*time.Minute))
	if err != nil || created != 0 {
		t.Fatalf("ventana en curso: creadas=%d err=%v, want 0", created, err)
	}
	created, err = d.Run(context.Background(), dbBase.Add(-time.Hour), dbBase.Add(10*time.Minute))
	if err != nil || created == 0 {
		t.Fatalf("ventana ya completa: creadas=%d err=%v, want > 0", created, err)
	}
}

// --- migración 0021: aplica y revierte limpio ---

func TestMigration0021_AplicaYRevierte(t *testing.T) {
	pool := testutil.PostgresPool(t)
	ctx := context.Background()

	// Una base de pruebas aparte: revertir una migración toma bloqueos fuertes
	// sobre users, y eso no se hace en la base que otras pruebas usan en paralelo.
	scratch := "auth2fa_mig_" + testutil.UniqueSuffix(t)
	if _, err := pool.Exec(ctx, "CREATE DATABASE "+scratch); err != nil {
		t.Skipf("no se pudo crear una base de pruebas aparte: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+scratch+" WITH (FORCE)") })

	cfg := pool.Config().ConnConfig.Copy()
	cfg.Database = scratch
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("conectando a la base de pruebas: %v", err)
	}
	defer conn.Close(ctx)

	migrations, err := filepath.Glob(filepath.Join("..", "..", "migrations", "*.sql"))
	if err != nil || len(migrations) == 0 {
		t.Fatalf("no hay migraciones: %v", err)
	}
	sort.Strings(migrations)
	applyUp := func() {
		t.Helper()
		for _, f := range migrations {
			sql, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Exec(ctx, string(sql)); err != nil {
				t.Fatalf("aplicando %s: %v", f, err)
			}
		}
	}
	state := func() (alertsTable, decoyColumn bool) {
		t.Helper()
		if err := conn.QueryRow(ctx, `SELECT to_regclass('public.alerts') IS NOT NULL`).Scan(&alertsTable); err != nil {
			t.Fatal(err)
		}
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'is_decoy')`).Scan(&decoyColumn); err != nil {
			t.Fatal(err)
		}
		return
	}

	applyUp()
	if a, d := state(); !a || !d {
		t.Fatalf("tras aplicar: tabla alerts=%v, columna users.is_decoy=%v, want ambas", a, d)
	}
	applyUp() // idempotente: aplicar de nuevo no falla

	down, err := os.ReadFile(filepath.Join("..", "..", "migrations", "down", "0021_alerts_decoys.down.sql"))
	if err != nil {
		t.Fatalf("leyendo la reversa: %v", err)
	}
	for i := 0; i < 2; i++ { // y la reversa también se puede repetir
		if _, err := conn.Exec(ctx, string(down)); err != nil {
			t.Fatalf("revirtiendo (pasada %d): %v", i+1, err)
		}
	}
	if a, d := state(); a || d {
		t.Fatalf("tras revertir: tabla alerts=%v, columna users.is_decoy=%v, want ninguna", a, d)
	}
	// auth_events.is_decoy es de 0020 y la reversa no lo toca.
	var stillThere bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'auth_events' AND column_name = 'is_decoy')`).Scan(&stillThere); err != nil || !stillThere {
		t.Fatalf("auth_events.is_decoy debe seguir existiendo: %v %v", stillThere, err)
	}

	applyUp()
	if a, d := state(); !a || !d {
		t.Fatalf("tras volver a aplicar: tabla alerts=%v, columna users.is_decoy=%v", a, d)
	}
}
