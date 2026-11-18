package alertseed_test

// Prueba contra Postgres local (se omite si no hay uno, como el resto del
// proyecto). Usa su propio tenant, con un nombre único que sirve de prefijo, y
// ventanas de 2019: no toca la simulación cargada ni el tráfico de otras pruebas.

import (
	"context"
	"fmt"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"auth-2fa-api/internal/alertseed"
	"auth-2fa-api/internal/apiclient"
	"auth-2fa-api/internal/detector"
	"auth-2fa-api/internal/testutil"
)

var base = time.Date(2019, 5, 1, 10, 0, 0, 0, time.UTC)

func insert(t *testing.T, pool *pgxpool.Pool, tenant, hash, ip string, decoy bool, at time.Time) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO auth_events (api_client_id, kind, method, result, email_hash, ip, user_agent, is_decoy, created_at)
		VALUES ($1::uuid, 'login', 'password', 'bad_credentials', NULLIF($2, ''), $3::inet, '', $4, $5)`,
		tenant, hash, ip, decoy, at)
	if err != nil {
		t.Fatalf("insertando evento de prueba: %v", err)
	}
}

type fixture struct {
	pool     *pgxpool.Pool
	opts     alertseed.Options
	tenantID string
}

func setup(t *testing.T) *fixture {
	t.Helper()
	pool := testutil.PostgresPool(t)
	ctx := context.Background()

	name := "alertseed-" + testutil.UniqueSuffix(t)
	client, _, err := apiclient.NewService(apiclient.NewRepository(pool)).Create(ctx, name)
	if err != nil {
		t.Fatalf("creando el tenant: %v", err)
	}
	ip := fmt.Sprintf("198.18.%d.%d", rand.IntN(250)+1, rand.IntN(250)+1)

	// Cinco ventanas, cada una con 22 fallos desde una IP contra cuentas
	// inexistentes y un intento contra un señuelo: alertas de regla y de
	// señuelo, por tenant y por IP (20 en total, 10 de cada fuente).
	for w := 0; w < 5; w++ {
		start := base.Add(time.Duration(w) * detector.WindowSize)
		for i := 0; i < 22; i++ {
			insert(t, pool, client.ID, fmt.Sprintf("h-%d-%d", w, i), ip, false, start.Add(time.Duration(i)*20*time.Second))
		}
		insert(t, pool, client.ID, "", ip, true, start.Add(9*time.Minute))
	}

	router, err := alertseed.NewRouter(pool)
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	t.Cleanup(func() {
		router.Close()
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM admin_audit_log WHERE target_type = 'alert' AND target_id IN (SELECT id::text FROM alerts WHERE tenant_id = $1)`, client.ID)
		_, _ = pool.Exec(bg, `DELETE FROM alerts WHERE tenant_id = $1 OR ip = $2::inet`, client.ID, ip)
		_, _ = pool.Exec(bg, `DELETE FROM auth_events WHERE api_client_id = $1`, client.ID)
		_, _ = pool.Exec(bg, `DELETE FROM api_clients WHERE id = $1`, client.ID)
	})

	d := detector.New(pool, detector.DefaultRules(), nil, 0, nil)
	d.TenantNamePrefix = name
	return &fixture{
		pool: pool, tenantID: client.ID,
		opts: alertseed.Options{
			Detector: d, Router: router, From: base.Add(-time.Hour), To: base.Add(time.Hour),
			TenantNamePrefix: name, PerSource: 2,
		},
	}
}

func auditRows(t *testing.T, f *fixture, action string) int {
	t.Helper()
	var n int
	err := f.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM admin_audit_log
		WHERE action = $1 AND target_id IN (SELECT id::text FROM alerts WHERE tenant_id = $2)`, action, f.tenantID).Scan(&n)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestSeed_AlertasDelDetectorYCierresPorLasRutas(t *testing.T) {
	f := setup(t)
	sum, err := alertseed.Seed(context.Background(), f.pool, f.opts)
	if err != nil {
		t.Fatalf("Seed: %v", err)
	}

	if sum.Created != 20 {
		t.Fatalf("alertas creadas por el detector = %d, want 20", sum.Created)
	}
	// Dos fuentes con datos (no hay modelo, así que ninguna del bosque): cada
	// una con 2 descartadas, 2 resueltas y el resto abiertas.
	for _, source := range []string{detector.SourceRegla, detector.SourceSenuelo} {
		c := sum.Counts[source]
		if c[detector.StateDescartada] != 2 || c[detector.StateResuelta] != 2 || c[detector.StateAbierta] != 6 {
			t.Fatalf("%s: %v, want 6 abiertas, 2 descartadas y 2 resueltas", source, c)
		}
	}
	if total := sum.Counts[detector.SourceIsolationForest]; total[detector.StateAbierta]+total[detector.StateDescartada]+total[detector.StateResuelta] != 0 {
		t.Fatalf("sin modelo no puede haber alertas del bosque: %v", total)
	}
	if sum.Closed != 8 {
		t.Fatalf("cierres = %d, want 8", sum.Closed)
	}

	// Pasaron por las rutas de la API: quedan en el registro de actividad con
	// los códigos del contrato, y las cerradas tienen su nota.
	if got := auditRows(t, f, "alert_dismissed"); got != 4 {
		t.Fatalf("entradas alert_dismissed = %d, want 4", got)
	}
	if got := auditRows(t, f, "alert_resolved"); got != 4 {
		t.Fatalf("entradas alert_resolved = %d, want 4", got)
	}
	var withNote int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM alerts WHERE tenant_id = $1 AND state <> 'abierta' AND note LIKE 'Simulado%'`, f.tenantID).Scan(&withNote); err != nil || withNote != 8 {
		t.Fatalf("alertas cerradas con nota = %d (%v), want 8", withNote, err)
	}
}

// Repetirlo no duplica alertas ni cierra más: deja exactamente lo mismo.
func TestSeed_EsRepetible(t *testing.T) {
	f := setup(t)
	first, err := alertseed.Seed(context.Background(), f.pool, f.opts)
	if err != nil {
		t.Fatalf("primera pasada: %v", err)
	}
	second, err := alertseed.Seed(context.Background(), f.pool, f.opts)
	if err != nil {
		t.Fatalf("segunda pasada: %v", err)
	}
	if second.Created != 0 || second.Closed != 0 {
		t.Fatalf("la segunda pasada creó %d y cerró %d alertas, want 0 y 0", second.Created, second.Closed)
	}
	if fmt.Sprint(first.Counts) != fmt.Sprint(second.Counts) {
		t.Fatalf("los conteos cambiaron entre pasadas:\n%v\n%v", first.Counts, second.Counts)
	}
	if got := auditRows(t, f, "alert_dismissed") + auditRows(t, f, "alert_resolved"); got != 8 {
		t.Fatalf("el registro de actividad tiene %d entradas, want 8 (la segunda pasada no cierra nada)", got)
	}
}

// Aunque se pidan más cierres que alertas, siempre queda alguna abierta por fuente.
func TestSeed_SiempreDejaAbiertas(t *testing.T) {
	f := setup(t)
	f.opts.PerSource = 100
	sum, err := alertseed.Seed(context.Background(), f.pool, f.opts)
	if err != nil {
		t.Fatalf("Seed: %v", err)
	}
	for _, source := range []string{detector.SourceRegla, detector.SourceSenuelo} {
		if sum.Counts[source][detector.StateAbierta] < 1 {
			t.Fatalf("%s se quedó sin alertas abiertas: %v", source, sum.Counts[source])
		}
		if sum.Counts[source][detector.StateDescartada] == 0 || sum.Counts[source][detector.StateResuelta] == 0 {
			t.Fatalf("%s debería tener de las dos cerradas: %v", source, sum.Counts[source])
		}
	}
}
