// Package alertseed deja alertas reales en la base LOCAL para probar la
// pantalla del panel con la simulación cargada: hace que el detector recorra
// un rango de ventanas (con detector.Run, nunca insertando alertas a mano) y
// después cierra algunas — unas como descartadas y otras como resueltas —
// pasando por las rutas de la API (POST /admin/alerts/{id}/dismiss y
// /resolve), así que también quedan en el registro de actividad como lo haría
// un operador de verdad.
//
// Es repetible: el índice único de alerts evita duplicar las del detector, y
// los cierres se calculan contra lo que ya está cerrado, así que correr dos
// veces deja lo mismo que correr una. Solo toca alertas de tenants cuyo
// nombre empieza con el prefijo dado (por defecto, los simulados).
//
// Las rutas se sirven en proceso, con un Redis en memoria (miniredis, que ya
// es dependencia del proyecto para las pruebas) y una credencial X-Admin-Token
// aleatoria que nunca sale del proceso: no hace falta levantar la API ni
// tocar ningún Redis. Por eso los cierres quedan atribuidos a la credencial
// compartida (resolved_by vacío), no a la cuenta de un operador.
package alertseed

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/metric/noop"

	"auth-2fa-api/internal/audit"
	"auth-2fa-api/internal/detector"
	"auth-2fa-api/internal/httpserver"
)

// Sources y States fijan el orden en que se reportan.
var (
	Sources = []string{detector.SourceRegla, detector.SourceSenuelo, detector.SourceIsolationForest}
	States  = []string{detector.StateAbierta, detector.StateDescartada, detector.StateResuelta}
)

// Router sirve las rutas /admin/* de la API en proceso.
type Router struct {
	handler http.Handler
	token   string
	redis   *miniredis.Miniredis
}

// NewRouter arma el router real de la API (httpserver.NewRouter) con lo mínimo
// para atender /admin/alerts: la base, un Redis en memoria, el registro de
// actividad y un token de administrador aleatorio. Las rutas de autenticación
// de usuarios finales quedan sin dependencias y no se usan.
func NewRouter(pool *pgxpool.Pool) (*Router, error) {
	mr, err := miniredis.Run()
	if err != nil {
		return nil, fmt.Errorf("levantando el Redis en memoria: %w", err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		mr.Close()
		return nil, err
	}
	token := hex.EncodeToString(raw[:])

	meter := noop.NewMeterProvider().Meter("alertseed")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	auditSvc := audit.NewService(audit.NewRepository(pool), 365*24*time.Hour, meter, logger)

	handler := httpserver.NewRouter(nil, nil, nil, nil, nil, pool, rdb, nil, meter, token,
		false, false, nil, nil, nil, "", false, time.Hour, auditSvc, nil, logger)
	return &Router{handler: handler, token: token, redis: mr}, nil
}

// Close apaga el Redis en memoria.
func (r *Router) Close() { r.redis.Close() }

// Post hace una llamada autenticada a la API y devuelve el código HTTP.
func (r *Router) Post(path, body string) (int, string) {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Token", r.token)
	rec := httptest.NewRecorder()
	r.handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// Options configura Seed.
type Options struct {
	Detector *detector.Detector
	Router   *Router
	From, To time.Time
	// TenantNamePrefix limita las alertas a cerrar (y lo que lee el detector,
	// si se configuró igual en el Detector) a los tenants cuyo nombre empieza así.
	TenantNamePrefix string
	// PerSource: cuántas alertas por fuente se dejan descartadas y cuántas
	// resueltas (el mismo número para cada estado).
	PerSource int
}

// Summary es el resultado de una pasada.
type Summary struct {
	// Created: alertas nuevas que creó detector.Run en esta pasada.
	Created int
	// Closed: alertas que esta pasada cerró por las rutas de la API.
	Closed int
	// Counts: alertas de los tenants del prefijo, por fuente y por estado.
	Counts map[string]map[string]int
}

type alertRow struct{ id, source, state string }

func (o Options) alerts(ctx context.Context, pool *pgxpool.Pool) ([]alertRow, error) {
	rows, err := pool.Query(ctx, `
		SELECT a.id::text, a.source, a.state
		FROM alerts a JOIN api_clients c ON c.id = a.tenant_id
		WHERE starts_with(c.name, $1)
		ORDER BY a.window_start, a.id`, o.TenantNamePrefix)
	if err != nil {
		return nil, fmt.Errorf("leyendo las alertas: %w", err)
	}
	defer rows.Close()
	var out []alertRow
	for rows.Next() {
		var a alertRow
		if err := rows.Scan(&a.id, &a.source, &a.state); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// pick elige n posiciones repartidas parejo entre las alertas abiertas (en vez
// de las n primeras), para que las cerradas queden mezcladas por todo el rango
// de fechas. Deja siempre al menos una abierta.
func pick(open []alertRow, n int) []alertRow {
	if len(open) <= 1 || n <= 0 {
		return nil
	}
	if n > len(open)-1 {
		n = len(open) - 1
	}
	out := make([]alertRow, 0, n)
	last := -1
	for i := 1; i <= n; i++ {
		pos := i * len(open) / (n + 1)
		if pos <= last {
			pos = last + 1
		}
		if pos >= len(open) {
			break
		}
		out = append(out, open[pos])
		last = pos
	}
	return out
}

// Seed corre el detector sobre [From, To) y cierra alertas hasta que cada
// fuente tenga PerSource descartadas y PerSource resueltas (contando las que
// ya lo estaban, para que repetir no cierre más), siempre dejando abiertas el
// resto.
func Seed(ctx context.Context, pool *pgxpool.Pool, o Options) (*Summary, error) {
	created, err := o.Detector.Run(ctx, o.From, o.To)
	if err != nil {
		return nil, fmt.Errorf("corriendo el detector: %w", err)
	}
	sum := &Summary{Created: created}

	all, err := o.alerts(ctx, pool)
	if err != nil {
		return nil, err
	}
	for _, source := range Sources {
		var open []alertRow
		closed := map[string]int{}
		for _, a := range all {
			if a.source != source {
				continue
			}
			if a.state == detector.StateAbierta {
				open = append(open, a)
			} else {
				closed[a.state]++
			}
		}
		needDismiss := max(o.PerSource-closed[detector.StateDescartada], 0)
		needResolve := max(o.PerSource-closed[detector.StateResuelta], 0)

		// Descartadas y resueltas se alternan, para que se mezclen por todo el rango.
		var actions []string
		for d, r := needDismiss, needResolve; d > 0 || r > 0; {
			if d > 0 {
				actions, d = append(actions, "dismiss"), d-1
			}
			if r > 0 {
				actions, r = append(actions, "resolve"), r-1
			}
		}
		chosen := pick(open, len(actions))
		for i, a := range chosen {
			action, note := actions[i], "Simulado para probar el panel: descartada"
			if action == "resolve" {
				note = "Simulado para probar el panel: resuelta"
			}
			code, body := o.Router.Post("/admin/alerts/"+a.id+"/"+action, fmt.Sprintf(`{"note":%q}`, note))
			if code != http.StatusOK {
				return nil, fmt.Errorf("POST /admin/alerts/%s/%s respondió %d: %s", a.id, action, code, body)
			}
			sum.Closed++
		}
	}

	all, err = o.alerts(ctx, pool)
	if err != nil {
		return nil, err
	}
	sum.Counts = map[string]map[string]int{}
	for _, s := range Sources {
		sum.Counts[s] = map[string]int{}
	}
	for _, a := range all {
		if sum.Counts[a.source] == nil {
			sum.Counts[a.source] = map[string]int{}
		}
		sum.Counts[a.source][a.state]++
	}
	return sum, nil
}
