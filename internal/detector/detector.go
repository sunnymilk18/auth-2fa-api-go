package detector

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DefaultIFThreshold es el umbral de respaldo para un modelo que no trae uno
// calibrado. Un modelo entrenado con cmd/train siempre lo trae (ver
// KeyModel.Threshold), así que en la práctica no se usa.
const DefaultIFThreshold = 0.6

// Analysis es todo lo que el detector concluye de una unidad: los tres
// métodos por separado, para que cmd/evaluate pueda compararlos sin tener que
// pasar por la tabla alerts.
type Analysis struct {
	Unit Unit
	// RuleMotives no vacío: la unidad dispara la línea base por umbrales.
	RuleMotives []string
	// DecoyMotives no vacío: hubo al menos un intento contra un señuelo.
	DecoyMotives []string
	// Score es el puntaje del bosque; nil si no hay modelo para este tipo
	// de clave.
	Score *float64
	// ForestAlert es true si Score alcanza el umbral; ForestMotives explica
	// por qué.
	ForestAlert   bool
	ForestMotives []string
}

// Finding es una alerta por generar, una por cada fuente que se activa.
type Finding struct {
	Unit    Unit
	Source  string
	Score   *float64
	Motives []string
}

// Findings devuelve las alertas que esta unidad genera, en orden fijo: regla,
// señuelo, isolation_forest.
func (a Analysis) Findings() []Finding {
	var out []Finding
	if len(a.RuleMotives) > 0 {
		out = append(out, Finding{Unit: a.Unit, Source: SourceRegla, Motives: a.RuleMotives})
	}
	if len(a.DecoyMotives) > 0 {
		out = append(out, Finding{Unit: a.Unit, Source: SourceSenuelo, Motives: a.DecoyMotives})
	}
	if a.ForestAlert {
		out = append(out, Finding{Unit: a.Unit, Source: SourceIsolationForest, Score: a.Score, Motives: a.ForestMotives})
	}
	return out
}

// Detector corre las reglas, el bosque y la regla de señuelos sobre auth_events.
// Con model nil funciona solo con reglas: es el estado normal de una API que
// nunca se entrenó, y no es un error.
type Detector struct {
	pool        *pgxpool.Pool
	alerts      *AlertRepository
	rules       Rules
	model       *Model
	ifThreshold float64 // 0: usar el umbral calibrado de cada bosque
	logger      *slog.Logger

	// TenantNamePrefix, si no está vacío, limita lo que Scan y Run leen a los
	// tenants cuyo nombre empieza así. Solo lo usan las herramientas del
	// experimento (cmd/train, cmd/evaluate) para quedarse con los tenants
	// simulados; la API lo deja vacío y mira todo.
	TenantNamePrefix string
}

// New arma un Detector. model puede ser nil (solo reglas). ifThreshold > 0
// fija el umbral del bosque para todos los tipos de clave
// (DETECTOR_IF_THRESHOLD); 0 usa el umbral calibrado que trae el modelo para
// cada uno.
func New(pool *pgxpool.Pool, rules Rules, model *Model, ifThreshold float64, logger *slog.Logger) *Detector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Detector{
		pool: pool, alerts: NewAlertRepository(pool),
		rules: rules, model: model, ifThreshold: ifThreshold, logger: logger,
	}
}

// HasModel reporta si hay un modelo cargado.
func (d *Detector) HasModel() bool { return d.model != nil }

// IFThreshold devuelve el umbral de puntaje que se aplica a keyType.
func (d *Detector) IFThreshold(keyType string) float64 {
	if d.ifThreshold > 0 {
		return d.ifThreshold
	}
	return d.model.Threshold(keyType)
}

// Analyze evalúa cada unidad con los tres métodos.
func (d *Detector) Analyze(units []Unit) []Analysis {
	out := make([]Analysis, 0, len(units))
	for _, u := range units {
		a := Analysis{
			Unit:         u,
			RuleMotives:  d.rules.Evaluate(u.Features),
			DecoyMotives: DecoyMotives(u.Features),
		}
		if score, ok := d.model.Score(u.KeyType, u.Features); ok {
			a.Score = &score
			if score >= d.IFThreshold(u.KeyType) {
				a.ForestAlert = true
				a.ForestMotives = d.model.Explain(u.KeyType, u.Features)
			}
		}
		out = append(out, a)
	}
	return out
}

// LoadEvents lee de auth_events lo que el detector necesita entre from
// (inclusivo) y to (exclusivo): los eventos de inicio de sesión y cualquier
// evento marcado como señuelo. Es de solo lectura. tenantNamePrefix, si no
// está vacío, deja solo los eventos de tenants cuyo nombre empieza así.
func LoadEvents(ctx context.Context, pool *pgxpool.Pool, from, to time.Time, tenantNamePrefix string) ([]Event, error) {
	const q = `
		SELECT e.created_at, e.kind, COALESCE(e.api_client_id::text, ''), COALESCE(e.user_id::text, ''),
			COALESCE(e.email_hash, ''), COALESCE(host(e.ip), ''), e.result, e.is_decoy
		FROM auth_events e
		LEFT JOIN api_clients c ON c.id = e.api_client_id
		WHERE e.created_at >= $1 AND e.created_at < $2 AND (e.kind = 'login' OR e.is_decoy)
			AND ($3 = '' OR starts_with(COALESCE(c.name, ''), $3))
		ORDER BY e.created_at, e.id`
	rows, err := pool.Query(ctx, q, from, to, tenantNamePrefix)
	if err != nil {
		return nil, fmt.Errorf("leyendo auth_events: %w", err)
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.At, &e.Kind, &e.TenantID, &e.UserID, &e.EmailHash, &e.IP, &e.Result, &e.IsDecoy); err != nil {
			return nil, fmt.Errorf("leyendo un evento: %w", err)
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("leyendo auth_events: %w", err)
	}
	return events, nil
}

// completeWindows alinea [from, to) a ventanas enteras: from hacia abajo, to
// hacia abajo — una ventana a medias nunca se evalúa, sus números todavía
// están cambiando.
func completeWindows(from, to time.Time) (time.Time, time.Time) {
	return WindowStartOf(from), WindowStartOf(to)
}

// Scan carga los eventos de las ventanas completas en [from, to), los agrega
// y los analiza. No escribe nada: es lo que usa cmd/evaluate.
func (d *Detector) Scan(ctx context.Context, from, to time.Time) ([]Analysis, error) {
	from, to = completeWindows(from, to)
	if !from.Before(to) {
		return nil, nil
	}
	events, err := LoadEvents(ctx, d.pool, from, to, d.TenantNamePrefix)
	if err != nil {
		return nil, err
	}
	return d.Analyze(Aggregate(events)), nil
}

// Run es Scan más guardar las alertas nuevas. Seguro de repetir sobre las
// mismas ventanas: el índice único de alerts evita duplicados. Devuelve
// cuántas alertas nuevas creó.
func (d *Detector) Run(ctx context.Context, from, to time.Time) (int, error) {
	analyses, err := d.Scan(ctx, from, to)
	if err != nil {
		return 0, err
	}
	created := 0
	for _, a := range analyses {
		for _, f := range a.Findings() {
			inserted, err := d.alerts.Insert(ctx, NewAlert{
				TenantID: f.Unit.TenantID, IP: f.Unit.IP,
				WindowStart: f.Unit.WindowStart, WindowEnd: f.Unit.WindowEnd(),
				Source: f.Source, Score: f.Score, Features: f.Unit.Features, Motives: f.Motives,
			})
			if err != nil {
				return created, err
			}
			if inserted {
				created++
			}
		}
	}
	return created, nil
}

// Start corre el detector cada interval hasta que ctx se cancele: en cada
// pasada revisa las ventanas completas de la última hora (lookback), y el
// índice único de alerts se encarga de no repetir las ya registradas. Un
// error en una pasada se registra y se sigue; el detector nunca tumba la API.
func (d *Detector) Start(ctx context.Context, interval, lookback time.Duration) {
	pass := func() {
		now := time.Now()
		n, err := d.Run(ctx, now.Add(-lookback), now)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			d.logger.Error("pasada del detector falló", "error", err)
		case n > 0:
			d.logger.Info("detector: alertas nuevas", "creadas", n)
		}
	}

	pass()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pass()
		}
	}
}
