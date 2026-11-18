package detector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Valores de alerts.source.
const (
	SourceRegla           = "regla"
	SourceIsolationForest = "isolation_forest"
	SourceSenuelo         = "senuelo"
)

// Valores de alerts.state.
const (
	StateAbierta    = "abierta"
	StateDescartada = "descartada"
	StateResuelta   = "resuelta"
)

// IsValidState reporta si s es un estado de alerta conocido.
func IsValidState(s string) bool {
	return s == StateAbierta || s == StateDescartada || s == StateResuelta
}

var (
	// ErrAlertNotFound: no existe una alerta con ese id.
	ErrAlertNotFound = errors.New("alerta no encontrada")
	// ErrAlertNotOpen: la alerta ya fue descartada o resuelta.
	ErrAlertNotOpen = errors.New("la alerta ya no está abierta")
)

// Alert es una fila de alerts con su tenant y su operador ya resueltos.
// TenantID/TenantName/IP/ResolvedBy/Note van vacíos cuando la columna es NULL
// — la misma convención que authevents.ListedEvent; el manejador HTTP es
// quien los convierte en null/{} según el contrato.
type Alert struct {
	ID          string
	TenantID    string
	TenantName  string
	IP          string
	WindowStart time.Time
	WindowEnd   time.Time
	Source      string
	Score       *float64
	Features    Features
	Motives     []string
	State       string
	CreatedAt   time.Time
	// ResolvedBy es el correo de la cuenta de operador que cerró la alerta;
	// vacío si sigue abierta o si la cerró la credencial compartida
	// X-Admin-Token, que no tiene cuenta individual.
	ResolvedBy string
	ResolvedAt *time.Time
	Note       string
}

// NewAlert es lo que el detector inserta.
type NewAlert struct {
	TenantID    string
	IP          string
	WindowStart time.Time
	WindowEnd   time.Time
	Source      string
	Score       *float64
	Features    Features
	Motives     []string
}

// AlertFilter acota List. Los campos en su valor cero no filtran. From/To ya
// vienen resueltos por quien llama (From inclusivo, To exclusivo) y se
// comparan contra window_start: la fecha de una alerta es la de los eventos
// que la causaron, no la de cuándo el detector la generó (un reproceso de
// ventanas viejas no debe verse como "de hoy").
type AlertFilter struct {
	State    string
	TenantID string
	From     time.Time
	To       time.Time
}

// AlertRepository persiste alertas en Postgres.
type AlertRepository struct {
	pool *pgxpool.Pool
}

func NewAlertRepository(pool *pgxpool.Pool) *AlertRepository {
	return &AlertRepository{pool: pool}
}

// Insert guarda una alerta y devuelve false (sin error) si ya existía una de
// la misma ventana, clave y fuente — ver idx_alerts_unique_window_key_source.
func (r *AlertRepository) Insert(ctx context.Context, a NewAlert) (bool, error) {
	features, err := json.Marshal(a.Features)
	if err != nil {
		return false, fmt.Errorf("serializando características: %w", err)
	}
	motives, err := json.Marshal(a.Motives)
	if err != nil {
		return false, fmt.Errorf("serializando motivos: %w", err)
	}
	const q = `
		INSERT INTO alerts (tenant_id, ip, window_start, window_end, source, score, features, motives)
		VALUES (NULLIF($1, '')::uuid, NULLIF($2, '')::inet, $3, $4, $5, $6, $7, $8)
		ON CONFLICT DO NOTHING`
	tag, err := r.pool.Exec(ctx, q, a.TenantID, a.IP, a.WindowStart, a.WindowEnd, a.Source, a.Score, features, motives)
	if err != nil {
		return false, fmt.Errorf("insertando alerta: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

const selectAlertColumns = `
	a.id, COALESCE(a.tenant_id::text, ''), COALESCE(c.name, ''), COALESCE(host(a.ip), ''),
	a.window_start, a.window_end, a.source, a.score, a.features, a.motives, a.state,
	a.created_at, COALESCE(op.email, ''), a.resolved_at, COALESCE(a.note, '')`

const fromAlertTables = `
	FROM alerts a
	LEFT JOIN api_clients c ON c.id = a.tenant_id
	LEFT JOIN admin_accounts op ON op.id = a.resolved_by`

func scanAlert(row pgx.Row, extra ...any) (*Alert, error) {
	a := &Alert{}
	var features, motives []byte
	dest := append([]any{
		&a.ID, &a.TenantID, &a.TenantName, &a.IP,
		&a.WindowStart, &a.WindowEnd, &a.Source, &a.Score, &features, &motives, &a.State,
		&a.CreatedAt, &a.ResolvedBy, &a.ResolvedAt, &a.Note,
	}, extra...)
	if err := row.Scan(dest...); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(features, &a.Features); err != nil {
		return nil, fmt.Errorf("leyendo características de la alerta %s: %w", a.ID, err)
	}
	if err := json.Unmarshal(motives, &a.Motives); err != nil {
		return nil, fmt.Errorf("leyendo motivos de la alerta %s: %w", a.ID, err)
	}
	if a.Motives == nil {
		a.Motives = []string{}
	}
	return a, nil
}

// Get devuelve una alerta por id, o ErrAlertNotFound.
func (r *AlertRepository) Get(ctx context.Context, id string) (*Alert, error) {
	a, err := scanAlert(r.pool.QueryRow(ctx, `SELECT `+selectAlertColumns+fromAlertTables+` WHERE a.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAlertNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("consultando alerta: %w", err)
	}
	return a, nil
}

const (
	defaultAlertPageSize = 50
	maxAlertPageSize     = 100
)

// List devuelve una página de alertas, la más reciente primero (por
// window_start, y created_at/id para desempatar de forma estable), junto con
// el total que cumple el filtro. page empieza en 1; page_size se acota a
// [1, 100] con 50 por defecto — mismo criterio que el resto de los listados.
func (r *AlertRepository) List(ctx context.Context, f AlertFilter, page, pageSize int) (alerts []*Alert, total, effectivePage, effectivePageSize int, err error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = defaultAlertPageSize
	}
	if pageSize > maxAlertPageSize {
		pageSize = maxAlertPageSize
	}

	query := `SELECT ` + selectAlertColumns + `, COUNT(*) OVER() AS total` + fromAlertTables + `
		WHERE a.window_start >= $1 AND a.window_start < $2`
	args := []any{f.From, f.To}
	if f.State != "" {
		args = append(args, f.State)
		query += fmt.Sprintf(" AND a.state = $%d", len(args))
	}
	if f.TenantID != "" {
		args = append(args, f.TenantID)
		query += fmt.Sprintf(" AND a.tenant_id = $%d", len(args))
	}
	query += fmt.Sprintf(" ORDER BY a.window_start DESC, a.created_at DESC, a.id DESC OFFSET $%d LIMIT $%d", len(args)+1, len(args)+2)
	args = append(args, (page-1)*pageSize, pageSize)

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, 0, 0, fmt.Errorf("listando alertas: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		a, err := scanAlert(rows, &total)
		if err != nil {
			return nil, 0, 0, 0, fmt.Errorf("leyendo alerta: %w", err)
		}
		alerts = append(alerts, a)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, 0, 0, fmt.Errorf("listando alertas: %w", err)
	}
	return alerts, total, page, pageSize, nil
}

// Close mueve una alerta abierta a newState (descartada o resuelta) y deja
// quién y cuándo. actorEmail es el operador que actúa; si no corresponde a
// una cuenta de operador (el X-Admin-Token compartido), resolved_by queda
// NULL. Devuelve ErrAlertNotFound si el id no existe y ErrAlertNotOpen si ya
// estaba cerrada.
func (r *AlertRepository) Close(ctx context.Context, id, newState, actorEmail, note string) (*Alert, error) {
	const q = `
		UPDATE alerts
		SET state = $2, resolved_at = now(),
			resolved_by = (SELECT id FROM admin_accounts WHERE email = $3),
			note = NULLIF($4, '')
		WHERE id = $1 AND state = 'abierta'`
	tag, err := r.pool.Exec(ctx, q, id, newState, actorEmail, note)
	if err != nil {
		return nil, fmt.Errorf("cerrando alerta: %w", err)
	}
	a, err := r.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrAlertNotOpen
	}
	return a, nil
}
