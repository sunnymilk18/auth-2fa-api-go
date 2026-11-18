package simulate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// insertChunk es cuántos eventos se mandan por sentencia.
const insertChunk = 5000

// Write reemplaza la simulación anterior (si la había) por res, todo en una
// transacción: o queda la simulación nueva completa, o queda la base como
// estaba. Solo toca tenants cuyo nombre empieza con TenantPrefix, sus
// usuarios, sus eventos y sus alertas.
func Write(ctx context.Context, pool *pgxpool.Pool, res *Result) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("abriendo la transacción: %w", err)
	}
	defer tx.Rollback(ctx)

	if err := wipe(ctx, tx); err != nil {
		return err
	}

	createdAt := res.Meta.TrainingFrom.AddDate(0, 0, -30)
	for _, t := range res.Tenants {
		sum := sha256.Sum256([]byte("sim-api-key-" + t.Name))
		if _, err := tx.Exec(ctx, `INSERT INTO api_clients (id, name, api_key_hash) VALUES ($1, $2, $3)`, t.ID, t.Name, hex.EncodeToString(sum[:])); err != nil {
			return fmt.Errorf("creando el tenant %s: %w", t.Name, err)
		}

		var ids, emails, usernames, ruts []string
		var decoys []bool
		for _, group := range [][]Account{t.Users, t.Decoys} {
			for _, a := range group {
				ids, emails, usernames, ruts, decoys = append(ids, a.ID), append(emails, a.Email), append(usernames, a.Username), append(ruts, a.RUT), append(decoys, a.IsDecoy)
			}
		}
		// password_hash no es un hash válido a propósito: nadie inicia sesión
		// con estas cuentas, solo existen para atribuirles eventos.
		if _, err := tx.Exec(ctx, `
			INSERT INTO users (id, api_client_id, email, password_hash, username, rut, is_active, email_verified, is_decoy, created_at)
			SELECT id::uuid, $1::uuid, email, '!simulado', username, rut, TRUE, TRUE, decoy, $7::timestamptz
			FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::bool[]) AS u(id, email, username, rut, decoy)`,
			t.ID, ids, emails, usernames, ruts, decoys, createdAt); err != nil {
			return fmt.Errorf("creando los usuarios de %s: %w", t.Name, err)
		}
	}

	for from := 0; from < len(res.Rows); from += insertChunk {
		to := min(from+insertChunk, len(res.Rows))
		n := to - from
		tenants, users, kinds, methods, results, hashes, ips := make([]string, 0, n), make([]string, 0, n), make([]string, 0, n), make([]string, 0, n), make([]string, 0, n), make([]string, 0, n), make([]string, 0, n)
		decoys := make([]bool, 0, n)
		ats := make([]time.Time, 0, n)
		for _, r := range res.Rows[from:to] {
			tenants, users, kinds, methods, results, hashes, ips = append(tenants, r.TenantID), append(users, r.UserID), append(kinds, r.Kind), append(methods, r.Method), append(results, r.Result), append(hashes, r.EmailHash), append(ips, r.IP)
			decoys, ats = append(decoys, r.IsDecoy), append(ats, r.At)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO auth_events (api_client_id, user_id, kind, method, result, email_hash, ip, user_agent, is_decoy, created_at)
			SELECT NULLIF(t, '')::uuid, NULLIF(u, '')::uuid, k, NULLIF(m, ''), r, NULLIF(h, ''), NULLIF(i, '')::inet, 'simulacion', d, c
			FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::bool[], $9::timestamptz[])
				AS e(t, u, k, m, r, h, i, d, c)`,
			tenants, users, kinds, methods, results, hashes, ips, decoys, ats); err != nil {
			return fmt.Errorf("insertando eventos: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// Wipe borra la simulación anterior sin escribir una nueva.
func Wipe(ctx context.Context, pool *pgxpool.Pool) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := wipe(ctx, tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func wipe(ctx context.Context, tx pgx.Tx) error {
	// Orden de dependencias: alertas y eventos primero (apuntan al tenant y a
	// los usuarios con ON DELETE SET NULL, o sea que borrar al tenant antes
	// los dejaría huérfanos en vez de eliminarlos), luego usuarios y tenants.
	for _, q := range []string{
		// Lo que cmd/seedalerts dejó en el registro de actividad al cerrar
		// alertas: va antes que las alertas, porque se busca por su id.
		`DELETE FROM admin_audit_log WHERE target_type = 'alert' AND target_id IN
			(SELECT a.id::text FROM alerts a JOIN api_clients c ON c.id = a.tenant_id WHERE starts_with(c.name, $1))`,
		`DELETE FROM alerts WHERE tenant_id IN (SELECT id FROM api_clients WHERE starts_with(name, $1))`,
		`DELETE FROM auth_events WHERE api_client_id IN (SELECT id FROM api_clients WHERE starts_with(name, $1))`,
		`DELETE FROM users WHERE api_client_id IN (SELECT id FROM api_clients WHERE starts_with(name, $1))`,
		`DELETE FROM api_clients WHERE starts_with(name, $1)`,
	} {
		if _, err := tx.Exec(ctx, q, TenantPrefix); err != nil {
			return fmt.Errorf("borrando la simulación anterior: %w", err)
		}
	}
	return nil
}

// TruthFile es el contenido de ground_truth.json.
type TruthFile struct {
	Seed uint64 `json:"seed"`
	// Intensity va solo cuando no es "actual" (ver Meta.Intensity).
	Intensity     string  `json:"intensity,omitempty"`
	WindowMinutes int     `json:"window_minutes"`
	Labels        []Label `json:"labels"`
}

// WriteTruth escribe las etiquetas reales — el archivo que el detector nunca
// lee. JSON con sangría y sin fechas de generación: misma semilla, mismo
// archivo, byte a byte.
func WriteTruth(path string, res *Result) error {
	return writeJSON(path, TruthFile{Seed: res.Meta.Seed, Intensity: res.Meta.Intensity, WindowMinutes: int(window / time.Minute), Labels: res.Labels})
}

// WriteMeta escribe los rangos de fechas. No son etiquetas.
func WriteMeta(path string, res *Result) error { return writeJSON(path, res.Meta) }

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// LoadTruth lee ground_truth.json.
func LoadTruth(path string) (*TruthFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var t TruthFile
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("%s no es un JSON válido: %w", path, err)
	}
	return &t, nil
}

// LoadMeta lee meta.json.
func LoadMeta(path string) (*Meta, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Meta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%s no es un JSON válido: %w", path, err)
	}
	return &m, nil
}
