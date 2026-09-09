package apiclient

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotFound = errors.New("api client not found")

type Repository struct {
	pool *pgxpool.Pool
}

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

func (r *Repository) Create(ctx context.Context, name, apiKeyHash string) (*APIClient, error) {
	const q = `
		INSERT INTO api_clients (name, api_key_hash)
		VALUES ($1, $2)
		RETURNING id, name, api_key_hash, active, created_at, updated_at`

	c := &APIClient{}
	err := r.pool.QueryRow(ctx, q, name, apiKeyHash).Scan(
		&c.ID, &c.Name, &c.APIKeyHash, &c.Active, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("inserting api client: %w", err)
	}
	return c, nil
}

func (r *Repository) FindByAPIKeyHash(ctx context.Context, apiKeyHash string) (*APIClient, error) {
	const q = `
		SELECT id, name, api_key_hash, active, created_at, updated_at
		FROM api_clients WHERE api_key_hash = $1`

	c := &APIClient{}
	err := r.pool.QueryRow(ctx, q, apiKeyHash).Scan(
		&c.ID, &c.Name, &c.APIKeyHash, &c.Active, &c.CreatedAt, &c.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("querying api client: %w", err)
	}
	return c, nil
}

// List returns every api client, oldest first — used by the admin CLI
// (cmd/createclient) so an operator can find an id to deactivate/rotate
// without querying Postgres directly.
func (r *Repository) List(ctx context.Context) ([]*APIClient, error) {
	const q = `
		SELECT id, name, api_key_hash, active, created_at, updated_at
		FROM api_clients ORDER BY created_at`

	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("listing api clients: %w", err)
	}
	defer rows.Close()

	var out []*APIClient
	for rows.Next() {
		c := &APIClient{}
		if err := rows.Scan(&c.ID, &c.Name, &c.APIKeyHash, &c.Active, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning api client: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SetActive flips a client's active flag — deactivating one makes its key
// stop authenticating immediately (see middleware.RequireAPIKey).
func (r *Repository) SetActive(ctx context.Context, id string, active bool) error {
	const q = `UPDATE api_clients SET active = $2, updated_at = now() WHERE id = $1`
	tag, err := r.pool.Exec(ctx, q, id, active)
	if err != nil {
		return fmt.Errorf("updating api client active state: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateKeyHash replaces id's stored key hash — used to rotate a key
// without changing the client's identity (id, name), so nothing else about
// it (e.g. which users belong to it) needs to move.
func (r *Repository) UpdateKeyHash(ctx context.Context, id, apiKeyHash string) error {
	const q = `UPDATE api_clients SET api_key_hash = $2, updated_at = now() WHERE id = $1`
	tag, err := r.pool.Exec(ctx, q, id, apiKeyHash)
	if err != nil {
		return fmt.Errorf("updating api client key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
