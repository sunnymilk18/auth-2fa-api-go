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
