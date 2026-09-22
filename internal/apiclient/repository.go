package apiclient

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

var ErrNotFound = errors.New("api client not found")

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) Create(ctx context.Context, name, apiKeyHash string) (*APIClient, error) {
	const q = `
		INSERT INTO api_clients (name, api_key_hash)
		OUTPUT INSERTED.id, INSERTED.name, INSERTED.api_key_hash, INSERTED.active, INSERTED.created_at, INSERTED.updated_at
		VALUES (?, ?)`

	c := &APIClient{}
	err := r.db.QueryRowContext(ctx, q, name, apiKeyHash).Scan(
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
		FROM api_clients WHERE api_key_hash = ?`

	c := &APIClient{}
	err := r.db.QueryRowContext(ctx, q, apiKeyHash).Scan(
		&c.ID, &c.Name, &c.APIKeyHash, &c.Active, &c.CreatedAt, &c.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("querying api client: %w", err)
	}
	return c, nil
}

// List returns every api client, oldest first — used by the admin CLI
// (cmd/createclient) so an operator can find an id to deactivate/rotate
// without querying the database directly.
func (r *Repository) List(ctx context.Context) ([]*APIClient, error) {
	const q = `
		SELECT id, name, api_key_hash, active, created_at, updated_at
		FROM api_clients ORDER BY created_at`

	rows, err := r.db.QueryContext(ctx, q)
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
	const q = `UPDATE api_clients SET active = ?, updated_at = SYSDATETIMEOFFSET() WHERE id = ?`
	res, err := r.db.ExecContext(ctx, q, active, id)
	if err != nil {
		return fmt.Errorf("updating api client active state: %w", err)
	}
	return errIfNoRowsAffected(res)
}

// UpdateKeyHash replaces id's stored key hash — used to rotate a key
// without changing the client's identity (id, name), so nothing else about
// it (e.g. which users belong to it) needs to move.
func (r *Repository) UpdateKeyHash(ctx context.Context, id, apiKeyHash string) error {
	const q = `UPDATE api_clients SET api_key_hash = ?, updated_at = SYSDATETIMEOFFSET() WHERE id = ?`
	res, err := r.db.ExecContext(ctx, q, apiKeyHash, id)
	if err != nil {
		return fmt.Errorf("updating api client key: %w", err)
	}
	return errIfNoRowsAffected(res)
}

func errIfNoRowsAffected(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
