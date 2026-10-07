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

const selectClientColumns = "id, name, api_key_hash, active, created_at, updated_at, system_admin_key_hash, system_admin_key_last_used_at, panel_base_url"

func scanClient(row pgx.Row) (*APIClient, error) {
	c := &APIClient{}
	err := row.Scan(
		&c.ID, &c.Name, &c.APIKeyHash, &c.Active, &c.CreatedAt, &c.UpdatedAt,
		&c.SystemAdminKeyHash, &c.SystemAdminKeyLastUsed, &c.PanelBaseURL,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (r *Repository) Create(ctx context.Context, name, apiKeyHash string) (*APIClient, error) {
	q := `
		INSERT INTO api_clients (name, api_key_hash)
		VALUES ($1, $2)
		RETURNING ` + selectClientColumns

	c, err := scanClient(r.pool.QueryRow(ctx, q, name, apiKeyHash))
	if err != nil {
		return nil, fmt.Errorf("inserting api client: %w", err)
	}
	return c, nil
}

func (r *Repository) FindByAPIKeyHash(ctx context.Context, apiKeyHash string) (*APIClient, error) {
	q := "SELECT " + selectClientColumns + " FROM api_clients WHERE api_key_hash = $1"

	c, err := scanClient(r.pool.QueryRow(ctx, q, apiKeyHash))
	if errors.Is(err, ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("querying api client: %w", err)
	}
	return c, nil
}

// FindBySystemAdminKeyHash looks up the client whose scoped admin
// credential hashes to apiKeyHash — see Service.AuthenticateSystemAdmin.
func (r *Repository) FindBySystemAdminKeyHash(ctx context.Context, apiKeyHash string) (*APIClient, error) {
	q := "SELECT " + selectClientColumns + " FROM api_clients WHERE system_admin_key_hash = $1"

	c, err := scanClient(r.pool.QueryRow(ctx, q, apiKeyHash))
	if errors.Is(err, ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("querying api client by system admin key: %w", err)
	}
	return c, nil
}

// FindByID looks up a client by its own id — used by auth.Service to read
// its PanelBaseURL when building the admin-initiated change-email link.
func (r *Repository) FindByID(ctx context.Context, id string) (*APIClient, error) {
	q := "SELECT " + selectClientColumns + " FROM api_clients WHERE id = $1"

	c, err := scanClient(r.pool.QueryRow(ctx, q, id))
	if errors.Is(err, ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("querying api client by id: %w", err)
	}
	return c, nil
}

// FindByIDs resolves many client ids to their names in a single query —
// used by blacklistHandlers.ListAll to attach api_client_name to every ban
// in one platform-wide listing without a query per row. Missing/unknown ids
// (including "") are simply absent from the returned map rather than an
// error — the caller treats that the same as "name unknown".
func (r *Repository) FindByIDs(ctx context.Context, ids []string) (map[string]string, error) {
	names := make(map[string]string, len(ids))
	if len(ids) == 0 {
		return names, nil
	}

	q := `SELECT id, name FROM api_clients WHERE id = ANY($1)`
	rows, err := r.pool.Query(ctx, q, ids)
	if err != nil {
		return nil, fmt.Errorf("querying api clients by ids: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, fmt.Errorf("scanning api client id/name: %w", err)
		}
		names[id] = name
	}
	return names, rows.Err()
}

// List returns every api client, oldest first — used by the admin CLI
// (cmd/createclient) so an operator can find an id to deactivate/rotate
// without querying Postgres directly.
func (r *Repository) List(ctx context.Context) ([]*APIClient, error) {
	q := "SELECT " + selectClientColumns + " FROM api_clients ORDER BY created_at"

	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("listing api clients: %w", err)
	}
	defer rows.Close()

	var out []*APIClient
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
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

// SetSystemAdminKeyHash replaces id's scoped admin credential — hash == nil
// revokes it outright (see Service.RevokeSystemAdminKey), a non-nil hash
// provisions or rotates it (see Service.RotateSystemAdminKey).
func (r *Repository) SetSystemAdminKeyHash(ctx context.Context, id string, hash *string) error {
	const q = `UPDATE api_clients SET system_admin_key_hash = $2, updated_at = now() WHERE id = $1`
	tag, err := r.pool.Exec(ctx, q, id, hash)
	if err != nil {
		return fmt.Errorf("updating api client system admin key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetPanelBaseURL configures (or clears, with url == nil) which panel this
// tenant's admin-initiated change-email emails should link to — see
// Service.SetPanelBaseURL.
func (r *Repository) SetPanelBaseURL(ctx context.Context, id string, url *string) error {
	const q = `UPDATE api_clients SET panel_base_url = $2, updated_at = now() WHERE id = $1`
	tag, err := r.pool.Exec(ctx, q, id, url)
	if err != nil {
		return fmt.Errorf("updating api client panel base url: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchSystemAdminKeyUsage records that id's scoped admin credential was
// just used — best-effort bookkeeping (see middleware.RequireSystemAdminToken),
// never something a failed write here should block the actual admin action on.
func (r *Repository) TouchSystemAdminKeyUsage(ctx context.Context, id string) error {
	const q = `UPDATE api_clients SET system_admin_key_last_used_at = now() WHERE id = $1`
	_, err := r.pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("touching system admin key usage: %w", err)
	}
	return nil
}
