package testutil

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"auth-2fa-api/internal/user"
)

// NewUser registers a throwaway user under apiClientID and registers a
// cleanup to delete it. Call this after NewAPIClient(t, pool) for the same
// pool — t.Cleanup runs LIFO, so the user (registered later) is deleted
// before its api_client, satisfying the users.api_client_id foreign key.
func NewUser(t *testing.T, pool *pgxpool.Pool, apiClientID, password string) *user.User {
	t.Helper()

	svc := user.NewService(user.NewRepository(pool))
	email := "user-" + UniqueSuffix(t) + "@example.com"
	u, err := svc.Register(context.Background(), apiClientID, email, password)
	if err != nil {
		t.Fatalf("creating test user: %v", err)
	}

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, u.ID)
	})

	return u
}
