package testutil

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"auth-2fa-api/internal/apiclient"
)

// NewAPIClient provisions a throwaway api_client (tenant) row for a test —
// most of the schema (users, devices, ...) hangs off one via a foreign key —
// and registers a cleanup to delete it afterwards. Returns the client and
// its plaintext API key.
func NewAPIClient(t *testing.T, pool *pgxpool.Pool) (*apiclient.APIClient, string) {
	t.Helper()

	svc := apiclient.NewService(apiclient.NewRepository(pool))
	client, plaintextKey, err := svc.Create(context.Background(), "testclient-"+UniqueSuffix(t))
	if err != nil {
		t.Fatalf("creating test api client: %v", err)
	}

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM api_clients WHERE id = $1`, client.ID)
	})

	return client, plaintextKey
}
