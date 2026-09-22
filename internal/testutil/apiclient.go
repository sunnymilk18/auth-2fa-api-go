package testutil

import (
	"context"
	"database/sql"
	"testing"

	"auth-2fa-api/internal/apiclient"
)

// NewAPIClient provisions a throwaway api_client (tenant) row for a test —
// most of the schema (users, devices, ...) hangs off one via a foreign key —
// and registers a cleanup to delete it afterwards. Returns the client and
// its plaintext API key.
func NewAPIClient(t *testing.T, db *sql.DB) (*apiclient.APIClient, string) {
	t.Helper()

	svc := apiclient.NewService(apiclient.NewRepository(db))
	client, plaintextKey, err := svc.Create(context.Background(), "testclient-"+UniqueSuffix(t))
	if err != nil {
		t.Fatalf("creating test api client: %v", err)
	}

	t.Cleanup(func() {
		ctx := context.Background()
		// Some tests create users via user.Service/auth.Service directly
		// (not through NewUser, which registers its own cleanup) — delete
		// any left referencing this client first, so that oversight doesn't
		// make the DELETE below silently no-op behind the FK and leave both
		// orphaned forever. refresh_tokens/trusted_devices cascade off
		// users(id) on their own (see migrations 0001/0002).
		_, _ = db.ExecContext(ctx, `DELETE FROM users WHERE api_client_id = ?`, client.ID)
		_, _ = db.ExecContext(ctx, `DELETE FROM api_clients WHERE id = ?`, client.ID)
	})

	return client, plaintextKey
}
