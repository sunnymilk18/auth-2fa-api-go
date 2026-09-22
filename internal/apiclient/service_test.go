package apiclient_test

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"auth-2fa-api/internal/apiclient"
	"auth-2fa-api/internal/testutil"
)

func newTestService(t *testing.T) *apiclient.Service {
	t.Helper()
	pool := testutil.MSSQLPool(t)
	return apiclient.NewService(apiclient.NewRepository(pool))
}

func newTestServiceAndPool(t *testing.T) (*apiclient.Service, *sql.DB) {
	t.Helper()
	pool := testutil.MSSQLPool(t)
	return apiclient.NewService(apiclient.NewRepository(pool)), pool
}

// mustCreate calls svc.Create directly (unlike testutil.NewAPIClient, which
// goes through it) and registers its own cleanup — needed by tests that
// specifically exercise Create/Authenticate rather than everything
// testutil.NewAPIClient provisions.
func mustCreate(t *testing.T, svc *apiclient.Service, pool *sql.DB) (*apiclient.APIClient, string) {
	t.Helper()
	client, plaintextKey, err := svc.Create(t.Context(), "test-"+testutil.UniqueSuffix(t))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.ExecContext(context.Background(), `DELETE FROM api_clients WHERE id = ?`, client.ID)
	})
	return client, plaintextKey
}

func TestCreate_GeneratesUniqueKeys(t *testing.T) {
	svc, pool := newTestServiceAndPool(t)

	const n = 100
	seenKeys := make(map[string]bool, n)
	seenHashes := make(map[string]bool, n)

	for i := 0; i < n; i++ {
		client, plaintextKey := mustCreate(t, svc, pool)
		if !strings.HasPrefix(plaintextKey, "sk_live_") {
			t.Fatalf("Create #%d: key %q missing sk_live_ prefix", i, plaintextKey)
		}
		if seenKeys[plaintextKey] {
			t.Fatalf("Create #%d: plaintext key collided with a previous Create call — the RNG behind generateKey may be broken (not cryptographically random)", i)
		}
		if seenHashes[client.APIKeyHash] {
			t.Fatalf("Create #%d: stored hash collided with a previous Create call", i)
		}
		seenKeys[plaintextKey] = true
		seenHashes[client.APIKeyHash] = true
	}
}

func TestCreate_StoresOnlyTheHash_NeverThePlaintext(t *testing.T) {
	svc, pool := newTestServiceAndPool(t)
	client, plaintextKey := mustCreate(t, svc, pool)

	if client.APIKeyHash == plaintextKey {
		t.Fatal("stored api_key_hash equals the plaintext key — it must be hashed")
	}
	if client.APIKeyHash != apiclient.HashKey(plaintextKey) {
		t.Fatalf("stored hash %q != HashKey(plaintext) %q", client.APIKeyHash, apiclient.HashKey(plaintextKey))
	}
}

func TestCreate_DuplicateName(t *testing.T) {
	svc, pool := newTestServiceAndPool(t)
	client, _ := mustCreate(t, svc, pool)

	if _, _, err := svc.Create(t.Context(), client.Name); !errors.Is(err, apiclient.ErrNameTaken) {
		t.Fatalf("err = %v, want %v", err, apiclient.ErrNameTaken)
	}
}

func TestAuthenticate_RoundTrip(t *testing.T) {
	svc, pool := newTestServiceAndPool(t)
	created, plaintextKey := mustCreate(t, svc, pool)

	got, err := svc.Authenticate(t.Context(), plaintextKey)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got.ID != created.ID {
		t.Fatalf("Authenticate returned client %q, want %q", got.ID, created.ID)
	}
}

func TestAuthenticate_UnknownKey(t *testing.T) {
	svc := newTestService(t)
	if _, err := svc.Authenticate(t.Context(), "sk_live_does_not_exist"); err != apiclient.ErrInvalidAPIKey {
		t.Fatalf("err = %v, want %v", err, apiclient.ErrInvalidAPIKey)
	}
}

func TestAuthenticate_InactiveClient(t *testing.T) {
	pool := testutil.MSSQLPool(t)
	svc := apiclient.NewService(apiclient.NewRepository(pool))
	client, plaintextKey := testutil.NewAPIClient(t, pool)

	if _, err := pool.ExecContext(t.Context(), `UPDATE api_clients SET active = 0 WHERE id = ?`, client.ID); err != nil {
		t.Fatalf("deactivating test client: %v", err)
	}

	if _, err := svc.Authenticate(t.Context(), plaintextKey); err != apiclient.ErrInactive {
		t.Fatalf("err = %v, want %v", err, apiclient.ErrInactive)
	}
}

func TestList_IncludesCreatedClients(t *testing.T) {
	svc, pool := newTestServiceAndPool(t)
	a, _ := testutil.NewAPIClient(t, pool)
	b, _ := testutil.NewAPIClient(t, pool)

	clients, err := svc.List(t.Context())
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	found := map[string]bool{}
	for _, c := range clients {
		found[c.ID] = true
	}
	if !found[a.ID] || !found[b.ID] {
		t.Fatalf("List (%d clients) missing one or both created clients %q, %q", len(clients), a.ID, b.ID)
	}
}

func TestDeactivate_ThenActivate(t *testing.T) {
	svc, pool := newTestServiceAndPool(t)
	client, plaintextKey := testutil.NewAPIClient(t, pool)

	if err := svc.Deactivate(t.Context(), client.ID); err != nil {
		t.Fatalf("Deactivate: %v", err)
	}
	if _, err := svc.Authenticate(t.Context(), plaintextKey); err != apiclient.ErrInactive {
		t.Fatalf("Authenticate after Deactivate: err = %v, want %v", err, apiclient.ErrInactive)
	}

	if err := svc.Activate(t.Context(), client.ID); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if _, err := svc.Authenticate(t.Context(), plaintextKey); err != nil {
		t.Fatalf("Authenticate after Activate: unexpected error %v", err)
	}
}

func TestDeactivate_UnknownID(t *testing.T) {
	svc := newTestService(t)
	if err := svc.Deactivate(t.Context(), "00000000-0000-0000-0000-000000000000"); err != apiclient.ErrNotFound {
		t.Fatalf("err = %v, want %v", err, apiclient.ErrNotFound)
	}
}

func TestRotate_InvalidatesOldKeyIssuesNewOne(t *testing.T) {
	svc, pool := newTestServiceAndPool(t)
	client, oldKey := testutil.NewAPIClient(t, pool)

	newKey, err := svc.Rotate(t.Context(), client.ID)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if newKey == oldKey {
		t.Fatal("Rotate returned the same key as before")
	}

	if _, err := svc.Authenticate(t.Context(), oldKey); err != apiclient.ErrInvalidAPIKey {
		t.Fatalf("Authenticate with the old (rotated-out) key: err = %v, want %v", err, apiclient.ErrInvalidAPIKey)
	}
	got, err := svc.Authenticate(t.Context(), newKey)
	if err != nil {
		t.Fatalf("Authenticate with the new key: %v", err)
	}
	if got.ID != client.ID {
		t.Fatalf("Authenticate with the new key returned client %q, want %q (rotation must keep identity)", got.ID, client.ID)
	}
}

func TestRotate_UnknownID(t *testing.T) {
	svc := newTestService(t)
	if _, err := svc.Rotate(t.Context(), "00000000-0000-0000-0000-000000000000"); err != apiclient.ErrNotFound {
		t.Fatalf("err = %v, want %v", err, apiclient.ErrNotFound)
	}
}
