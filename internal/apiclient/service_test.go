package apiclient_test

import (
	"strings"
	"testing"

	"auth-2fa-api/internal/apiclient"
	"auth-2fa-api/internal/testutil"
)

func newTestService(t *testing.T) *apiclient.Service {
	t.Helper()
	pool := testutil.PostgresPool(t)
	return apiclient.NewService(apiclient.NewRepository(pool))
}

func TestCreate_GeneratesUniqueKeys(t *testing.T) {
	svc := newTestService(t)

	const n = 100
	seenKeys := make(map[string]bool, n)
	seenHashes := make(map[string]bool, n)

	for i := 0; i < n; i++ {
		client, plaintextKey, err := svc.Create(t.Context(), "test-"+testutil.UniqueSuffix(t))
		if err != nil {
			t.Fatalf("Create #%d: %v", i, err)
		}
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
	svc := newTestService(t)

	client, plaintextKey, err := svc.Create(t.Context(), "test-"+testutil.UniqueSuffix(t))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if client.APIKeyHash == plaintextKey {
		t.Fatal("stored api_key_hash equals the plaintext key — it must be hashed")
	}
	if client.APIKeyHash != apiclient.HashKey(plaintextKey) {
		t.Fatalf("stored hash %q != HashKey(plaintext) %q", client.APIKeyHash, apiclient.HashKey(plaintextKey))
	}
}

func TestAuthenticate_RoundTrip(t *testing.T) {
	svc := newTestService(t)
	created, plaintextKey, err := svc.Create(t.Context(), "test-"+testutil.UniqueSuffix(t))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

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
	pool := testutil.PostgresPool(t)
	svc := apiclient.NewService(apiclient.NewRepository(pool))
	client, plaintextKey := testutil.NewAPIClient(t, pool)

	if _, err := pool.Exec(t.Context(), `UPDATE api_clients SET active = FALSE WHERE id = $1`, client.ID); err != nil {
		t.Fatalf("deactivating test client: %v", err)
	}

	if _, err := svc.Authenticate(t.Context(), plaintextKey); err != apiclient.ErrInactive {
		t.Fatalf("err = %v, want %v", err, apiclient.ErrInactive)
	}
}
