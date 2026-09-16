package testutil

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
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
	suffix := UniqueSuffix(t)
	email := "user-" + suffix + "@example.com"
	username := "user-" + suffix
	u, err := svc.Register(context.Background(), apiClientID, email, password, username, UniqueRUT(t))
	if err != nil {
		t.Fatalf("creating test user: %v", err)
	}

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, u.ID)
	})

	return u
}

// UniqueRUT returns a fresh, checksum-valid RUT (see user.NewRUT) with a
// random 8-digit body — collision-free the same way UniqueSuffix is.
func UniqueRUT(t *testing.T) string {
	t.Helper()
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("generating unique rut: %v", err)
	}
	// %08d over a uint32 mod 1e8 always yields exactly 8 digits.
	body := fmt.Sprintf("%08d", binary.BigEndian.Uint32(b[:])%100000000)
	return user.NewRUT(body)
}
