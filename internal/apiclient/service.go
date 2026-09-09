package apiclient

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

var (
	ErrInvalidAPIKey = errors.New("invalid api key")
	ErrInactive      = errors.New("api client is inactive")
)

type Service struct {
	repo *Repository
}

func NewService(repo *Repository) *Service {
	return &Service{repo: repo}
}

// Authenticate validates a plaintext API key (as received in the
// X-API-Key header) and returns the client it belongs to.
func (s *Service) Authenticate(ctx context.Context, apiKey string) (*APIClient, error) {
	client, err := s.repo.FindByAPIKeyHash(ctx, HashKey(apiKey))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrInvalidAPIKey
		}
		return nil, err
	}
	if !client.Active {
		return nil, ErrInactive
	}
	return client, nil
}

// Create provisions a new API client, generating a random key. The
// plaintext key is returned exactly once — only its hash is stored.
func (s *Service) Create(ctx context.Context, name string) (client *APIClient, plaintextKey string, err error) {
	plaintextKey, err = generateKey()
	if err != nil {
		return nil, "", fmt.Errorf("generating api key: %w", err)
	}
	client, err = s.repo.Create(ctx, name, HashKey(plaintextKey))
	if err != nil {
		return nil, "", err
	}
	return client, plaintextKey, nil
}

// List returns every api client, oldest first.
func (s *Service) List(ctx context.Context) ([]*APIClient, error) {
	return s.repo.List(ctx)
}

// Deactivate makes a client's key stop authenticating immediately, without
// deleting it (its users and their data stay put).
func (s *Service) Deactivate(ctx context.Context, id string) error {
	return s.repo.SetActive(ctx, id, false)
}

// Activate reverses a previous Deactivate.
func (s *Service) Activate(ctx context.Context, id string) error {
	return s.repo.SetActive(ctx, id, true)
}

// Rotate issues a fresh key for an existing client, invalidating the old
// one immediately — the client's identity (id, name, and every user
// scoped to it) is unchanged, only the credential is replaced. Like
// Create, the plaintext key is returned exactly once.
func (s *Service) Rotate(ctx context.Context, id string) (plaintextKey string, err error) {
	plaintextKey, err = generateKey()
	if err != nil {
		return "", fmt.Errorf("generating api key: %w", err)
	}
	if err := s.repo.UpdateKeyHash(ctx, id, HashKey(plaintextKey)); err != nil {
		return "", err
	}
	return plaintextKey, nil
}

// HashKey is a high-entropy-secret hash (like refresh/device tokens) —
// not bcrypt, since API keys are random and long, not low-entropy
// user-chosen secrets that need slow hashing.
func HashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func generateKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "sk_live_" + hex.EncodeToString(b), nil
}
