package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var ErrInvalidToken = errors.New("invalid or expired token")

// Claims embeds the user id ("sub") plus a token "type" so access and
// refresh tokens can't be swapped for one another even though they share
// a structure.
type Claims struct {
	jwt.RegisteredClaims
	Email       string `json:"email"`
	APIClientID string `json:"client_id"` // which consuming system this session belongs to
	TokenType   string `json:"type"`      // "access" or "refresh"
}

// TokenManager issues and validates two kinds of tokens:
//   - Access tokens: signed with RS256 (private key). Any external system
//     can verify them on its own using only the public key (see the JWKS
//     endpoint) — no call back to this API required.
//   - Refresh tokens: signed with HS256 (shared secret). These are only
//     ever presented back to this API's own /auth/refresh endpoint, so a
//     symmetric secret is simpler and just as safe here.
type TokenManager struct {
	accessPrivateKey *rsa.PrivateKey
	accessPublicKey  *rsa.PublicKey
	accessKeyID      string
	refreshSecret    []byte
	accessTTL        time.Duration
	refreshTTL       time.Duration
}

func NewTokenManager(accessPrivateKey *rsa.PrivateKey, accessKeyID, refreshSecret string, accessTTL, refreshTTL time.Duration) *TokenManager {
	return &TokenManager{
		accessPrivateKey: accessPrivateKey,
		accessPublicKey:  &accessPrivateKey.PublicKey,
		accessKeyID:      accessKeyID,
		refreshSecret:    []byte(refreshSecret),
		accessTTL:        accessTTL,
		refreshTTL:       refreshTTL,
	}
}

func (tm *TokenManager) IssueAccessToken(userID, apiClientID, email string) (string, error) {
	claims := tm.newClaims(userID, apiClientID, email, "access", tm.accessTTL)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = tm.accessKeyID
	return token.SignedString(tm.accessPrivateKey)
}

func (tm *TokenManager) IssueRefreshToken(userID, apiClientID, email string) (string, error) {
	claims := tm.newClaims(userID, apiClientID, email, "refresh", tm.refreshTTL)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(tm.refreshSecret)
}

func (tm *TokenManager) newClaims(userID, apiClientID, email, tokenType string, ttl time.Duration) Claims {
	now := time.Now()
	return Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			ID:        newJTI(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		Email:       email,
		APIClientID: apiClientID,
		TokenType:   tokenType,
	}
}

// newJTI generates a random JWT ID. IssuedAt/ExpiresAt are only
// second-precision, so two tokens for the same user issued within the same
// second would otherwise be byte-for-byte identical (and collide on
// refresh_tokens.token_hash, which is UNIQUE) without this.
func newJTI() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand.Read on the standard reader only fails if the OS RNG
		// itself is broken — nothing a caller could sensibly recover from.
		panic(fmt.Sprintf("auth: reading random bytes for jti: %v", err))
	}
	return hex.EncodeToString(b)
}

func (tm *TokenManager) ParseAccessToken(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, ErrInvalidToken
		}
		return tm.accessPublicKey, nil
	})
	if err != nil || !token.Valid || claims.TokenType != "access" {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

func (tm *TokenManager) ParseRefreshToken(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return tm.refreshSecret, nil
	})
	if err != nil || !token.Valid || claims.TokenType != "refresh" {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

// PublicKey exposes the RSA public key and its key id, used to publish the
// JWKS document that other systems fetch to verify access tokens.
func (tm *TokenManager) PublicKey() (*rsa.PublicKey, string) {
	return tm.accessPublicKey, tm.accessKeyID
}
