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
//
// Access token verification is keyed by kid, not tied to a single key —
// see AddVerificationKey's doc comment for why: rotating the signing key
// needs the *previous* one to stay verifiable for a while, so tokens
// issued right before the rotation don't fail mid-flight.
type TokenManager struct {
	signingKey    *rsa.PrivateKey
	signingKeyID  string
	verifyKeys    map[string]*rsa.PublicKey // kid -> public key; always includes signingKey's own
	refreshSecret []byte
	accessTTL     time.Duration
	refreshTTL    time.Duration
}

func NewTokenManager(accessPrivateKey *rsa.PrivateKey, accessKeyID, refreshSecret string, accessTTL, refreshTTL time.Duration) *TokenManager {
	return &TokenManager{
		signingKey:    accessPrivateKey,
		signingKeyID:  accessKeyID,
		verifyKeys:    map[string]*rsa.PublicKey{accessKeyID: &accessPrivateKey.PublicKey},
		refreshSecret: []byte(refreshSecret),
		accessTTL:     accessTTL,
		refreshTTL:    refreshTTL,
	}
}

// AddVerificationKey registers an additional public key access tokens may
// be verified against, without making it the signing key — used during a
// JWT key rotation: once a new key takes over signing (a fresh
// TokenManager, built with the new key via NewTokenManager), the
// *previous* signing key's public half gets added here so tokens issued
// with it right before the rotation (still valid for up to accessTTL)
// keep verifying instead of suddenly failing. Once that window has safely
// passed, the operator stops calling this for the old key on the next
// deploy and it drops out of the verification set — see README's
// "Rotación de claves JWT".
func (tm *TokenManager) AddVerificationKey(kid string, pub *rsa.PublicKey) {
	tm.verifyKeys[kid] = pub
}

func (tm *TokenManager) IssueAccessToken(userID, apiClientID, email string) (string, error) {
	claims := tm.newClaims(userID, apiClientID, email, "access", tm.accessTTL)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = tm.signingKeyID
	return token.SignedString(tm.signingKey)
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

// ParseAccessToken looks up the verification key by the token's own "kid"
// header (see AddVerificationKey) rather than assuming there's only one —
// an unrecognized kid (e.g. a key retired after its rotation window ended)
// is treated the same as any other invalid token.
func (tm *TokenManager) ParseAccessToken(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, ErrInvalidToken
		}
		kid, _ := t.Header["kid"].(string)
		pub, ok := tm.verifyKeys[kid]
		if !ok {
			return nil, ErrInvalidToken
		}
		return pub, nil
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

// PublicKeys exposes every public key access tokens can currently be
// verified against (normally just one — more only during a key rotation's
// overlap window), for publishing as JWKS.
func (tm *TokenManager) PublicKeys() map[string]*rsa.PublicKey {
	return tm.verifyKeys
}
