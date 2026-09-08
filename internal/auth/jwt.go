package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var ErrInvalidToken = errors.New("invalid or expired token")

// Claims embeds the user id ("sub") plus a token "type" so access and
// refresh tokens can't be swapped for one another even though they share
// a structure.
type Claims struct {
	jwt.RegisteredClaims
	Email     string `json:"email"`
	TokenType string `json:"type"` // "access" or "refresh"
}

type TokenManager struct {
	accessSecret  []byte
	refreshSecret []byte
	accessTTL     time.Duration
	refreshTTL    time.Duration
}

func NewTokenManager(accessSecret, refreshSecret string, accessTTL, refreshTTL time.Duration) *TokenManager {
	return &TokenManager{
		accessSecret:  []byte(accessSecret),
		refreshSecret: []byte(refreshSecret),
		accessTTL:     accessTTL,
		refreshTTL:    refreshTTL,
	}
}

func (tm *TokenManager) IssueAccessToken(userID, email string) (string, error) {
	return tm.issue(userID, email, "access", tm.accessSecret, tm.accessTTL)
}

func (tm *TokenManager) IssueRefreshToken(userID, email string) (string, error) {
	return tm.issue(userID, email, "refresh", tm.refreshSecret, tm.refreshTTL)
}

func (tm *TokenManager) issue(userID, email, tokenType string, secret []byte, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		Email:     email,
		TokenType: tokenType,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

func (tm *TokenManager) ParseAccessToken(tokenStr string) (*Claims, error) {
	return tm.parse(tokenStr, "access", tm.accessSecret)
}

func (tm *TokenManager) ParseRefreshToken(tokenStr string) (*Claims, error) {
	return tm.parse(tokenStr, "refresh", tm.refreshSecret)
}

func (tm *TokenManager) parse(tokenStr, expectedType string, secret []byte) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return secret, nil
	})
	if err != nil || !token.Valid {
		return nil, ErrInvalidToken
	}
	if claims.TokenType != expectedType {
		return nil, ErrInvalidToken
	}
	return claims, nil
}
