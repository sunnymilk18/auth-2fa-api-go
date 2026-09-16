package auth

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
)

// jwk is a single JSON Web Key (RFC 7517) describing an RSA public key.
type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwksResponse struct {
	Keys []jwk `json:"keys"`
}

// JWKS serves this API's public key set. Any system that receives an access
// token from a client can fetch this endpoint, cache it, and verify the
// token's RS256 signature entirely on its own — no call back to this API.
//
// Normally a single key. More than one only appears during a JWT key
// rotation's overlap window (see TokenManager.AddVerificationKey) — a
// verifier is expected to pick the entry matching the token's own "kid"
// header, not just take the first one, exactly like ParseAccessToken does
// internally.
func (h *Handlers) JWKS(w http.ResponseWriter, r *http.Request) {
	keys := h.svc.PublicKeys()

	resp := jwksResponse{Keys: make([]jwk, 0, len(keys))}
	for kid, pub := range keys {
		resp.Keys = append(resp.Keys, jwk{
			Kty: "RSA",
			Use: "sig",
			Kid: kid,
			Alg: "RS256",
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
