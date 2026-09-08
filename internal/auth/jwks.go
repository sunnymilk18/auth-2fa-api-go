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
func (h *Handlers) JWKS(w http.ResponseWriter, r *http.Request) {
	pub, kid := h.svc.PublicKey()

	resp := jwksResponse{Keys: []jwk{{
		Kty: "RSA",
		Use: "sig",
		Kid: kid,
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
