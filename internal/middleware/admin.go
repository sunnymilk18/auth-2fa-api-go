package middleware

import (
	"crypto/subtle"
	"net/http"
)

// RequireAdminToken gates operator-only routes (provisioning api_clients
// over HTTP) behind a single fixed secret — deliberately separate from
// RequireAPIKey: that one authenticates a *tenant*, this authenticates
// *you*, the operator, and tenants must never be able to provision other
// tenants themselves.
//
// token == "" (ADMIN_API_TOKEN unset) disables the routes entirely rather
// than accepting no token or an empty header — the caller wires this up
// only when token is non-empty (see router.go), so reaching this
// middleware at all with an empty configured token would itself be a
// wiring bug, not a valid "no auth required" state.
func RequireAdminToken(token string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got := r.Header.Get("X-Admin-Token")
			// ConstantTimeCompare needs equal-length inputs to avoid leaking
			// length via timing; a plain []byte(token) comparison already
			// isn't length-hiding either way once got is empty/wrong length,
			// but this keeps the comparison itself from short-circuiting on
			// the common case (empty header) any faster than the real one.
			if token == "" || got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
				http.Error(w, `{"error":"token de administrador inválido o faltante"}`, http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
