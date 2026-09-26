package middleware

import (
	"errors"
	"net/http"

	"auth-2fa-api/internal/apiclient"
	"auth-2fa-api/internal/auth"
)

// RequireSystemAdminToken validates the X-System-Admin-Token header against
// api_clients.system_admin_key_hash and injects the calling client's own id
// into the request context — the same context key RequireAPIKey uses (see
// auth.ContextWithAPIClient), since here too "the calling system's
// identity" is exactly the scope every downstream handler must enforce: a
// system-admin token can only ever act on its own tenant's users, never
// another tenant's. Deliberately separate from RequireAdminToken: that one
// authenticates the operator (unscoped, spans every tenant), this one
// authenticates a single tenant's own operators.
func RequireSystemAdminToken(svc *apiclient.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := r.Header.Get("X-System-Admin-Token")
			if key == "" {
				http.Error(w, `{"error":"falta el header X-System-Admin-Token"}`, http.StatusUnauthorized)
				return
			}

			client, err := svc.AuthenticateSystemAdmin(r.Context(), key)
			if err != nil {
				status := http.StatusUnauthorized
				msg := "credencial de administrador de sistema inválida"
				if errors.Is(err, apiclient.ErrInactive) {
					msg = "el cliente está inactivo"
				}
				http.Error(w, `{"error":"`+msg+`"}`, status)
				return
			}

			ctx := auth.ContextWithAPIClient(r.Context(), client.ID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
