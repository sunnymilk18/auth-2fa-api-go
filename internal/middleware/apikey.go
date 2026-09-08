package middleware

import (
	"errors"
	"net/http"

	"auth-2fa-api/internal/apiclient"
	"auth-2fa-api/internal/auth"
)

// RequireAPIKey validates the X-API-Key header against api_clients and
// injects the calling system's identity into the request context — used
// by /auth/register and /auth/login to scope users to the right tenant.
func RequireAPIKey(svc *apiclient.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := r.Header.Get("X-API-Key")
			if key == "" {
				http.Error(w, `{"error":"missing X-API-Key header"}`, http.StatusUnauthorized)
				return
			}

			client, err := svc.Authenticate(r.Context(), key)
			if err != nil {
				status := http.StatusUnauthorized
				msg := "invalid api key"
				if errors.Is(err, apiclient.ErrInactive) {
					msg = "api key is inactive"
				}
				http.Error(w, `{"error":"`+msg+`"}`, status)
				return
			}

			ctx := auth.ContextWithAPIClient(r.Context(), client.ID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
