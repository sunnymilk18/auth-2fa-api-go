package middleware

import (
	"context"
	"net/http"
	"strings"

	"auth-2fa-api/internal/auth"
)

// RequireAuth validates the Bearer access token on protected routes and
// injects the authenticated user's id/email into the request context.
func RequireAuth(tokens *auth.TokenManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			parts := strings.SplitN(header, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
				http.Error(w, `{"error":"falta el header Authorization o tiene un formato inválido"}`, http.StatusUnauthorized)
				return
			}

			claims, err := tokens.ParseAccessToken(parts[1])
			if err != nil {
				http.Error(w, `{"error":"token inválido o expirado"}`, http.StatusUnauthorized)
				return
			}

			ctx := auth.ContextWithUser(r.Context(), claims.Subject, claims.Email)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// UserIDFromContext and EmailFromContext are thin re-exports of the auth
// package's context helpers, kept here so existing callers importing
// middleware don't need to change.
func UserIDFromContext(ctx context.Context) (string, bool) {
	return auth.UserIDFromContext(ctx)
}

func EmailFromContext(ctx context.Context) (string, bool) {
	return auth.EmailFromContext(ctx)
}
