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

// OptionalAuth is RequireAuth's non-rejecting sibling: if a valid Bearer
// token is present, it sets the same context RequireAuth would; if absent
// or invalid, the request just proceeds without that context, instead of
// failing with 401. Used only by auth.Handlers.EnrollTOTP/ConfirmTOTP,
// which accept EITHER an access token (changing method from an
// already-authenticated settings screen) OR a first-login setup token
// carried in the request body (see auth.Service.LoginStep1's doc comment)
// — the handler itself decides which mode applies by checking whether this
// middleware found a user in context, falling back to the body otherwise.
func OptionalAuth(tokens *auth.TokenManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			parts := strings.SplitN(header, " ", 2)
			if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
				if claims, err := tokens.ParseAccessToken(parts[1]); err == nil {
					ctx := auth.ContextWithUser(r.Context(), claims.Subject, claims.Email)
					r = r.WithContext(ctx)
				}
			}
			next.ServeHTTP(w, r)
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
