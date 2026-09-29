package middleware

import (
	"context"
	"net/http"
	"strings"

	"auth-2fa-api/internal/auth"
)

// RequireAuth validates the Bearer access token on protected routes and
// injects the authenticated user's id/email into the request context.
// accessRevocation additionally rejects a token that's otherwise
// perfectly valid (signature and expiry both fine) but was issued before
// the account's most recent ban/revoke-sessions/password-reset — see
// auth.AccessRevocationStore's doc comment for why a bare JWT check alone
// can't catch that on its own. Nilable: a deployment that never
// constructed one (shouldn't happen in practice — see auth.Service's own
// doc comment on why this isn't optional like totp/push) just skips this
// extra check, same as before it existed.
func RequireAuth(tokens *auth.TokenManager, accessRevocation *auth.AccessRevocationStore) func(http.Handler) http.Handler {
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

			if isAccessTokenRevoked(r.Context(), accessRevocation, claims) {
				http.Error(w, `{"error":"token inválido o expirado"}`, http.StatusUnauthorized)
				return
			}

			ctx := auth.ContextWithUser(r.Context(), claims.Subject, claims.Email)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// isAccessTokenRevoked fails open on a nil store, a token with no
// IssuedAt (shouldn't happen — TokenManager always sets one — but a nil
// pointer here must never panic the request), or a Redis error (same
// reasoning as RateLimiter/Blacklist: an outage here must not take down
// every authenticated request in the API).
func isAccessTokenRevoked(ctx context.Context, accessRevocation *auth.AccessRevocationStore, claims *auth.Claims) bool {
	if accessRevocation == nil || claims.IssuedAt == nil {
		return false
	}
	revoked, err := accessRevocation.IsRevoked(ctx, claims.Subject, claims.IssuedAt.Time)
	return err == nil && revoked
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
func OptionalAuth(tokens *auth.TokenManager, accessRevocation *auth.AccessRevocationStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			parts := strings.SplitN(header, " ", 2)
			if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
				// A revoked-but-otherwise-valid token is treated the same as
				// any other invalid one here — silently falls through with
				// no user context, same as a missing/expired/malformed
				// Bearer header, never a hard 401 (that's the whole point of
				// this being "optional").
				if claims, err := tokens.ParseAccessToken(parts[1]); err == nil && !isAccessTokenRevoked(r.Context(), accessRevocation, claims) {
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
