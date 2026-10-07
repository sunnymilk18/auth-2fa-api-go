package auth

import "context"

// Lives in the auth package (not middleware) so both the HTTP middleware
// that sets it and the auth handlers that read it can depend on it without
// creating an import cycle between auth and middleware.
type contextKey string

const (
	ctxUserIDKey      contextKey = "userID"
	ctxEmailKey       contextKey = "email"
	ctxAPIClientIDKey contextKey = "apiClientID"
)

// ContextWithUser attaches an authenticated user's id/email to ctx.
func ContextWithUser(ctx context.Context, userID, email string) context.Context {
	ctx = context.WithValue(ctx, ctxUserIDKey, userID)
	ctx = context.WithValue(ctx, ctxEmailKey, email)
	return ctx
}

func UserIDFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(ctxUserIDKey).(string)
	return v, ok
}

func EmailFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(ctxEmailKey).(string)
	return v, ok
}

// ContextWithAPIClient attaches the calling system's identity, set by the
// X-API-Key middleware and consumed by /auth/register and /auth/login.
func ContextWithAPIClient(ctx context.Context, apiClientID string) context.Context {
	return context.WithValue(ctx, ctxAPIClientIDKey, apiClientID)
}

func APIClientIDFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(ctxAPIClientIDKey).(string)
	return v, ok
}
