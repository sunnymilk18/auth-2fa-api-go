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
	ctxAdminActorKey  contextKey = "adminActor"
	ctxAdminRoleKey   contextKey = "adminRole"
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

// ContextWithAdminActor attaches who is acting on an /admin/* request —
// set by middleware.RequireAdminAccess, read by handlers that want to log
// which specific admin (or "token", for the shared X-Admin-Token/script
// path) performed a destructive action. See that middleware's doc comment
// for why this exists alongside the plain X-Admin-Token check.
func ContextWithAdminActor(ctx context.Context, actor string) context.Context {
	return context.WithValue(ctx, ctxAdminActorKey, actor)
}

func AdminActorFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(ctxAdminActorKey).(string)
	return v, ok
}

// ContextWithAdminRole attaches the acting admin's permission tier
// ("admin" or "superadmin", or middleware.AdminRoleSuperAdmin for the
// shared X-Admin-Token/script path, which always has full access) — set
// by middleware.RequireAdminAccess, checked by middleware.RequireSuperAdmin
// for routes limited to the higher tier. See adminauth.Role's doc comment
// for what each tier can and can't do.
func ContextWithAdminRole(ctx context.Context, role string) context.Context {
	return context.WithValue(ctx, ctxAdminRoleKey, role)
}

func AdminRoleFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(ctxAdminRoleKey).(string)
	return v, ok
}
