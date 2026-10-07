// Package adminctx holds the two admin-session context values — who is
// acting on an /admin/* request (an admin's own email, or
// middleware.AdminActorToken for the shared X-Admin-Token/script path)
// and their permission tier ("admin"/"superadmin") — set once by
// middleware.RequireAdminAccess and read by any handler, in any package,
// that needs to attribute or gate an action.
//
// Deliberately its OWN leaf package, not part of internal/auth or
// internal/middleware: internal/middleware already imports internal/auth
// and internal/apiclient, and internal/auth already imports
// internal/apiclient — so a handler package that itself needs to read
// these values (internal/apiclient's own /admin/clients handlers, for the
// audit log) can't safely import either auth or middleware without
// risking a cycle. This package imports nothing beyond "context", so
// anything can depend on it.
package adminctx

import "context"

type contextKey string

const (
	actorKey contextKey = "adminActor"
	roleKey  contextKey = "adminRole"
)

// WithActor attaches who is acting on an /admin/* request.
func WithActor(ctx context.Context, actor string) context.Context {
	return context.WithValue(ctx, actorKey, actor)
}

// Actor returns the acting admin's email, or middleware.AdminActorToken
// for the shared X-Admin-Token/script path — ok is false if nothing was
// ever set (a request that never went through middleware.
// RequireAdminAccess at all, e.g. a /system-admin/* request).
func Actor(ctx context.Context) (actor string, ok bool) {
	v, ok := ctx.Value(actorKey).(string)
	return v, ok
}

// WithRole attaches the acting admin's permission tier.
func WithRole(ctx context.Context, role string) context.Context {
	return context.WithValue(ctx, roleKey, role)
}

// Role returns the acting admin's permission tier ("admin"/"superadmin",
// or middleware.AdminRoleSuperAdmin for the shared X-Admin-Token/script
// path) — ok is false under the same conditions as Actor.
func Role(ctx context.Context) (role string, ok bool) {
	v, ok := ctx.Value(roleKey).(string)
	return v, ok
}
