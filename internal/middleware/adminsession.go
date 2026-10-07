package middleware

import (
	"context"
	"crypto/subtle"
	"net/http"

	"auth-2fa-api/internal/adminctx"
)

// AdminSessionCookieName is the httpOnly cookie RequireAdminAccess reads
// and the login/logout handlers set/clear — not exported as a constant
// string literal anywhere else, so a rename only ever happens here.
const AdminSessionCookieName = "admin_session"

// AdminPanelHeader is the CSRF mitigation required alongside the session
// cookie while it's SameSite=None (see httpserver.adminAuthHandlers'
// cookieSameSite doc comment for why it's None at all, for now) — a
// cross-site attacker can make a victim's browser *send* a simple request
// with the cookie attached (that's exactly what SameSite=None allows), but
// can't make it carry an arbitrary custom header: only JavaScript already
// running on the panel's own origin can set one, and that origin is the
// only one the panel's CORS allows credentialed requests from to begin
// with. A plain cross-site <form> POST — the classic CSRF vector — simply
// can't produce this header, so requiring it closes the gap SameSite=None
// reopens. Becomes redundant (but harmless to leave on) once the cookie
// itself goes back to SameSite=Strict on a shared real domain.
const AdminPanelHeader = "X-Admin-Panel"

// AdminActorToken is the sentinel RequireAdminAccess records via
// adminctx.WithActor for the X-Admin-Token/script path, which has
// no individual admin email to attribute an action to — exported so a
// handler can tell that case apart from a real admin's email (e.g.
// httpserver.adminAuthHandlers.RevokeAccount, which only enforces its
// "can't revoke yourself" rule when the actor is an actual logged-in
// admin).
const AdminActorToken = "token"

// AdminRoleSuperAdmin is the role string RequireSuperAdmin checks for —
// must stay equal to string(adminauth.RoleSuperAdmin), since middleware
// deliberately doesn't import the adminauth package (see
// AdminSessionValidator's doc comment) and so can't reference that
// constant directly. Also what RequireAdminAccess assigns the
// X-Admin-Token/script path: that shared credential already has
// unrestricted access to everything, same as a superadmin.
const AdminRoleSuperAdmin = "superadmin"

// AdminSessionValidator is the one method RequireAdminAccess needs from
// adminauth.Service — a narrow interface here (rather than importing that
// whole package into middleware) keeps this package's existing dependency
// shape: it already depends on auth and apiclient, never on a sibling
// feature package. role is a plain string for the same reason — see
// adminauth.Service.ValidateSession's own doc comment.
type AdminSessionValidator interface {
	ValidateSession(ctx context.Context, token string) (email string, role string, ok bool, err error)
}

// RequireAdminAccess gates /admin/* behind either credential: the shared
// X-Admin-Token (scripts/automation — see RequireAdminToken, which this
// reimplements inline rather than wrapping, since only one of the two
// checks should ever reject the request) or a valid admin_session cookie
// (the panel, after a human logs in via adminauth.Service.Login). Exactly
// one needs to succeed. adminctx.WithActor records which path
// succeeded ("token", or the admin's own email) so handlers can log who
// actually performed a destructive action — see that function's doc
// comment for why that distinction matters now that /admin/* isn't only
// reachable with one shared secret. adminctx.WithRole records the
// permission tier ("admin"/"superadmin", or AdminRoleSuperAdmin for the
// token path) that RequireSuperAdmin checks for routes limited to
// superadmins — see adminauth.Role's doc comment for what each tier means.
func RequireAdminAccess(token string, sessions AdminSessionValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("X-Admin-Token"); got != "" && token != "" &&
				subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1 {
				ctx := adminctx.WithActor(r.Context(), AdminActorToken)
				ctx = adminctx.WithRole(ctx, AdminRoleSuperAdmin)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			if cookie, err := r.Cookie(AdminSessionCookieName); sessions != nil && err == nil && cookie.Value != "" && r.Header.Get(AdminPanelHeader) != "" {
				if email, role, ok, err := sessions.ValidateSession(r.Context(), cookie.Value); err == nil && ok {
					ctx := adminctx.WithActor(r.Context(), email)
					ctx = adminctx.WithRole(ctx, role)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			http.Error(w, `{"error":"token de administrador inválido o faltante"}`, http.StatusUnauthorized)
		})
	}
}

// RequireSuperAdmin chains after RequireAdminAccess to further restrict a
// route to the superadmin tier — see adminauth.Role's doc comment for
// which routes that applies to (admin-account management,
// tenant/api_client management, and the IP allowlist: the three
// categories that affect "who has access at all" or "which systems/IPs
// are trusted platform-wide"). Always passes for the X-Admin-Token/script
// path, which RequireAdminAccess already marks AdminRoleSuperAdmin.
func RequireSuperAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if role, ok := adminctx.Role(r.Context()); ok && role == AdminRoleSuperAdmin {
			next.ServeHTTP(w, r)
			return
		}
		http.Error(w, `{"error":"esta acción requiere permisos de superadministrador"}`, http.StatusForbidden)
	})
}
