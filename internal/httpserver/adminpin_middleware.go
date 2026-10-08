package httpserver

import (
	"encoding/json"
	"fmt"
	"net/http"

	"auth-2fa-api/internal/adminauth"
	"auth-2fa-api/internal/adminctx"
	"auth-2fa-api/internal/audit"
	"auth-2fa-api/internal/middleware"
)

// AdminPinHeader is the header the panel sends the caller's own PIN on for
// a destructive /admin/* action — see requireAdminPin.
const AdminPinHeader = "X-Admin-Pin"

// writeJSONErrorCode is writeJSONError plus a machine-readable "code" field
// — used only by requireAdminPin below, where the panel needs to tell
// apart "no PIN header sent", "wrong PIN", and "this account has no PIN
// yet" to show the right screen, not just that something was refused.
func writeJSONErrorCode(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message, "code": code})
}

// requireAdminPin gates a destructive /admin/* route behind the caller's
// own PIN, confirmed fresh on every call — never cached in the session, so
// a stolen session alone is never enough for the routes this wraps. Chains
// after middleware.RequireAdminAccess, so adminctx.Actor is already set;
// the shared X-Admin-Token/script path (middleware.AdminActorToken) is
// exempt outright — it's not a person who could have a session stolen,
// and there's no "own PIN" for it to have. svc can be a nil
// *adminauth.Service (same reason router.go's sessionValidator can be
// nil): when it is, the only way RequireAdminAccess ever succeeded ahead
// of this is the token path, already handled above, so svc is never
// actually dereferenced in that case.
//
// A missing header, a wrong PIN, an account with no PIN configured yet,
// and a lockout from too many wrong PINs each get a distinct response
// (pin_required/pin_invalid/pin_not_set, or 429 with Retry-After) so the
// panel can show the right screen instead of a generic "forbidden" — see
// adminauth.Service.VerifyAdminPin's doc comment for where ok/notSet/
// retryAfter come from. A wrong PIN is also recorded as
// account.pin_failed — the one audit action this middleware itself
// writes; every PIN-gated route it wraps still logs its own action only
// on success, same as every other /admin/* route already does.
func requireAdminPin(svc *adminauth.Service, auditSvc *audit.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			actor, _ := adminctx.Actor(r.Context())
			if actor == middleware.AdminActorToken {
				next.ServeHTTP(w, r)
				return
			}

			pin := r.Header.Get(AdminPinHeader)
			if pin == "" {
				writeJSONErrorCode(w, http.StatusForbidden, "pin_required", "esta acción requiere confirmar tu PIN")
				return
			}

			ok, notSet, retryAfter, err := svc.VerifyAdminPin(r.Context(), actor, pin)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "no se pudo confirmar el PIN")
				return
			}
			if retryAfter > 0 {
				w.Header().Set("Retry-After", fmt.Sprintf("%.0f", retryAfter.Seconds()))
				writeJSONError(w, http.StatusTooManyRequests, "demasiados intentos fallidos, vuelve a intentar más tarde")
				return
			}
			if notSet {
				writeJSONErrorCode(w, http.StatusForbidden, "pin_not_set", "primero debes crear tu PIN")
				return
			}
			if !ok {
				role, _ := adminctx.Role(r.Context())
				auditSvc.Log(r.Context(), audit.Entry{
					ActorEmail: actor, ActorRole: role, Action: audit.ActionAccountPinFailed,
					TargetType: audit.TargetTypeAdminAccount, TargetLabel: actor,
					ActorIP: audit.RemoteIP(r),
				})
				writeJSONErrorCode(w, http.StatusForbidden, "pin_invalid", "el PIN no es correcto")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
