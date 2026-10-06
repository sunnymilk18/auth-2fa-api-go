package httpserver

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/metric"

	"auth-2fa-api/internal/adminauth"
	"auth-2fa-api/internal/apiclient"
	"auth-2fa-api/internal/auth"
	"auth-2fa-api/internal/middleware"
	"auth-2fa-api/internal/user"
)

// NewRouter wires all routes: public auth endpoints, API docs, and a sample
// protected endpoint that any consuming system can imitate to guard its own
// routes. meter is a no-op if telemetry.SetupMetrics was never called (or
// ran with no OTLP endpoint configured) — callers never need to check.
// adminToken == "" leaves /admin/* unregistered entirely (404, not "open
// with no auth") — see middleware.RequireAdminToken. /system-admin/* is
// unaffected by adminToken: it's always registered, gated per-client by
// whether that client has its own scoped key provisioned (see
// middleware.RequireSystemAdminToken).
// totpEnabled controls whether /auth/totp/* is registered at all — see
// config.Config.TOTPEncryptionKeyBase64's doc comment: unset means the
// feature doesn't exist here (404, not "exists but always fails"), same
// pattern as adminToken == "" for /admin/*.
// pushEnabled controls whether the push-notification login-approval routes
// are registered at all — same opt-in-at-deployment pattern as totpEnabled
// (see config.Config.FirebaseCredentialsPath's doc comment): unset means
// 404, not "exists but always fails".
// trustedProxyCIDRs is the validated (already-parsed, invalid entries
// already dropped by the caller — see middleware.ValidateTrustedProxyCIDRs)
// form of TRUSTED_PROXY_CIDRS. Empty means trust nothing: chi's
// ClientIPFromXFF middleware isn't registered at all in that case, so
// middleware.ClientIP falls back to the real RemoteAddr for every request,
// same as if this parameter didn't exist.
// banReferenceSecret derives the short "reference" code /system-admin/
// blacklist shows for a ban instead of the raw IP — see middleware.
// Blacklist.Reference's doc comment. nil/empty disables it (omitted from
// responses, not a startup failure).
// adminAccounts backs the operator panel's own individual login — see
// adminauth.Service's doc comment. adminPanelOrigin == "" leaves
// /admin/auth/* and /admin/accounts/* unregistered (same opt-in-or-404
// pattern as adminToken == "" for /admin/* as a whole), and makes
// /admin/clients, /admin/users and /admin/blacklist fall back to the same
// wildcard, no-credentials CORS they always had — see config.Config.
// AdminPanelOrigin's doc comment. adminSessionCrossSite/adminSessionTTL
// configure the panel session cookie — see config.Config's own fields.
func NewRouter(authHandlers *auth.Handlers, authSvc *auth.Service, tokens *auth.TokenManager, accessRevocation *auth.AccessRevocationStore, users *user.Service, pgPool *pgxpool.Pool, rdb *redis.Client, apiClients *apiclient.Service, meter metric.Meter, adminToken string, totpEnabled bool, pushEnabled bool, trustedProxyCIDRs []string, banReferenceSecret []byte, adminAccounts *adminauth.Service, adminPanelOrigin string, adminSessionCrossSite bool, adminSessionTTL time.Duration, logger *slog.Logger) http.Handler {
	r := chi.NewRouter()

	// Any origin, no credentials: this is a header/token API (X-API-Key,
	// Bearer), never cookies — so there's no session to leak by allowing
	// "*", and each consuming system's own frontend can live at whatever
	// domain it wants without us maintaining an allowlist per tenant.
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions},
		AllowedHeaders:   []string{"Content-Type", "Authorization", "X-API-Key", "X-Admin-Token", "X-System-Admin-Token"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	r.Use(chimw.RequestID)

	// Resolves the real client IP from X-Forwarded-For, walking it
	// right-to-left and skipping any hop inside trustedProxyCIDRs — the
	// opposite of chi's own chimw.RealIP (deliberately NOT used here: it's
	// deprecated upstream as vulnerable to IP spoofing, GHSA-3fxj-6jh8-hvhx/
	// GHSA-rjr7-jggh-pgcp/GHSA-9g5q-2w5x-hmxf — it blindly trusts the
	// leftmost XFF value, or True-Client-IP/X-Real-IP, from ANY request,
	// letting anyone dodge the rate limits and the IP blacklist just by
	// setting a header). Read via middleware.ClientIP, never r.RemoteAddr
	// directly. Only registered when there's actually something to trust —
	// with nothing configured, no middleware here at all, so RemoteAddr
	// (the real TCP peer) is what every request resolves to, same as if
	// TRUSTED_PROXY_CIDRS never existed.
	if len(trustedProxyCIDRs) > 0 {
		r.Use(chimw.ClientIPFromXFF(trustedProxyCIDRs...))
	}

	r.Use(middleware.RequestLogger(logger))
	r.Use(chimw.Recoverer)
	r.Use(chimw.Timeout(15 * time.Second))
	r.Use(middleware.Metrics(meter))

	// Escalates a client IP that keeps tripping the rate limits declared
	// below into a standalone ban: 3 denials within 24h bans it outright,
	// 24h the first time, 72h the second, 7 days from the third on — see
	// middleware.Blacklist's doc comment for why it resets after 30 days of
	// good behavior instead of climbing forever. Registered globally here
	// (chi requires every Use before any route) so a banned IP never
	// reaches any route at all, rate-limited or not.
	blacklist := middleware.NewBlacklist(rdb,
		3, 24*time.Hour,
		[]time.Duration{24 * time.Hour, 72 * time.Hour, 7 * 24 * time.Hour},
		30*24*time.Hour,
		banReferenceSecret,
	)
	r.Use(blacklist.Middleware)
	blHandlers := &blacklistHandlers{bl: blacklist, logger: logger}

	// Actually checks both dependencies rather than always claiming "ok" —
	// an orchestrator (k8s liveness/readiness, a load balancer's health
	// check) relying on this to detect an outage needs it to be true.
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()

		status := "ok"
		code := http.StatusOK
		if err := pgPool.Ping(ctx); err != nil {
			status = "postgres unreachable"
			code = http.StatusServiceUnavailable
		} else if err := rdb.Ping(ctx).Err(); err != nil {
			status = "redis unreachable"
			code = http.StatusServiceUnavailable
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": status})
	})

	// Publishes the RS256 public key so any consuming system can verify
	// access tokens on its own, without calling back to this API.
	r.Get("/.well-known/jwks.json", authHandlers.JWKS)

	// API documentation (OpenAPI/Swagger).
	r.Get("/openapi.yaml", serveOpenAPISpec)
	r.Get("/docs", serveDocs)

	// Rate limits blunt brute-force attempts against credentials, OTP codes
	// and device PINs. Fixed windows, keyed by client IP, backed by Redis.
	// Each is wired into the shared blacklist above: repeatedly tripping
	// any one of them (or a mix of several) counts toward the same ban.
	registerLimiter := middleware.NewRateLimiter(rdb, "register", 10, time.Hour).AttachBlacklist(blacklist)
	loginLimiter := middleware.NewRateLimiter(rdb, "login", 20, 15*time.Minute).AttachBlacklist(blacklist)
	otpLimiter := middleware.NewRateLimiter(rdb, "verify-otp", 30, 15*time.Minute).AttachBlacklist(blacklist)
	deviceLoginLimiter := middleware.NewRateLimiter(rdb, "device-login", 30, 15*time.Minute).AttachBlacklist(blacklist)
	passwordResetRequestLimiter := middleware.NewRateLimiter(rdb, "password-reset-request", 5, time.Hour).AttachBlacklist(blacklist)
	passwordResetConfirmLimiter := middleware.NewRateLimiter(rdb, "password-reset-confirm", 10, 15*time.Minute).AttachBlacklist(blacklist)
	verifyEmailConfirmLimiter := middleware.NewRateLimiter(rdb, "verify-email-confirm", 10, 15*time.Minute).AttachBlacklist(blacklist)
	changeEmailConfirmLimiter := middleware.NewRateLimiter(rdb, "change-email-confirm", 10, 15*time.Minute).AttachBlacklist(blacklist)
	verifyEmailResendLimiter := middleware.NewRateLimiter(rdb, "verify-email-resend", 5, time.Hour).AttachBlacklist(blacklist)
	totpConfirmLimiter := middleware.NewRateLimiter(rdb, "totp-confirm", 10, 15*time.Minute).AttachBlacklist(blacklist)
	sendLoginEmailCodeLimiter := middleware.NewRateLimiter(rdb, "login-send-email-code", 10, 15*time.Minute).AttachBlacklist(blacklist)
	requestLoginEmailCodeLimiter := middleware.NewRateLimiter(rdb, "login-request-email-code", 10, 15*time.Minute).AttachBlacklist(blacklist)
	resendLoginCodeLimiter := middleware.NewRateLimiter(rdb, "login-resend-code", 5, time.Hour).AttachBlacklist(blacklist)
	// Legitimate use rarely needs more than one refresh per ACCESS_TOKEN_TTL
	// window per device — 30/15min leaves plenty of room for several
	// devices/tabs on the same account plus the occasional retry, while
	// still shutting down a loop hammering this endpoint with one stolen or
	// otherwise-valid refresh token (this was the one /auth/* route with no
	// rate limit at all before this).
	refreshLimiter := middleware.NewRateLimiter(rdb, "refresh", 30, 15*time.Minute).AttachBlacklist(blacklist)
	// Keyed by login_token (see loginTokenKey below), not by IP like every
	// limiter above — /auth/login/push-status is polled every ~2s for up to
	// PUSH_LOGIN_TTL (60s default), so a single wait alone can cost up to
	// ~30 requests. Sharing an IP-wide budget with otpLimiter (as this used
	// to) meant one or two login attempts from the same IP could nearly
	// exhaust it for everyone behind that IP — including different users
	// polling entirely unrelated logins through the same consuming
	// system's backend. Keying by login_token instead gives every login
	// attempt its own isolated budget that expires with the token itself,
	// so 100 here isn't "generous", it's just headroom for that one
	// attempt (a stray extra tab polling the same token, a slow retry)
	// with no cost to raising it: nothing outlives the token's own 60s
	// regardless of this limit.
	pushStatusLimiter := middleware.NewRateLimiter(rdb, "login-push-status", 100, 15*time.Minute).AttachBlacklist(blacklist)
	// On top of the account-level PIN lockout (user.Service.VerifyPin) —
	// these just bound raw request volume against the endpoint itself, same
	// reasoning as every other limiter here. The account-level lockout
	// alone only throttles guesses against ONE account; an attacker with
	// several stolen access tokens could otherwise spray PIN guesses across
	// many different accounts from the same IP without ever tripping any
	// single account's own counter — these catch that.
	pinVerifyLimiter := middleware.NewRateLimiter(rdb, "pin-verify", 30, 15*time.Minute).AttachBlacklist(blacklist)
	pinSetLimiter := middleware.NewRateLimiter(rdb, "pin-set", 30, 15*time.Minute).AttachBlacklist(blacklist)
	deviceRegisterLimiter := middleware.NewRateLimiter(rdb, "device-register", 30, 15*time.Minute).AttachBlacklist(blacklist)
	// Same reasoning as pinVerifyLimiter — a request volume bound on top of
	// the account-level PIN lockout, not a replacement for it.
	loginPinLimiter := middleware.NewRateLimiter(rdb, "login-pin", 30, 15*time.Minute).AttachBlacklist(blacklist)

	r.Route("/auth", func(r chi.Router) {
		// Every /auth/* call must identify which consuming system it's from —
		// used to keep each system's users isolated from the others.
		r.Use(middleware.RequireAPIKey(apiClients))

		r.With(registerLimiter.Middleware).Post("/register", authHandlers.Register)
		r.With(loginLimiter.Middleware).Post("/login", authHandlers.Login)
		r.With(otpLimiter.Middleware).Post("/verify-otp", authHandlers.VerifyOTP)

		// Completes a login VerifyOTP/ConfirmTOTP/PushLoginStatus reported
		// pin_required for (see LoginResult) — an account with
		// PinRequiredAtLogin gets no tokens from any of those until this
		// also succeeds. Public like them (X-API-Key only, no Bearer yet).
		r.With(loginPinLimiter.Middleware).Post("/login/pin", authHandlers.LoginPin)

		r.With(refreshLimiter.Middleware).Post("/refresh", authHandlers.Refresh)
		r.Post("/logout", authHandlers.Logout)

		// Trusted device + PIN: a returning device can log in with this
		// instead of password+OTP. A brand new device always fails here and
		// must go through the flow above first.
		r.With(deviceLoginLimiter.Middleware).Post("/devices/login", authHandlers.DeviceLogin)

		// "No recibí el código" recovery for a plain email login already in
		// progress (see auth.Service.ResendLoginOTP's doc comment) — always
		// available, unlike request-email-code, since the emailed OTP is the
		// core login path, not an opt-in feature.
		r.With(resendLoginCodeLimiter.Middleware).Post("/login/resend-code", authHandlers.ResendLoginCode)

		if pushEnabled {
			// Polled by the PC (~every 2s) while the phone hasn't answered
			// yet — identified only by login_token, same as /auth/verify-otp:
			// no Bearer token exists on the PC side of a push login either.
			// Rate-limited by that same login_token (see pushStatusLimiter's
			// own comment above), not by IP.
			r.With(pushStatusLimiter.MiddlewareByKey(loginTokenQueryKey)).Get("/login/push-status", authHandlers.PushLoginStatus)

			// The "usar otro método" fallback for a login that only offered
			// push (see auth.Service.LoginStep1's doc comment: the OTP isn't
			// emailed up front in that case) — only meaningful when push is
			// actually enabled, same reasoning as push-status above.
			r.With(requestLoginEmailCodeLimiter.Middleware).Post("/login/request-email-code", authHandlers.RequestLoginEmailCode)
		}

		r.With(passwordResetRequestLimiter.Middleware).Post("/password-reset/request", authHandlers.RequestPasswordReset)
		r.With(passwordResetConfirmLimiter.Middleware).Post("/password-reset/confirm", authHandlers.ConfirmPasswordReset)

		r.With(verifyEmailConfirmLimiter.Middleware).Post("/verify-email/confirm", authHandlers.ConfirmEmailVerification)
		r.With(verifyEmailResendLimiter.Middleware).Post("/verify-email/resend", authHandlers.ResendEmailVerification)

		// Confirms an email correction an admin started — see
		// AdminHandlers.ChangeEmail (under /system-admin/users below) and
		// Handlers.ConfirmChangeEmail's own doc comment for why this is
		// public: the admin never sees the code, only the account itself
		// (proving control of its new address) can apply the change.
		r.With(changeEmailConfirmLimiter.Middleware).Post("/change-email/confirm", authHandlers.ConfirmChangeEmail)

		if totpEnabled {
			// First-login "choose email or authenticator" screen (see
			// auth.Service.LoginStep1's doc comment) — the "email" branch.
			// No Bearer token exists yet at this point, only the pending
			// setup login_token from /auth/login.
			r.With(sendLoginEmailCodeLimiter.Middleware).Post("/login/send-email-code", authHandlers.SendLoginEmailCode)

			// Authenticator app (Google Authenticator, Authy, etc.) as an
			// opt-in alternative to the emailed OTP. EnrollTOTP/ConfirmTOTP
			// accept EITHER a Bearer token (changing method later, from an
			// already-authenticated settings screen) OR a login_token (the
			// first-login setup flow's "authenticator" branch — no Bearer
			// exists yet) — see middleware.OptionalAuth and auth.Handlers.
			// EnrollTOTP's doc comments. Only registered when the server
			// has TOTP_ENCRYPTION_KEY configured.
			r.Group(func(r chi.Router) {
				r.Use(middleware.OptionalAuth(tokens, accessRevocation))
				r.Post("/totp/enroll", authHandlers.EnrollTOTP)
				r.With(totpConfirmLimiter.Middleware).Post("/totp/confirm", authHandlers.ConfirmTOTP)
			})
		}

		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAuth(tokens, accessRevocation))
			r.With(deviceRegisterLimiter.Middleware).Post("/devices/register", authHandlers.RegisterDevice)
			r.Get("/devices", authHandlers.ListDevices)
			r.Delete("/devices/{id}", authHandlers.RevokeDevice)

			// Account PIN: unlocks a trusted device (see RegisterDevice/
			// DeviceLogin above) and, for a consuming system that wants it,
			// confirms a sensitive action from any client — see
			// Handlers.SetPin/VerifyPin's doc comments. Each has its own
			// rate limiter on top of the account-level PIN lockout
			// (user.Service.VerifyPin) — keyed by IP like every other
			// limiter here (middleware.ClientIP, see TRUSTED_PROXY_CIDRS).
			r.With(pinSetLimiter.Middleware).Put("/pin", authHandlers.SetPin)
			r.With(pinVerifyLimiter.Middleware).Post("/pin/verify", authHandlers.VerifyPin)

			if pushEnabled {
				// Opting a trusted device into push approval (and back out
				// of it), and the phone's own "I tapped this number" answer
				// — all three require the caller's own Bearer token (see
				// Handlers.EnableDevicePush / DisableDevicePush /
				// AnswerPushLogin doc comments).
				r.Post("/devices/{id}/push", authHandlers.EnableDevicePush)
				r.Delete("/devices/{id}/push", authHandlers.DisableDevicePush)
				r.Post("/login/push-answer", authHandlers.AnswerPushLogin)
			}

			// Disabling only ever makes sense from an already-authenticated
			// settings screen — there's no first-login equivalent of "turn
			// off the thing I haven't set up yet".
			if totpEnabled {
				r.Post("/totp/disable", authHandlers.DisableTOTP)
			}
		})
	})

	// Account-level moderation — same four handlers back both /admin/users
	// (the operator's own X-Admin-Token, unscoped) and /system-admin/users
	// (a tenant's own scoped X-System-Admin-Token) below; see
	// auth.AdminHandlers' doc comment. See user.Service.Ban's doc comment
	// for why banning is never triggered automatically.
	adminUserHandlers := auth.NewAdminHandlers(authSvc)

	// /admin/* lives on its own *chi.Mux (adminRouter, mounted below),
	// never inside r — a browser-based panel login needs a cookie-carrying
	// (credentialed) CORS response scoped to the panel's own exact origin,
	// which is fundamentally incompatible with the wildcard,
	// no-credentials CORS the rest of this API deliberately uses (see r's
	// own cors.Handler above): go-chi/cors answers a preflight OPTIONS
	// request and stops the middleware chain right there, so if both CORS
	// configs sat on the same router, whichever one is outermost would
	// always win for every path, including the other one's routes. Two
	// separate muxes, mounted together at the very end of this function,
	// is what actually keeps them from colliding.
	adminRouter := chi.NewRouter()
	if adminToken != "" || adminPanelOrigin != "" {
		adminRouter.Use(chimw.RequestID)
		if len(trustedProxyCIDRs) > 0 {
			adminRouter.Use(chimw.ClientIPFromXFF(trustedProxyCIDRs...))
		}
		adminRouter.Use(middleware.RequestLogger(logger))
		adminRouter.Use(chimw.Recoverer)
		adminRouter.Use(chimw.Timeout(15 * time.Second))
		adminRouter.Use(middleware.Metrics(meter))
		adminRouter.Use(blacklist.Middleware)

		if adminPanelOrigin != "" {
			// Credentialed: the panel's own session cookie rides on these
			// requests, so the origin must be exact (browsers refuse "*"
			// together with credentials) — see config.Config.
			// AdminPanelOrigin's doc comment.
			adminRouter.Use(cors.Handler(cors.Options{
				AllowedOrigins:   []string{adminPanelOrigin},
				AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions},
				AllowedHeaders:   []string{"Content-Type", "X-Admin-Token", middleware.AdminPanelHeader},
				AllowCredentials: true,
				MaxAge:           300,
			}))
		} else {
			// No panel configured — same wildcard, no-credentials CORS
			// /admin/* always had before this feature existed, for the
			// X-Admin-Token/script-only case (curl doesn't need CORS
			// headers at all, but a hypothetical browser-based fetch using
			// just the token header still worked under the old single
			// global CORS config, so this preserves that).
			adminRouter.Use(cors.Handler(cors.Options{
				AllowedOrigins:   []string{"*"},
				AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions},
				AllowedHeaders:   []string{"Content-Type", "X-Admin-Token"},
				AllowCredentials: false,
				MaxAge:           300,
			}))
		}

		// adminAccounts can be a nil *adminauth.Service (TOTP not configured
		// server-wide at all — see cmd/api/main.go's wiring) — passed
		// through this explicit nil check rather than straight into
		// RequireAdminAccess, since a nil *adminauth.Service boxed directly
		// into the AdminSessionValidator interface would NOT compare equal
		// to a nil interface there (classic Go typed-nil gotcha), and
		// RequireAdminAccess's own nil check for "no session feature
		// configured" relies on getting a true nil interface.
		var sessionValidator middleware.AdminSessionValidator
		if adminAccounts != nil {
			sessionValidator = adminAccounts
		}
		adminAccess := middleware.RequireAdminAccess(adminToken, sessionValidator)

		adminHandlers := apiclient.NewHandlers(apiClients)
		adminRouter.Route("/clients", func(r chi.Router) {
			r.Use(adminAccess)

			r.Post("/", adminHandlers.Create)
			r.Get("/", adminHandlers.List)
			r.Post("/{id}/deactivate", adminHandlers.Deactivate)
			r.Post("/{id}/activate", adminHandlers.Activate)
			r.Post("/{id}/rotate", adminHandlers.Rotate)
			r.Put("/{id}/panel-base-url", adminHandlers.SetPanelBaseURL)

			// Provisions/revokes the credential a client's own operators
			// use against /system-admin/users below — an operator-only
			// action, never something a tenant can do to itself.
			r.Post("/{id}/system-admin-key/rotate", adminHandlers.RotateSystemAdminKey)
			r.Delete("/{id}/system-admin-key", adminHandlers.RevokeSystemAdminKey)
		})

		adminRouter.Route("/users", func(r chi.Router) {
			r.Use(adminAccess)

			// No {id} — unlike X-System-Admin-Token, neither credential
			// here sets a tenant in context, so this spans every tenant.
			// See AdminHandlers.ListUsers' doc comment. Deliberately not
			// in openapi.yaml/docs: those are served unauthenticated at
			// /docs, and this route's existence shouldn't be discoverable
			// by anyone without the operator's own credential — see
			// README's /admin/users section for where this is documented
			// instead.
			r.Get("/", adminUserHandlers.ListUsers)

			r.Post("/{id}/ban", adminUserHandlers.Ban)
			r.Post("/{id}/unban", adminUserHandlers.Unban)
			r.Post("/{id}/disable-totp", adminUserHandlers.DisableTOTP)
			r.Post("/{id}/revoke-sessions", adminUserHandlers.RevokeSessions)
			r.Post("/{id}/reset-pin", adminUserHandlers.ResetPin)
			r.Post("/{id}/change-email", adminUserHandlers.ChangeEmail)
			r.Put("/{id}/login-pin-required", adminUserHandlers.SetLoginPinRequired)
			r.Get("/{id}/lockouts", adminUserHandlers.GetLockouts)
			r.Post("/{id}/clear-lockouts", adminUserHandlers.ClearLockouts)
		})

		// Manual override for the automatic IP blacklist above — lifts a
		// ban early (most commonly: a shared IP where the actual offender
		// is long gone, but everyone else behind it is still paying for
		// it) and clears its strike/level history.
		adminRouter.Route("/blacklist", func(r chi.Router) {
			r.Use(adminAccess)

			r.Delete("/{ip}", func(w http.ResponseWriter, r *http.Request) {
				ip := chi.URLParam(r, "ip")
				if err := blacklist.Unban(r.Context(), ip); err != nil {
					http.Error(w, `{"error":"no se pudo levantar el baneo"}`, http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			})

			// Exempts an IP from ever being struck/banned — operator-only,
			// deliberately not exposed under /system-admin/*: the exemption
			// is global (protects the IP against every system's strikes,
			// not just whoever added it — see blacklistHandlers.
			// AddAllowlist's doc comment), so letting any one tenant's own
			// credential grant it would let that tenant weaken protection
			// for every other tenant on the platform, not just itself —
			// unlike every other /system-admin/* action, which can only
			// ever affect its own tenant's own data.
			r.Route("/allowlist", func(r chi.Router) {
				r.Get("/", blHandlers.ListAllowlist)
				r.Post("/", blHandlers.AddAllowlist)
				r.Delete("/{ip}", blHandlers.RemoveAllowlist)
			})
		})

		// The panel's own login — see adminauth.Service and config.Config.
		// AdminPanelOrigin's doc comments for why this is opt-in
		// separately from adminToken: a login surface with no configured
		// origin to accept cookies from would be useless and shouldn't
		// exist (same "opt-in or 404" pattern as TOTP/push above), even
		// when adminToken is set for script-only use. Also requires
		// adminAccounts != nil — cmd/api/main.go only constructs one when
		// TOTP is configured server-wide (TOTPEncryptionKeyBase64), since
		// an admin account's TOTP secret can't be encrypted at rest
		// without it and TOTP is mandatory for every admin account, not
		// opt-in the way it is for end users.
		if adminPanelOrigin != "" && adminAccounts != nil {
			sameSite := http.SameSiteNoneMode
			if !adminSessionCrossSite {
				sameSite = http.SameSiteStrictMode
			}
			adminAuth := newAdminAuthHandlers(adminAccounts, adminSessionTTL, sameSite, logger)

			adminRouter.Post("/auth/login", adminAuth.Login)
			adminRouter.Post("/auth/logout", adminAuth.Logout)

			adminRouter.Route("/accounts", func(r chi.Router) {
				r.Use(adminAccess)
				r.Get("/", adminAuth.ListAccounts)
				r.Post("/", adminAuth.CreateAccount)
				r.Post("/{id}/revoke", adminAuth.RevokeAccount)
			})
		}
	}

	// A tenant's own scoped moderation, gated by its own X-System-Admin-Token
	// rather than the operator's global one — registered unconditionally
	// (unlike /admin/*, which needs ADMIN_API_TOKEN set at all): whether
	// any given request can actually authenticate depends on whether that
	// specific client has ever had a key provisioned via
	// POST /admin/clients/{id}/system-admin-key/rotate, not on a
	// deployment-wide flag. A client with no key provisioned gets the same
	// 401 as a wrong key — see middleware.RequireSystemAdminToken.
	r.Route("/system-admin/users", func(r chi.Router) {
		r.Use(middleware.RequireSystemAdminToken(apiClients))

		// Scoped to the caller's own tenant via APIClientIDFromContext —
		// see AdminHandlers.ListUsers' doc comment. The same handler also
		// backs GET /admin/users above, unscoped — which one a request
		// gets is entirely a function of which token authenticated it.
		r.Get("/", adminUserHandlers.ListUsers)

		r.Post("/{id}/ban", adminUserHandlers.Ban)
		r.Post("/{id}/unban", adminUserHandlers.Unban)
		r.Post("/{id}/disable-totp", adminUserHandlers.DisableTOTP)
		r.Post("/{id}/revoke-sessions", adminUserHandlers.RevokeSessions)
		r.Post("/{id}/reset-pin", adminUserHandlers.ResetPin)
		r.Post("/{id}/change-email", adminUserHandlers.ChangeEmail)
		r.Put("/{id}/login-pin-required", adminUserHandlers.SetLoginPinRequired)
		r.Get("/{id}/lockouts", adminUserHandlers.GetLockouts)
		r.Post("/{id}/clear-lockouts", adminUserHandlers.ClearLockouts)
	})

	// A tenant's own view of its banned IPs — see blacklistHandlers' doc
	// comment and middleware.Blacklist.ListOwned/UnbanOwned for why this is
	// scoped by ownership rather than mirroring /admin/blacklist (the
	// operator's own unscoped override) directly.
	r.Route("/system-admin/blacklist", func(r chi.Router) {
		r.Use(middleware.RequireSystemAdminToken(apiClients))
		r.Get("/", blHandlers.List)
		r.Delete("/{ip}", blHandlers.Unban)
	})

	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireAuth(tokens, accessRevocation))

		r.Get("/me", func(w http.ResponseWriter, r *http.Request) {
			userID, _ := middleware.UserIDFromContext(r.Context())

			u, err := users.FindByID(r.Context(), userID)
			if err != nil {
				http.Error(w, `{"error":"usuario no encontrado"}`, http.StatusNotFound)
				return
			}
			pinSet, err := users.HasPin(r.Context(), userID)
			if err != nil {
				http.Error(w, `{"error":"no se pudo obtener el usuario"}`, http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":           u.ID,
				"email":        u.Email,
				"username":     u.Username,
				"rut":          u.RUT,
				"totp_enabled": u.TOTPEnabled,
				"pin_set":      pinSet,
			})
		})
	})

	// top has no middleware of its own — it only dispatches by prefix, so
	// r's wildcard CORS and adminRouter's credentialed/panel-specific CORS
	// each only ever see the requests meant for them (see adminRouter's
	// own doc comment above for why that separation has to happen at this
	// level, not as nested middleware on one shared router).
	top := chi.NewRouter()
	top.Mount("/admin", adminRouter)
	top.Mount("/", r)
	return top
}

// loginTokenQueryKey reads login_token from the query string — the key
// pushStatusLimiter counts by, since /auth/login/push-status has no other
// identity to key on (no Bearer token exists on the PC side of a push
// login). A request missing it entirely shares one bucket among itself —
// harmless: the handler itself already rejects a missing login_token on
// its own terms, this is only about what the rate limiter counts against.
func loginTokenQueryKey(r *http.Request) string {
	return r.URL.Query().Get("login_token")
}
