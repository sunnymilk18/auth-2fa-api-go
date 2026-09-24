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
// with no auth") — see middleware.RequireAdminToken.
// totpEnabled controls whether /auth/totp/* is registered at all — see
// config.Config.TOTPEncryptionKeyBase64's doc comment: unset means the
// feature doesn't exist here (404, not "exists but always fails"), same
// pattern as adminToken == "" for /admin/*.
// pushEnabled controls whether the push-notification login-approval routes
// are registered at all — same opt-in-at-deployment pattern as totpEnabled
// (see config.Config.FirebaseCredentialsPath's doc comment): unset means
// 404, not "exists but always fails".
func NewRouter(authHandlers *auth.Handlers, tokens *auth.TokenManager, users *user.Service, pgPool *pgxpool.Pool, rdb *redis.Client, apiClients *apiclient.Service, trustProxyHeaders bool, meter metric.Meter, adminToken string, totpEnabled bool, pushEnabled bool, logger *slog.Logger) http.Handler {
	r := chi.NewRouter()

	// Any origin, no credentials: this is a header/token API (X-API-Key,
	// Bearer), never cookies — so there's no session to leak by allowing
	// "*", and each consuming system's own frontend can live at whatever
	// domain it wants without us maintaining an allowlist per tenant.
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions},
		AllowedHeaders:   []string{"Content-Type", "Authorization", "X-API-Key", "X-Admin-Token"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
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
	blacklist := middleware.NewBlacklist(rdb, trustProxyHeaders,
		3, 24*time.Hour,
		[]time.Duration{24 * time.Hour, 72 * time.Hour, 7 * 24 * time.Hour},
		30*24*time.Hour,
	)
	r.Use(blacklist.Middleware)

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
	registerLimiter := middleware.NewRateLimiter(rdb, "register", 10, time.Hour, trustProxyHeaders).AttachBlacklist(blacklist)
	loginLimiter := middleware.NewRateLimiter(rdb, "login", 20, 15*time.Minute, trustProxyHeaders).AttachBlacklist(blacklist)
	otpLimiter := middleware.NewRateLimiter(rdb, "verify-otp", 30, 15*time.Minute, trustProxyHeaders).AttachBlacklist(blacklist)
	deviceLoginLimiter := middleware.NewRateLimiter(rdb, "device-login", 30, 15*time.Minute, trustProxyHeaders).AttachBlacklist(blacklist)
	passwordResetRequestLimiter := middleware.NewRateLimiter(rdb, "password-reset-request", 5, time.Hour, trustProxyHeaders).AttachBlacklist(blacklist)
	passwordResetConfirmLimiter := middleware.NewRateLimiter(rdb, "password-reset-confirm", 10, 15*time.Minute, trustProxyHeaders).AttachBlacklist(blacklist)
	verifyEmailConfirmLimiter := middleware.NewRateLimiter(rdb, "verify-email-confirm", 10, 15*time.Minute, trustProxyHeaders).AttachBlacklist(blacklist)
	verifyEmailResendLimiter := middleware.NewRateLimiter(rdb, "verify-email-resend", 5, time.Hour, trustProxyHeaders).AttachBlacklist(blacklist)
	totpConfirmLimiter := middleware.NewRateLimiter(rdb, "totp-confirm", 10, 15*time.Minute, trustProxyHeaders).AttachBlacklist(blacklist)
	sendLoginEmailCodeLimiter := middleware.NewRateLimiter(rdb, "login-send-email-code", 10, 15*time.Minute, trustProxyHeaders).AttachBlacklist(blacklist)
	requestLoginEmailCodeLimiter := middleware.NewRateLimiter(rdb, "login-request-email-code", 10, 15*time.Minute, trustProxyHeaders).AttachBlacklist(blacklist)
	resendLoginCodeLimiter := middleware.NewRateLimiter(rdb, "login-resend-code", 5, time.Hour, trustProxyHeaders).AttachBlacklist(blacklist)

	r.Route("/auth", func(r chi.Router) {
		// Every /auth/* call must identify which consuming system it's from —
		// used to keep each system's users isolated from the others.
		r.Use(middleware.RequireAPIKey(apiClients))

		r.With(registerLimiter.Middleware).Post("/register", authHandlers.Register)
		r.With(loginLimiter.Middleware).Post("/login", authHandlers.Login)
		r.With(otpLimiter.Middleware).Post("/verify-otp", authHandlers.VerifyOTP)
		r.Post("/refresh", authHandlers.Refresh)
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
			r.With(otpLimiter.Middleware).Get("/login/push-status", authHandlers.PushLoginStatus)

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
				r.Use(middleware.OptionalAuth(tokens))
				r.Post("/totp/enroll", authHandlers.EnrollTOTP)
				r.With(totpConfirmLimiter.Middleware).Post("/totp/confirm", authHandlers.ConfirmTOTP)
			})
		}

		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAuth(tokens))
			r.Post("/devices/register", authHandlers.RegisterDevice)
			r.Get("/devices", authHandlers.ListDevices)
			r.Delete("/devices/{id}", authHandlers.RevokeDevice)

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

	if adminToken != "" {
		adminHandlers := apiclient.NewHandlers(apiClients)
		r.Route("/admin/clients", func(r chi.Router) {
			r.Use(middleware.RequireAdminToken(adminToken))

			r.Post("/", adminHandlers.Create)
			r.Get("/", adminHandlers.List)
			r.Post("/{id}/deactivate", adminHandlers.Deactivate)
			r.Post("/{id}/activate", adminHandlers.Activate)
			r.Post("/{id}/rotate", adminHandlers.Rotate)
		})

		// Manual, account-level moderation — see user.Service.Ban's doc
		// comment for why this is never triggered automatically.
		userAdminHandlers := user.NewAdminHandlers(users)
		r.Route("/admin/users", func(r chi.Router) {
			r.Use(middleware.RequireAdminToken(adminToken))

			r.Post("/{id}/ban", userAdminHandlers.Ban)
			r.Post("/{id}/unban", userAdminHandlers.Unban)
		})

		// Manual override for the automatic IP blacklist above — lifts a
		// ban early (most commonly: a shared IP where the actual offender
		// is long gone, but everyone else behind it is still paying for
		// it) and clears its strike/level history.
		r.Route("/admin/blacklist", func(r chi.Router) {
			r.Use(middleware.RequireAdminToken(adminToken))

			r.Delete("/{ip}", func(w http.ResponseWriter, r *http.Request) {
				ip := chi.URLParam(r, "ip")
				if err := blacklist.Unban(r.Context(), ip); err != nil {
					http.Error(w, `{"error":"no se pudo levantar el baneo"}`, http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			})
		})
	}

	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireAuth(tokens))

		r.Get("/me", func(w http.ResponseWriter, r *http.Request) {
			userID, _ := middleware.UserIDFromContext(r.Context())

			u, err := users.FindByID(r.Context(), userID)
			if err != nil {
				http.Error(w, `{"error":"usuario no encontrado"}`, http.StatusNotFound)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":           u.ID,
				"email":        u.Email,
				"username":     u.Username,
				"rut":          u.RUT,
				"totp_enabled": u.TOTPEnabled,
			})
		})
	})

	return r
}
