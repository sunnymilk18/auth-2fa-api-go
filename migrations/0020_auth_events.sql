-- Records every end-user authentication attempt (login, password reset,
-- registration) plus IP ban/unban history — the foundation for the admin
-- panel's "tanda 2" of Estadísticas and, later, a Security Center. Separate
-- from admin_audit_log on purpose: that table is operator actions against
-- /admin/*, this one is end-user-facing traffic, at a much higher volume
-- and with its own retention policy (AUTH_EVENTS_RETENTION_DAYS).
--
-- api_client_id/user_id are nullable and ON DELETE SET NULL: a row must
-- never block deleting a tenant or a user, and a login attempt against an
-- invalid api key legitimately has no api_client_id at all (see
-- internal/auth's wiring — RequireAPIKey rejects those before reaching any
-- handler, so in practice this is only ever NULL for a handful of edge
-- cases, not the common case).
CREATE TABLE IF NOT EXISTS auth_events (
    id            BIGSERIAL PRIMARY KEY,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    api_client_id UUID REFERENCES api_clients(id) ON DELETE SET NULL,
    user_id       UUID REFERENCES users(id) ON DELETE SET NULL,

    -- kind: login, password_reset_request, password_reset_confirm,
    -- register, ip_ban, ip_unban — see internal/authevents.Kind* consts.
    kind   TEXT NOT NULL,
    -- method: only meaningful for kind = login (NULL for every other
    -- kind) — password, totp, email_code, push, device_pin,
    -- device_trusted. See internal/authevents.Method* consts.
    method TEXT,
    -- result: the outcome, meaning depends on kind — see
    -- internal/authevents.Result* consts for the full set per kind.
    result TEXT NOT NULL,

    -- email_hash: HMAC-SHA256 (not plain SHA-256 — see
    -- internal/authevents.HashEmail's doc comment) of the normalized email
    -- an attempt was made against, hex-encoded. Only ever set when
    -- user_id is NULL (the identifier didn't resolve to a real account) —
    -- never both at once, and never the plaintext email anywhere in this
    -- table.
    email_hash TEXT,

    -- ban_origin/actor_email: only meaningful for kind = ip_ban/ip_unban —
    -- automatic (no actor), operator (actor_email is the operator's
    -- email), or tenant (api_client_id above is the tenant, actor_email
    -- stays NULL — a system-admin-scoped unban has no operator identity).
    -- See internal/authevents.BanOrigin* consts.
    ban_origin  TEXT,
    actor_email TEXT,

    -- ip: the real client IP (see internal/auth's own client-IP
    -- resolution, which mirrors middleware.ClientIP's trusted-proxy logic
    -- — see that function's doc comment for why this must never be a
    -- naive r.RemoteAddr read) — for ip_ban/ip_unban this is the banned
    -- IP, not the actor's.
    ip         INET,
    user_agent TEXT NOT NULL DEFAULT '',

    -- is_decoy: always FALSE today, reserved for a future decoy-account
    -- feature (see the Security Center this table is laying groundwork
    -- for) — never set by any code path yet.
    is_decoy BOOLEAN NOT NULL DEFAULT FALSE
);

-- Backs GET /admin/stats' new per-tenant blocks (failures_by_tenant) and
-- any future per-tenant auth_events query — same reasoning as
-- idx_admin_audit_log_created_at/idx_users_created_at.
CREATE INDEX IF NOT EXISTS idx_auth_events_api_client_created_at ON auth_events(api_client_id, created_at DESC);
-- Backs top_failing_ips.
CREATE INDEX IF NOT EXISTS idx_auth_events_ip_created_at ON auth_events(ip, created_at DESC);
-- Backs the retention sweep (DELETE ... WHERE created_at < cutoff) and
-- logins_by_day/bans_by_day's date-range scans.
CREATE INDEX IF NOT EXISTS idx_auth_events_created_at ON auth_events(created_at);
