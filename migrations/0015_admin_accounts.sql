-- Individual admin accounts for the operator's own panel (cross-tenant,
-- separate from the tenant-scoped `users` table) — see internal/adminauth.
-- Lets each person who operates this API log in with their own
-- credentials instead of sharing one X-Admin-Token, which stays as the
-- credential for scripts/automation (cmd/createclient-style CLI usage,
-- curl) rather than the panel itself.
--
-- totp_secret_enc is NOT NULL, unlike users.totp_secret_enc which is
-- nullable/opt-in: an admin account is the highest-privilege credential in
-- the whole system (acts across every tenant), so a second factor is
-- mandatory from account creation, not an opt-in added later. Encrypted at
-- rest the same way as users.totp_secret_enc — see auth.TOTPManager.
CREATE TABLE IF NOT EXISTS admin_accounts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    totp_secret_enc TEXT NOT NULL,
    active          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Session tokens backing the panel's httpOnly cookie — same shape as
-- refresh_tokens (only a hash of the token is ever stored, see
-- adminauth.SessionRepository), so a database leak alone never yields a
-- usable session.
CREATE TABLE IF NOT EXISTS admin_sessions (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_account_id UUID NOT NULL REFERENCES admin_accounts(id) ON DELETE CASCADE,
    token_hash       TEXT NOT NULL UNIQUE,
    expires_at       TIMESTAMPTZ NOT NULL,
    revoked          BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at       TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_admin_sessions_account_id ON admin_sessions(admin_account_id);
