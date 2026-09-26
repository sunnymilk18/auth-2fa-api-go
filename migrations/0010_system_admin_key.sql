-- system_admin_key_hash: an optional second credential per api_client,
-- scoped to that tenant only. Lets a consuming system moderate its own
-- users (ban/unban, disable TOTP, revoke sessions) without needing the
-- operator's global ADMIN_API_TOKEN, which spans every tenant. Nullable
-- and unique-when-set: most clients never provision one, and Postgres
-- treats multiple NULLs as distinct under a UNIQUE constraint, so that's
-- fine.
ALTER TABLE api_clients ADD COLUMN IF NOT EXISTS system_admin_key_hash TEXT UNIQUE;
ALTER TABLE api_clients ADD COLUMN IF NOT EXISTS system_admin_key_last_used_at TIMESTAMPTZ;
