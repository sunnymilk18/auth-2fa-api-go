-- Self-guarding: safe to run on a fresh database, before the first
-- api_client exists, and safe to re-run any number of times afterwards.
--
-- Two separate concerns, deliberately not coupled:
--   1. Backfill: attributes any pre-multi-tenant user (created back when
--      api_client_id didn't exist yet) to a specific api_client. Only ever
--      matters for this project's own original deployment, which is why
--      the name is hardcoded — a fresh database has no such users, so this
--      block is a no-op for it.
--        go run ./cmd/createclient -name auth-2fa-app-flutter   (once)
--        go run ./cmd/migrate                                    (backfills)
--   2. Locking in per-tenant uniqueness: runs unconditionally, and only
--      needs every user to already have an api_client_id — true for a
--      fresh database immediately (zero users), and true for an existing
--      one once #1 (or manual assignment) has resolved every user. This is
--      what actually enables the same email under different tenants; it
--      used to be wrongly nested inside #1's DO block, so it only ever ran
--      on the one deployment where the backfill target already existed —
--      everywhere else (including a plain fresh `go run ./cmd/migrate`)
--      users.email silently stayed globally UNIQUE forever.

DO $$
DECLARE
    default_client_id UUID;
BEGIN
    SELECT id INTO default_client_id FROM api_clients WHERE name = 'auth-2fa-app-flutter';

    IF default_client_id IS NULL THEN
        RAISE NOTICE 'api_client "auth-2fa-app-flutter" does not exist yet -- skipping backfill.';
    ELSE
        UPDATE users SET api_client_id = default_client_id WHERE api_client_id IS NULL;
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM users WHERE api_client_id IS NULL) THEN
        EXECUTE 'ALTER TABLE users ALTER COLUMN api_client_id SET NOT NULL';
        EXECUTE 'ALTER TABLE users DROP CONSTRAINT IF EXISTS users_email_key';
        EXECUTE 'CREATE UNIQUE INDEX IF NOT EXISTS idx_users_api_client_email ON users(api_client_id, email)';
    ELSE
        RAISE NOTICE 'some users still have no api_client_id -- per-tenant email uniqueness not locked in yet.';
    END IF;
END $$;
