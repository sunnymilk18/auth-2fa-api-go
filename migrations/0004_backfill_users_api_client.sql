-- Self-guarding: safe to run before the first api_client exists (no-ops
-- with a notice) and safe to re-run afterwards (only applies once).
--
-- Sequence:
--   1. go run ./cmd/migrate            (applies 0001-0003; this file no-ops)
--   2. go run ./cmd/createclient -name auth-2fa-app-flutter
--   3. go run ./cmd/migrate            (this file now backfills + locks in the constraints)

DO $$
DECLARE
    default_client_id UUID;
BEGIN
    SELECT id INTO default_client_id FROM api_clients WHERE name = 'auth-2fa-app-flutter';

    IF default_client_id IS NULL THEN
        RAISE NOTICE 'api_client "auth-2fa-app-flutter" does not exist yet -- skipping backfill. Run cmd/createclient, then re-run migrations.';
        RETURN;
    END IF;

    UPDATE users SET api_client_id = default_client_id WHERE api_client_id IS NULL;

    IF NOT EXISTS (SELECT 1 FROM users WHERE api_client_id IS NULL) THEN
        EXECUTE 'ALTER TABLE users ALTER COLUMN api_client_id SET NOT NULL';
        EXECUTE 'ALTER TABLE users DROP CONSTRAINT IF EXISTS users_email_key';
        EXECUTE 'CREATE UNIQUE INDEX IF NOT EXISTS idx_users_api_client_email ON users(api_client_id, email)';
    END IF;
END $$;
