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
--      what actually enables the same email under different tenants.

DECLARE @default_client_id VARCHAR(36);
SELECT @default_client_id = id FROM api_clients WHERE name = 'auth-2fa-app-flutter';

IF @default_client_id IS NULL
BEGIN
    PRINT 'api_client "auth-2fa-app-flutter" does not exist yet -- skipping backfill.';
END
ELSE
BEGIN
    UPDATE users SET api_client_id = @default_client_id WHERE api_client_id IS NULL;
END
GO

IF NOT EXISTS (SELECT 1 FROM users WHERE api_client_id IS NULL)
BEGIN
    IF EXISTS (
        SELECT 1 FROM sys.columns
        WHERE object_id = OBJECT_ID('users') AND name = 'api_client_id' AND is_nullable = 1
    )
    BEGIN
        -- SQL Server won't ALTER COLUMN while idx_users_api_client_id (from
        -- 0003) depends on it — unlike Postgres, which allows this directly.
        -- Drop it, alter, recreate: no data loss, the index is just a
        -- lookup accelerator.
        IF EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_users_api_client_id')
        BEGIN
            DROP INDEX idx_users_api_client_id ON users;
        END
        ALTER TABLE users ALTER COLUMN api_client_id VARCHAR(36) NOT NULL;
        CREATE INDEX idx_users_api_client_id ON users(api_client_id);
    END

    -- Postgres's original UNIQUE(email) constraint (from 0001) has no
    -- equivalent here — this project's SQL Server 0001 never created one,
    -- since per-tenant uniqueness (the index below) was always the real
    -- target. Nothing to drop.

    IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_users_api_client_email')
    BEGIN
        CREATE UNIQUE INDEX idx_users_api_client_email ON users(api_client_id, email);
    END
END
ELSE
BEGIN
    PRINT 'some users still have no api_client_id -- per-tenant email uniqueness not locked in yet.';
END
GO
