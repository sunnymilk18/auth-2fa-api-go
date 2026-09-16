-- Adds username + rut as required, per-tenant-unique identity fields,
-- alongside email. Login accepts any of the three (see
-- internal/user/identifier.go) precisely because all three are unique per
-- api_client_id, so a lookup by any of them always resolves to at most one
-- account.
--
-- Only test accounts existed in this database at the time this migration
-- was written (confirmed 2026-09-16) — unlike 0004's api_client_id
-- backfill, there's no sensible default value to backfill existing rows
-- with here: rut is a real government-issued id (nothing to invent), and
-- giving every existing row the same username would immediately violate
-- the uniqueness this migration adds. So this wipes users outright instead
-- of backfilling. Safe/no-op on any already-empty database (a fresh
-- contributor's local db, CI, a new deployment). Cascades automatically to
-- refresh_tokens and trusted_devices (both ON DELETE CASCADE) — nothing
-- left orphaned.
--
-- If this project ever needs to run this migration against a database with
-- real user accounts, do NOT reuse this file as-is: write a proper
-- transition instead (nullable columns, a "complete your profile" gate
-- blocking login until username+rut are filled in, NOT NULL only once
-- every row is complete — same shape as 0005's email_verified backfill).
--
-- Guarded on the column not existing yet — same idempotency requirement
-- every migration here has (testutil.PostgresPool re-applies every *.sql
-- file before each test, including ones running concurrently in other
-- packages against the same database): without this guard, DELETE FROM
-- users would fire again on every single test in the suite, wiping out
-- live rows another package's test was still using.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'username'
    ) THEN
        DELETE FROM users;
        ALTER TABLE users ADD COLUMN username TEXT NOT NULL;
        ALTER TABLE users ADD COLUMN rut TEXT NOT NULL;
    END IF;
END $$;

-- Both scoped to api_client_id, same multi-tenant pattern as email's own
-- idx_users_api_client_email (see migration 0004): the same username or rut
-- string may exist under two different api_clients as unrelated accounts.
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_api_client_username ON users(api_client_id, username);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_api_client_rut ON users(api_client_id, rut);
