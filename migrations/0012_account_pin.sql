-- PIN moves from being per-device (trusted_devices.pin_hash) to a single
-- per-account secret: it still unlocks a trusted device, and now also
-- confirms sensitive actions (e.g. an admin ban) from any client.
--
-- Idempotent like every migration here (IF NOT EXISTS / IF EXISTS) — the
-- test harness re-applies every *.sql file on every test run (see
-- testutil.applyMigrations), not just once. That's also why the one-time
-- wipe of existing trusted_devices this needs in a real deployment (see
-- README) is a separate manual step, not a DELETE in here: a DELETE would
-- re-run on every test too, destroying devices other tests just created.
ALTER TABLE trusted_devices DROP COLUMN IF EXISTS pin_hash;
ALTER TABLE trusted_devices DROP COLUMN IF EXISTS failed_pin_attempts;

ALTER TABLE users ADD COLUMN IF NOT EXISTS pin_hash TEXT; -- bcrypt of a 6-digit PIN; NULL = never set
ALTER TABLE users ADD COLUMN IF NOT EXISTS pin_failed_attempts INT NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS pin_locked_until TIMESTAMPTZ; -- NULL = not locked
ALTER TABLE users ADD COLUMN IF NOT EXISTS pin_set_at TIMESTAMPTZ;
