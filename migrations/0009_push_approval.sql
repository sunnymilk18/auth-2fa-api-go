-- Adds optional push-notification login approval — a third alternative to
-- the email OTP / TOTP second factor, opt-in per trusted device (see
-- README's design notes for the full mechanism: a 2-digit number shown on
-- the requesting device, matched against 3 choices on the phone, to defend
-- against blind "tap approve" MFA-fatigue attacks).
--
-- push_token is nullable: not every trusted device opts into push — it
-- stays a PIN-only device (today's behavior) until the user explicitly
-- activates "approve logins from my phone" from an already-authenticated
-- session. Lives on trusted_devices (not a new table) because it's the
-- same concept as the existing device pairing, just with one more
-- capability — see the column's own naming next to device_token_hash.
--
-- The pending login requests themselves (the 60-second window between
-- "PC asked for approval" and "phone answered") are NOT modeled here —
-- they're short-lived, high-churn session data, same reasoning as OTP/TOTP
-- login sessions (see auth.OTPStore, auth.TOTPLoginStore): they live in
-- Redis with a TTL, not in Postgres.
--
-- Guarded on the column not existing yet — same idempotency requirement
-- every migration here has (testutil.PostgresPool re-applies every *.sql
-- file before each test).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'trusted_devices' AND column_name = 'push_token'
    ) THEN
        ALTER TABLE trusted_devices ADD COLUMN push_token TEXT;
    END IF;
END $$;
