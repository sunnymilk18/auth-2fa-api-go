-- Registration now requires confirming access to the email address before
-- the account can log in (see auth.EmailVerificationStore / LoginStep1's
-- EmailVerified check) — otherwise an account can be created with an email
-- its owner never consented to, and every login attempt against it would
-- keep emailing that real owner OTP codes they never asked for.
--
-- Self-guarding, same technique as 0004's backfill: added nullable so
-- existing rows land on NULL, distinguishable from an explicit FALSE for a
-- genuinely new, not-yet-verified account. Backfilled to TRUE (pre-existing
-- accounts predate this requirement, so they aren't retroactively locked
-- out), then locked to NOT NULL DEFAULT FALSE for every row and future
-- insert alike. Safe to re-run: once no row is NULL, all three statements
-- below are no-ops.
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN;
UPDATE users SET email_verified = TRUE WHERE email_verified IS NULL;
ALTER TABLE users ALTER COLUMN email_verified SET NOT NULL;
ALTER TABLE users ALTER COLUMN email_verified SET DEFAULT FALSE;
