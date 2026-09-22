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
-- insert alike. Safe to re-run: once no row is NULL, all statements below
-- are no-ops.

IF NOT EXISTS (
    SELECT 1 FROM sys.columns
    WHERE object_id = OBJECT_ID('users') AND name = 'email_verified'
)
BEGIN
    ALTER TABLE users ADD email_verified BIT NULL;
END
GO

UPDATE users SET email_verified = 1 WHERE email_verified IS NULL;
GO

IF EXISTS (
    SELECT 1 FROM sys.columns
    WHERE object_id = OBJECT_ID('users') AND name = 'email_verified' AND is_nullable = 1
)
BEGIN
    ALTER TABLE users ALTER COLUMN email_verified BIT NOT NULL;
END
GO

IF NOT EXISTS (
    SELECT 1 FROM sys.default_constraints dc
    JOIN sys.columns c ON c.object_id = dc.parent_object_id AND c.column_id = dc.parent_column_id
    WHERE dc.parent_object_id = OBJECT_ID('users') AND c.name = 'email_verified'
)
BEGIN
    ALTER TABLE users ADD CONSTRAINT df_users_email_verified DEFAULT 0 FOR email_verified;
END
GO
