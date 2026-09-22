-- Lets a newly-verified account choose its second-factor method (email code
-- vs authenticator app) on its very first login, instead of always defaulting
-- to email — see auth.Service.LoginStep1's doc comment.
--
-- two_factor_method_chosen starts FALSE for every account. The first time
-- LoginStep1 succeeds past the password check for an account with this
-- still FALSE, it skips auto-sending an email code and instead hands back a
-- pending setup session, letting the client show a "how do you want to
-- protect your account" screen. It flips to TRUE the first time either path
-- actually completes (a successful email-code login, or TOTP enrollment
-- confirmed) — every login after that behaves exactly as it does today,
-- the choice screen is a one-time thing.
--
-- Guarded on the column not existing yet — same idempotency requirement
-- every migration here has (testutil.MSSQLPool re-applies every *.sql file
-- before each test).
IF NOT EXISTS (
    SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('users') AND name = 'two_factor_method_chosen'
)
BEGIN
    -- Both statements run via EXEC (each its own dynamically-compiled
    -- batch) rather than directly in this BEGIN...END: SQL Server compiles
    -- a whole batch up front, so a plain UPDATE referencing the column
    -- ADDed two statements above would fail to resolve it by name here.
    -- Wrapping the backfill in EXEC defers its compilation until it
    -- actually runs, by which point the ALTER has already committed. Both
    -- stay inside this IF, so the backfill only ever runs once — the
    -- moment the column is first added — matching the original intent:
    -- every account that already existed before this migration already
    -- has a working login (email, or TOTP already confirmed) and must NOT
    -- suddenly see the first-time choice screen on its next login, while
    -- rows inserted after this point (genuinely new registrations) keep
    -- the column's own default of 0.
    EXEC('ALTER TABLE users ADD two_factor_method_chosen BIT NOT NULL DEFAULT 0');
    EXEC('UPDATE users SET two_factor_method_chosen = 1');
END
GO
