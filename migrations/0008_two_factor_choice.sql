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
-- every migration here has (testutil.PostgresPool re-applies every *.sql
-- file before each test).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'two_factor_method_chosen'
    ) THEN
        ALTER TABLE users ADD COLUMN two_factor_method_chosen BOOLEAN NOT NULL DEFAULT FALSE;

        -- Backfill: every account that already existed before this
        -- migration already has a working login (email, or TOTP already
        -- confirmed) — it must NOT suddenly see the first-time choice
        -- screen on its next login. Only rows inserted after this point
        -- (genuinely new registrations) get the column's own FALSE default.
        UPDATE users SET two_factor_method_chosen = TRUE;
    END IF;
END $$;
