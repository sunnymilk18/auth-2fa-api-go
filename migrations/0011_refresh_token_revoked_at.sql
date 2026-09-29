-- revoked_at: when a refresh_tokens row was revoked (NULL if it never was).
-- Lets the cleanup job (RefreshRepository.DeleteExpired) purge a revoked
-- row a short, fixed time after it was revoked — instead of only once it
-- hits its own expires_at (up to REFRESH_TOKEN_TTL later, 7 days by
-- default) — while still keeping it around briefly, rather than deleting
-- it the instant it's revoked: a short-lived revoked row is what lets a
-- reused/stolen copy of it be recognized as "already revoked" rather than
-- "never existed" (see RefreshRepository.ConsumeIfValid's doc comment).
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;
