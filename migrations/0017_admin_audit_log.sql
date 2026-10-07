-- Append-only record of what every operator action did — see
-- internal/audit. Deliberately NOT a foreign key to admin_accounts: a
-- revoked (or even deleted-by-direct-DB-surgery) account's past actions
-- must stay readable, and actor_email is also used for the shared
-- X-Admin-Token/script path ("token"), which has no admin_accounts row at
-- all. Never holds secrets, password hashes, API keys, or codes — only
-- what happened and what it was done to (see internal/audit.Entry's doc
-- comment).
CREATE TABLE IF NOT EXISTS admin_audit_log (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_email  TEXT NOT NULL,
    actor_role   TEXT NOT NULL,
    action       TEXT NOT NULL,
    target_type  TEXT NOT NULL DEFAULT '',
    target_id    TEXT NOT NULL DEFAULT '',
    -- target_label is a human-readable snapshot of the target (the user's
    -- email, the client's name, the IP) taken AT THE TIME of the action —
    -- deliberately denormalized, not a join against users/api_clients,
    -- so the entry still reads clearly even after the target itself
    -- changes (the user's email gets corrected, the client is renamed) or
    -- is gone entirely.
    target_label TEXT NOT NULL DEFAULT '',
    actor_ip     TEXT NOT NULL DEFAULT ''
);

-- GET /admin/audit always orders most-recent-first and usually filters by
-- a date range — a single index on created_at covers both without needing
-- a composite per filter combination; add one on actor_email/action later
-- only if filtering by those alone (no date range) turns out slow in
-- practice.
CREATE INDEX IF NOT EXISTS idx_admin_audit_log_created_at ON admin_audit_log(created_at DESC);
