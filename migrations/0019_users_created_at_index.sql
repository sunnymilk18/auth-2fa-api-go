-- Backs GET /admin/stats' per-day user counts (users_per_day,
-- new_in_range inside users_per_tenant) and any future admin query that
-- filters/orders by signup date — every such query narrows by created_at
-- first (a 7 or 30 day window), same reasoning as
-- idx_admin_audit_log_created_at.
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);
