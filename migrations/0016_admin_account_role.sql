-- Two-tier permission for admin_accounts: 'superadmin' can do everything
-- (including manage other admin accounts, tenants/api_clients, and the IP
-- allowlist — the three categories that affect "who has access at all" or
-- "which systems/IPs are trusted platform-wide"), 'admin' is limited to
-- day-to-day moderation (user actions, lifting an individual IP ban) — see
-- internal/httpserver/router.go's RequireSuperAdmin wiring for exactly
-- which routes require which role.
--
-- NOT NULL with no default on purpose: every INSERT (adminauth.Service.
-- CreateAccount, cmd/createadmin) must now pass an explicit role rather
-- than silently inheriting one, since picking the wrong default here
-- (either direction) would be a real privilege mistake, not a cosmetic one.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'admin_accounts' AND column_name = 'role'
    ) THEN
        ALTER TABLE admin_accounts ADD COLUMN role TEXT;
        UPDATE admin_accounts SET role = 'superadmin' WHERE role IS NULL;
        ALTER TABLE admin_accounts ALTER COLUMN role SET NOT NULL;
        ALTER TABLE admin_accounts ADD CONSTRAINT admin_accounts_role_check
            CHECK (role IN ('admin', 'superadmin'));
    END IF;
END $$;
