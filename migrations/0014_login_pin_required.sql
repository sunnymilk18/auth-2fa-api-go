-- pin_required_at_login: per-account switch, managed by an operator/tenant
-- via PUT /system-admin/users/{id}/login-pin-required (or its unscoped
-- /admin/users mirror). Go itself knows nothing about roles — those live
-- in whatever panel manages this flag — so this is just the one bit of
-- state that panel syncs onto the account it wants to require a PIN step
-- for, on top of password + second factor, before any token is issued.
-- See auth.Service's LoginResult/LoginPinStep for how this is enforced.
ALTER TABLE users ADD COLUMN IF NOT EXISTS pin_required_at_login BOOLEAN NOT NULL DEFAULT FALSE;
