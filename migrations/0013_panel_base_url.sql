-- panel_base_url: optional, per tenant — the base URL of that tenant's
-- deployed admin panel (changes per environment/deployment, e.g. a Dokploy
-- sslip.io domain in one, http://localhost:5173 in dev). Used to build a
-- link in the admin-initiated change-email email (see
-- auth.Service.AdminChangeEmail) pointing at the panel's confirmation
-- screen with the new email pre-filled. Nullable: a tenant with nothing
-- configured just gets the email without a link, same as today.
ALTER TABLE api_clients ADD COLUMN IF NOT EXISTS panel_base_url TEXT;
