-- api_clients: identifies which system is calling this API (multi-tenant).
-- Each api_client gets its own isolated set of users — the same email can
-- exist as separate accounts under different api_clients.
CREATE TABLE IF NOT EXISTS api_clients (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name         TEXT NOT NULL UNIQUE,
    api_key_hash TEXT NOT NULL UNIQUE,
    active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Nullable for now — existing rows have no client yet. See 0004, which
-- backfills this and enforces NOT NULL. Split in two so the operator can
-- create the first api_client (via cmd/createclient) in between.
ALTER TABLE users ADD COLUMN IF NOT EXISTS api_client_id UUID REFERENCES api_clients(id);
CREATE INDEX IF NOT EXISTS idx_users_api_client_id ON users(api_client_id);
