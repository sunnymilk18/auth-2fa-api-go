-- api_clients: identifies which system is calling this API (multi-tenant).
-- Each api_client gets its own isolated set of users — the same email can
-- exist as separate accounts under different api_clients.

IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'api_clients')
BEGIN
    CREATE TABLE api_clients (
        id           VARCHAR(36) PRIMARY KEY DEFAULT CONVERT(VARCHAR(36), NEWID()),
        name         NVARCHAR(255) NOT NULL UNIQUE,
        api_key_hash VARCHAR(255) NOT NULL UNIQUE,
        active       BIT NOT NULL DEFAULT 1,
        created_at   DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        updated_at   DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET()
    );
END
GO

-- Nullable for now — existing rows have no client yet. See 0004, which
-- backfills this and enforces NOT NULL. Split in two so the operator can
-- create the first api_client (via cmd/createclient) in between.
IF NOT EXISTS (
    SELECT 1 FROM sys.columns
    WHERE object_id = OBJECT_ID('users') AND name = 'api_client_id'
)
BEGIN
    ALTER TABLE users ADD api_client_id VARCHAR(36) REFERENCES api_clients(id);
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_users_api_client_id')
BEGIN
    CREATE INDEX idx_users_api_client_id ON users(api_client_id);
END
GO
