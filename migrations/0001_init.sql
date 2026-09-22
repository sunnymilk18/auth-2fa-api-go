-- Users table: persistent identity data lives here (SQL Server).
-- OTP codes are intentionally NOT stored here — they live in Redis with a TTL,
-- since they are short-lived and high-churn by nature.
--
-- IDs are VARCHAR(36) holding a string-formatted UUID (CONVERT(VARCHAR(36),
-- NEWID())) rather than SQL Server's native UNIQUEIDENTIFIER type — the Go
-- mssql driver returns UNIQUEIDENTIFIER values as raw 16-byte GUIDs, not
-- formatted strings, which would require extra conversion at every scan
-- site across the whole codebase. Storing the id as text keeps every Go
-- struct field (already typed as `string` everywhere, unchanged from the
-- Postgres version) working with a plain Scan(&s.ID), at the cost of a few
-- extra bytes per row — a non-issue at this app's scale.

IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'users')
BEGIN
    CREATE TABLE users (
        id            VARCHAR(36) PRIMARY KEY DEFAULT CONVERT(VARCHAR(36), NEWID()),
        email         NVARCHAR(320) NOT NULL, -- RFC 5321 max; unique per api_client_id, see 0004
        password_hash VARCHAR(255) NOT NULL,  -- bcrypt hash, ASCII
        is_active     BIT NOT NULL DEFAULT 1,
        created_at    DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        updated_at    DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET()
    );
END
GO

-- email's uniqueness used to be a plain UNIQUE constraint here, same as
-- Postgres — migration 0004 replaces it with a per-api_client_id unique
-- index once api_client_id exists, so nothing is added for it here.

IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'refresh_tokens')
BEGIN
    CREATE TABLE refresh_tokens (
        id         VARCHAR(36) PRIMARY KEY DEFAULT CONVERT(VARCHAR(36), NEWID()),
        user_id    VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash VARCHAR(64) NOT NULL UNIQUE, -- sha256 hex digest, fixed length
        expires_at DATETIMEOFFSET NOT NULL,
        revoked    BIT NOT NULL DEFAULT 0,
        created_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET()
    );
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_refresh_tokens_user_id')
BEGIN
    CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
END
GO
