-- Trusted devices: an additional "something you have" (device_token) +
-- "something you know" (pin) factor that lets a recognized device skip the
-- password+email-OTP flow. Lives in the same SQL Server database as `users`
-- (persistent, low-volume data) — no need for a separate database.

IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'trusted_devices')
BEGIN
    CREATE TABLE trusted_devices (
        id                  VARCHAR(36) PRIMARY KEY DEFAULT CONVERT(VARCHAR(36), NEWID()),
        user_id             VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        device_id           NVARCHAR(255) NOT NULL UNIQUE, -- generated once by the client app, stored in secure local storage
        device_name         NVARCHAR(255) NOT NULL DEFAULT '',
        device_token_hash   VARCHAR(255) NOT NULL, -- sha256 of a random bearer token; rotated on every successful use
        pin_hash            VARCHAR(255) NOT NULL, -- bcrypt of a 6-digit PIN, specific to this device
        failed_pin_attempts INT NOT NULL DEFAULT 0,
        revoked             BIT NOT NULL DEFAULT 0,
        trusted_at          DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        last_used_at        DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        expires_at          DATETIMEOFFSET NOT NULL,
        created_at          DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        updated_at          DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET()
    );
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_trusted_devices_user_id')
BEGIN
    CREATE INDEX idx_trusted_devices_user_id ON trusted_devices(user_id);
END
GO
