-- Trusted devices: an additional "something you have" (device_token) +
-- "something you know" (pin) factor that lets a recognized device skip the
-- password+email-OTP flow. Lives in the same Postgres database as `users`
-- (persistent, low-volume data) — no need for a separate database.

CREATE TABLE IF NOT EXISTS trusted_devices (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id           TEXT NOT NULL UNIQUE, -- generated once by the client app, stored in secure local storage
    device_name         TEXT NOT NULL DEFAULT '',
    device_token_hash   TEXT NOT NULL, -- sha256 of a random bearer token; rotated on every successful use
    pin_hash            TEXT NOT NULL, -- bcrypt of a 6-digit PIN, specific to this device
    failed_pin_attempts INT NOT NULL DEFAULT 0,
    revoked             BOOLEAN NOT NULL DEFAULT FALSE,
    trusted_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_trusted_devices_user_id ON trusted_devices(user_id);
