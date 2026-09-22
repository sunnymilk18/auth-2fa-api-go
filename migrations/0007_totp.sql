-- Adds optional TOTP (Google Authenticator-style) two-factor as an
-- alternative to the email OTP flow — opt-in per account, activated from
-- an already-authenticated session (see auth.Service.StartTOTPEnrollment),
-- same shape as the existing trusted-device+PIN shortcut.
--
-- totp_secret_enc stores the secret AES-256-GCM-encrypted (see
-- auth.TOTPManager) under an app-level key (TOTP_ENCRYPTION_KEY), never in
-- plain text: unlike password_hash, the server must recover the actual
-- secret to compute whether a code is currently valid, so it can't be
-- one-way hashed the way a password is — encryption at rest is the
-- equivalent protection here.
--
-- totp_enabled stays FALSE while a secret exists but hasn't been confirmed
-- yet (a QR was generated but never successfully scanned+verified) — see
-- ConfirmTOTPEnrollment — so LoginStep1 never starts expecting TOTP codes
-- for an account that never finished setup.
--
-- Guarded on the column not existing yet — same idempotency requirement
-- every migration here has (testutil.MSSQLPool re-applies every *.sql file
-- before each test).
IF NOT EXISTS (
    SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('users') AND name = 'totp_secret_enc'
)
BEGIN
    ALTER TABLE users ADD totp_secret_enc NVARCHAR(MAX) NULL;
    ALTER TABLE users ADD totp_enabled BIT NOT NULL DEFAULT 0;
END
GO
