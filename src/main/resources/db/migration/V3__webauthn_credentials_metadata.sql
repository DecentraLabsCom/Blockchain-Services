-- Add optional metadata columns for WebAuthn credentials.

ALTER TABLE webauthn_credentials
    ADD COLUMN IF NOT EXISTS authenticator_attachment VARCHAR(32) NULL,
    ADD COLUMN IF NOT EXISTS resident_key BOOLEAN NULL,
    ADD COLUMN IF NOT EXISTS transports TEXT NULL;
