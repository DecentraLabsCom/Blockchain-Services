-- Add optional metadata columns for WebAuthn credentials.

ALTER TABLE webauthn_credentials
    ADD COLUMN authenticator_attachment VARCHAR(32) NULL;

ALTER TABLE webauthn_credentials
    ADD COLUMN resident_key BOOLEAN NULL;

ALTER TABLE webauthn_credentials
    ADD COLUMN transports TEXT NULL;
