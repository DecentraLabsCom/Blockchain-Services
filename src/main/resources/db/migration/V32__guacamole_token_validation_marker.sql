-- A Guacamole token is known to be valid when OpenResty receives it from
-- Guacamole and durably registers it before returning it to the browser.
-- This marker lets post-revocation history reconciliation prove the original
-- capability without trying to reuse the revoked bearer token.
ALTER TABLE guacamole_token_revocation_queue
    ADD COLUMN token_validated_at DATETIME NULL AFTER token_ciphertext;
