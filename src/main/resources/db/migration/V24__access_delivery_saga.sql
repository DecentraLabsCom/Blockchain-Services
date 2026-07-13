-- Complete the access-delivery saga and remove plaintext bearer material.
-- Existing in-flight codes cannot be encrypted safely inside SQL, so they are
-- revoked during this security migration and must be reissued.

ALTER TABLE lab_access_codes
    MODIFY COLUMN access_token TEXT NULL,
    ADD COLUMN access_token_ciphertext MEDIUMTEXT NULL AFTER access_token,
    ADD COLUMN recoverable_code_ciphertext TEXT NULL AFTER recoverable_code,
    ADD COLUMN resource_type VARCHAR(16) NULL AFTER lab_url;

UPDATE lab_access_codes
SET consumed_at = COALESCE(consumed_at, CURRENT_TIMESTAMP),
    recoverable_code = NULL,
    access_token = NULL
WHERE access_token IS NOT NULL OR recoverable_code IS NOT NULL;

UPDATE access_authorization_provisioning
SET status = CASE
    WHEN status = 'PREPARING' THEN 'PREPARED'
    WHEN status = 'DELIVERED' THEN 'REVOKED'
    ELSE status
END;
