-- Durable, encrypted WebAuthn sessions for intent authorization.
-- The payload contains the original intent/SAML context and is encrypted by
-- IntentPayloadCipher before it reaches this table.
CREATE TABLE IF NOT EXISTS intent_authorization_sessions (
    session_id CHAR(32) PRIMARY KEY,
    request_id VARCHAR(66) NOT NULL,
    status VARCHAR(32) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    payload_ciphertext MEDIUMTEXT NOT NULL,
    result_error TEXT NULL,
    result_http_status SMALLINT NULL,
    result_ack_json TEXT NULL,
    completed_at DATETIME(6) NULL,
    retention_expires_at DATETIME(6) NULL,
    version BIGINT NOT NULL DEFAULT 0,
    claim_id CHAR(36) NULL,
    claimed_by VARCHAR(128) NULL,
    claim_version BIGINT NULL,
    claim_expires_at DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    INDEX idx_intent_auth_session_request (request_id),
    INDEX idx_intent_auth_session_status_expiry (status, expires_at),
    INDEX idx_intent_auth_session_retention (status, retention_expires_at),
    INDEX idx_intent_auth_session_claim (claim_id, claim_expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
