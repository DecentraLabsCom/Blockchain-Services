-- Durable WebAuthn intent sessions and monotonic/distributed intent execution.

CREATE TABLE IF NOT EXISTS intent_authorization_sessions (
    session_id VARCHAR(64) NOT NULL,
    request_id VARCHAR(66) NOT NULL,
    status VARCHAR(32) NOT NULL,
    submission_ciphertext LONGTEXT NULL,
    credential_ids_json JSON NULL,
    challenge TEXT NULL,
    return_url VARCHAR(2048) NULL,
    expires_at DATETIME(6) NOT NULL,
    error TEXT NULL,
    completed_at DATETIME(6) NULL,
    version BIGINT NOT NULL DEFAULT 0,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (session_id),
    UNIQUE KEY uk_intent_authorization_request (request_id),
    KEY idx_intent_authorization_status_expiry (status, expires_at)
);

ALTER TABLE intents
    ADD COLUMN worker_id VARCHAR(96) NULL AFTER status,
    ADD COLUMN execution_version BIGINT NOT NULL DEFAULT 0 AFTER worker_id,
    ADD COLUMN institutional_wallet_address VARCHAR(64) NULL AFTER execution_version,
    ADD COLUMN transaction_nonce DECIMAL(65, 0) NULL AFTER institutional_wallet_address,
    ADD COLUMN replacement_generation INT NOT NULL DEFAULT 0 AFTER transaction_nonce,
    ADD COLUMN submitted_at DATETIME(6) NULL AFTER tx_hash,
    ADD KEY idx_intents_claim (status, updated_at),
    ADD CONSTRAINT uq_intents_institutional_wallet_nonce
        UNIQUE (institutional_wallet_address, transaction_nonce);
