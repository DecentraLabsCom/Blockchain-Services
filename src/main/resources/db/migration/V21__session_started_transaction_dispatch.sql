ALTER TABLE session_started_attestations
    ADD COLUMN onchain_wallet_address VARCHAR(42) NULL,
    ADD COLUMN onchain_nonce DECIMAL(65, 0) NULL,
    ADD COLUMN onchain_status VARCHAR(24) NOT NULL DEFAULT 'QUEUED',
    ADD COLUMN onchain_submitted_at TIMESTAMP NULL,
    ADD COLUMN onchain_mined_at TIMESTAMP NULL,
    ADD CONSTRAINT uq_session_started_wallet_nonce UNIQUE (onchain_wallet_address, onchain_nonce),
    ADD KEY idx_session_started_transaction_status (onchain_status, updated_at);

UPDATE session_started_attestations
SET onchain_status = CASE
    WHEN onchain_published_at IS NOT NULL THEN 'MINED_SUCCESS'
    WHEN onchain_tx_hash IS NOT NULL THEN 'SUBMITTED'
    ELSE 'QUEUED'
END;
