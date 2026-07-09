ALTER TABLE session_started_attestations
    ADD COLUMN onchain_tx_hash VARCHAR(66) NULL,
    ADD COLUMN onchain_published_at TIMESTAMP NULL,
    ADD COLUMN onchain_publish_locked_at TIMESTAMP NULL,
    ADD COLUMN onchain_publish_attempts INT NOT NULL DEFAULT 0,
    ADD COLUMN onchain_publish_last_error TEXT NULL,
    ADD KEY idx_session_started_onchain_pending (
        onchain_published_at,
        onchain_publish_locked_at,
        created_at
    );
