-- Fence generic outbox workers and SessionStarted replacements across replicas.
ALTER TABLE institutional_transaction_outbox
    ADD COLUMN version BIGINT NOT NULL DEFAULT 0 AFTER attempts;

ALTER TABLE session_started_attestations
    ADD COLUMN onchain_version BIGINT NOT NULL DEFAULT 0 AFTER onchain_publish_attempts,
    ADD COLUMN onchain_original_gas_price DECIMAL(65, 0) NULL AFTER onchain_nonce,
    ADD COLUMN onchain_current_gas_price DECIMAL(65, 0) NULL AFTER onchain_original_gas_price;

CREATE TABLE IF NOT EXISTS session_started_attestation_hash_history (
    id BIGINT NOT NULL AUTO_INCREMENT,
    attestation_id BIGINT NOT NULL,
    tx_hash VARCHAR(128) NOT NULL,
    gas_price DECIMAL(65, 0) NOT NULL,
    replaced_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_session_started_hash_history (attestation_id, tx_hash),
    KEY idx_session_started_hash_history_lookup (attestation_id, replaced_at)
);
