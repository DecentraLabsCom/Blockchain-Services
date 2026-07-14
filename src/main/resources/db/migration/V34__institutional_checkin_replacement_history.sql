-- Preserve check-in hashes and bounded replacement fee state across retries.
ALTER TABLE institutional_checkin_outbox
    ADD COLUMN original_gas_price DECIMAL(65, 0) NULL AFTER nonce,
    ADD COLUMN current_gas_price DECIMAL(65, 0) NULL AFTER original_gas_price;

CREATE TABLE IF NOT EXISTS institutional_checkin_outbox_hash_history (
    id BIGINT NOT NULL AUTO_INCREMENT,
    outbox_id BIGINT NOT NULL,
    tx_hash VARCHAR(128) NOT NULL,
    gas_price DECIMAL(65, 0) NOT NULL,
    replaced_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_checkin_hash_history (outbox_id, tx_hash),
    KEY idx_checkin_hash_history_lookup (outbox_id, replaced_at)
);
