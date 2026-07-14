-- Preserve every hash that was superseded by a same-nonce replacement.
-- The current hash remains on institutional_transaction_outbox; this table
-- contains only hashes that must still be reconciled after a later bump.
CREATE TABLE IF NOT EXISTS institutional_transaction_outbox_hash_history (
    id BIGINT NOT NULL AUTO_INCREMENT,
    outbox_id BIGINT NOT NULL,
    tx_hash VARCHAR(128) NOT NULL,
    gas_price DECIMAL(65, 0) NOT NULL,
    replaced_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_institutional_transaction_hash_history (outbox_id, tx_hash),
    KEY idx_institutional_transaction_hash_history_lookup (outbox_id, replaced_at)
);
