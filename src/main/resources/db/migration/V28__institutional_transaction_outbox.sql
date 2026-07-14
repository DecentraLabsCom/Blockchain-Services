-- Durable transaction attempts for generic institutional-wallet producers.
-- An unresolved row is intentionally a wallet barrier: later producers cannot
-- allocate a higher nonce and leave the chain waiting behind a missing one.
CREATE TABLE IF NOT EXISTS institutional_transaction_outbox (
    id BIGINT NOT NULL AUTO_INCREMENT,
    chain_id DECIMAL(65, 0) NOT NULL,
    wallet_address VARCHAR(64) NOT NULL,
    operation_key CHAR(64) NOT NULL,
    nonce DECIMAL(65, 0) NOT NULL,
    gas_price DECIMAL(65, 0) NOT NULL,
    gas_limit DECIMAL(65, 0) NOT NULL,
    to_address VARCHAR(128) NOT NULL,
    value_wei DECIMAL(65, 0) NOT NULL,
    data LONGTEXT NOT NULL,
    signed_raw_transaction LONGTEXT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'RESERVED',
    attempts INT NOT NULL DEFAULT 0,
    tx_hash VARCHAR(128) NULL,
    last_error TEXT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_institutional_transaction_operation (chain_id, wallet_address, operation_key),
    UNIQUE KEY uk_institutional_transaction_nonce (chain_id, wallet_address, nonce),
    KEY idx_institutional_transaction_blocker (chain_id, wallet_address, status, nonce)
);
