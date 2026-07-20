-- Durable event identity, processing state and polling cursor.
-- Rows are retained for replay/audit; DEAD_LETTER rows require operator review.
CREATE TABLE IF NOT EXISTS contract_event_journal (
    contract_address VARCHAR(128) NOT NULL,
    event_signature CHAR(66) NOT NULL,
    transaction_hash VARCHAR(128) NOT NULL,
    log_index DECIMAL(65, 0) NOT NULL,
    block_number DECIMAL(65, 0) NOT NULL,
    event_name VARCHAR(128) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'PENDING',
    attempts INT NOT NULL DEFAULT 0,
    lease_id VARCHAR(128) NULL,
    next_attempt_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_error VARCHAR(1024) NULL,
    first_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    processed_at DATETIME NULL,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (contract_address, event_signature, transaction_hash, log_index),
    KEY idx_contract_event_journal_retry (status, next_attempt_at, updated_at),
    KEY idx_contract_event_journal_block (contract_address, event_signature, block_number)
);

CREATE TABLE IF NOT EXISTS contract_event_cursor (
    contract_address VARCHAR(128) NOT NULL,
    event_signature CHAR(66) NOT NULL,
    last_processed_block DECIMAL(65, 0) NOT NULL,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (contract_address, event_signature)
);
