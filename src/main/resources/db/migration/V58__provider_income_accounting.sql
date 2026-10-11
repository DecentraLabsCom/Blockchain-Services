-- Durable provider-income attribution by reservation generation and settlement scope.
CREATE TABLE IF NOT EXISTS provider_income_reservations (
    chain_id DECIMAL(65,0) NOT NULL,
    contract_address VARCHAR(42) NOT NULL,
    reservation_id CHAR(66) NOT NULL,
    reservation_key CHAR(66) NOT NULL,
    lab_id VARCHAR(78) NOT NULL,
    provider_address VARCHAR(42) NOT NULL,
    access_uri VARCHAR(512) NULL,
    gateway_id VARCHAR(255) NULL,
    price_raw VARCHAR(78) NOT NULL,
    provider_share_raw VARCHAR(78) NOT NULL,
    transaction_hash VARCHAR(66) NOT NULL,
    log_index DECIMAL(65,0) NOT NULL,
    block_number DECIMAL(65,0) NOT NULL,
    block_hash VARCHAR(128) NOT NULL,
    transaction_index DECIMAL(65,0) NOT NULL DEFAULT 0,
    event_signature CHAR(66) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (chain_id, contract_address, reservation_id),
    KEY idx_provider_income_reservation_lab (chain_id, contract_address, lab_id),
    KEY idx_provider_income_reservation_gateway (chain_id, contract_address, gateway_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS provider_income_accruals (
    chain_id DECIMAL(65,0) NOT NULL,
    contract_address VARCHAR(42) NOT NULL,
    transaction_hash VARCHAR(66) NOT NULL,
    log_index DECIMAL(65,0) NOT NULL,
    block_number DECIMAL(65,0) NOT NULL,
    block_hash VARCHAR(128) NOT NULL,
    transaction_index DECIMAL(65,0) NOT NULL DEFAULT 0,
    event_signature CHAR(66) NOT NULL,
    lab_id VARCHAR(78) NOT NULL,
    reservation_id CHAR(66) NOT NULL,
    amount_raw VARCHAR(78) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (chain_id, contract_address, transaction_hash, block_hash, log_index),
    KEY idx_provider_income_accrual_scope (chain_id, contract_address, lab_id, block_number, transaction_index, log_index),
    KEY idx_provider_income_accrual_reservation (chain_id, contract_address, reservation_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS provider_income_batches (
    chain_id DECIMAL(65,0) NOT NULL,
    contract_address VARCHAR(42) NOT NULL,
    batch_id CHAR(66) NOT NULL,
    lab_id VARCHAR(78) NOT NULL,
    amount_raw VARCHAR(78) NOT NULL,
    scope_root CHAR(66) NOT NULL,
    transaction_hash VARCHAR(66) NOT NULL,
    log_index DECIMAL(65,0) NOT NULL,
    block_number DECIMAL(65,0) NOT NULL,
    block_hash VARCHAR(128) NOT NULL,
    transaction_index DECIMAL(65,0) NOT NULL DEFAULT 0,
    event_signature CHAR(66) NOT NULL,
    source_status VARCHAR(24) NOT NULL DEFAULT 'PENDING',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (chain_id, contract_address, batch_id),
    KEY idx_provider_income_batch_lab (chain_id, contract_address, lab_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS provider_income_batch_sources (
    chain_id DECIMAL(65,0) NOT NULL,
    contract_address VARCHAR(42) NOT NULL,
    batch_id CHAR(66) NOT NULL,
    accrual_transaction_hash VARCHAR(66) NOT NULL,
    accrual_block_hash VARCHAR(128) NOT NULL,
    accrual_log_index DECIMAL(65,0) NOT NULL,
    reservation_id CHAR(66) NOT NULL,
    amount_raw VARCHAR(78) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (chain_id, contract_address, batch_id, accrual_transaction_hash, accrual_block_hash, accrual_log_index),
    KEY idx_provider_income_batch_source_reservation (chain_id, contract_address, reservation_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS provider_income_settlement_events (
    chain_id DECIMAL(65,0) NOT NULL,
    contract_address VARCHAR(42) NOT NULL,
    transaction_hash VARCHAR(66) NOT NULL,
    log_index DECIMAL(65,0) NOT NULL,
    block_number DECIMAL(65,0) NOT NULL,
    block_hash VARCHAR(128) NOT NULL,
    transaction_index DECIMAL(65,0) NOT NULL DEFAULT 0,
    event_signature CHAR(66) NOT NULL,
    activity VARCHAR(32) NOT NULL,
    batch_id CHAR(66) NULL,
    claim_id CHAR(66) NULL,
    lab_id VARCHAR(78) NULL,
    amount_raw VARCHAR(78) NULL,
    scope_root CHAR(66) NULL,
    target_status INT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (chain_id, contract_address, transaction_hash, block_hash, log_index),
    KEY idx_provider_income_settlement_batch (chain_id, contract_address, batch_id),
    KEY idx_provider_income_settlement_claim (chain_id, contract_address, claim_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
