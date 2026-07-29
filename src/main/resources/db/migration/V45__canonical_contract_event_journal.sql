-- Bind event journal rows to the chain and canonical block that produced them.
-- Legacy rows are retained as UNKNOWN evidence and will be replayed in the
-- active chain context after this migration.
ALTER TABLE contract_event_journal
    ADD COLUMN chain_id DECIMAL(65, 0) NULL FIRST,
    ADD COLUMN block_hash VARCHAR(128) NULL AFTER block_number,
    ADD COLUMN confirmations DECIMAL(65, 0) NOT NULL DEFAULT 0 AFTER block_hash,
    ADD COLUMN canonical_status VARCHAR(16) NOT NULL DEFAULT 'UNKNOWN' AFTER confirmations,
    ADD KEY idx_contract_event_journal_chain_block (chain_id, contract_address, block_number, block_hash);

UPDATE contract_event_journal
SET chain_id = 0,
    block_hash = CONCAT('legacy:', transaction_hash, ':', block_number),
    canonical_status = 'UNKNOWN'
WHERE chain_id IS NULL OR block_hash IS NULL;

ALTER TABLE contract_event_journal
    MODIFY COLUMN chain_id DECIMAL(65, 0) NOT NULL,
    MODIFY COLUMN block_hash VARCHAR(128) NOT NULL,
    DROP PRIMARY KEY,
    ADD PRIMARY KEY (chain_id, contract_address, event_signature, transaction_hash, block_hash, block_number, log_index);

ALTER TABLE contract_event_cursor
    ADD COLUMN chain_id DECIMAL(65, 0) NULL FIRST,
    ADD COLUMN last_processed_block_hash VARCHAR(128) NULL AFTER last_processed_block,
    ADD KEY idx_contract_event_cursor_chain (chain_id, contract_address, event_signature);

UPDATE contract_event_cursor
SET chain_id = 0
WHERE chain_id IS NULL;

ALTER TABLE contract_event_cursor
    MODIFY COLUMN chain_id DECIMAL(65, 0) NOT NULL,
    MODIFY COLUMN last_processed_block_hash VARCHAR(128) NULL,
    DROP PRIMARY KEY,
    ADD PRIMARY KEY (chain_id, contract_address, event_signature);
