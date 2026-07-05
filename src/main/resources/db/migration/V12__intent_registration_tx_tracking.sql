ALTER TABLE intents
    ADD COLUMN registration_tx_hash VARCHAR(80) NULL AFTER block_number,
    ADD COLUMN registration_block_number BIGINT NULL AFTER registration_tx_hash;
