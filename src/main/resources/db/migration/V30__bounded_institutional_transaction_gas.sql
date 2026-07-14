-- Keep the original fee basis separate from the latest replacement fee.
-- Existing rows are initialized from the pre-V30 gas_price value before the
-- old accumulator column is removed.
ALTER TABLE institutional_transaction_outbox
    ADD COLUMN original_gas_price DECIMAL(65, 0) NULL AFTER nonce,
    ADD COLUMN current_gas_price DECIMAL(65, 0) NULL AFTER original_gas_price;

UPDATE institutional_transaction_outbox
SET original_gas_price = gas_price,
    current_gas_price = gas_price
WHERE original_gas_price IS NULL OR current_gas_price IS NULL;

ALTER TABLE institutional_transaction_outbox
    MODIFY COLUMN original_gas_price DECIMAL(65, 0) NOT NULL,
    MODIFY COLUMN current_gas_price DECIMAL(65, 0) NOT NULL,
    DROP COLUMN gas_price;
