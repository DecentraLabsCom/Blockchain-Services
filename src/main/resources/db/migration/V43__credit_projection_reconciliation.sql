-- Make the on-chain credit movement projection idempotent.

ALTER TABLE credit_movements
    MODIFY COLUMN movement_type ENUM('MINT','LOCK','CAPTURE','RELEASE','CANCEL','ADJUST','EXPIRE') NOT NULL;

ALTER TABLE credit_movements
    ADD COLUMN source_key VARCHAR(128) NULL AFTER reference;

CREATE UNIQUE INDEX uq_cm_account_source
    ON credit_movements (account_address, source_key);
