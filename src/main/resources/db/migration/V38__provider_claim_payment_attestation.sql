-- M-03: make provider settlement a traceable claim lifecycle.
-- Existing rows receive explicit legacy markers; all new writes are validated
-- by ProviderSettlementService and carry the full claim/payment references.

ALTER TABLE provider_invoice_records
    ADD COLUMN claim_id VARCHAR(128) NULL COMMENT 'Stable settlement claim identifier',
    ADD COLUMN reservation_hash CHAR(66) NULL COMMENT 'Hash of the canonical reservation-key set';

UPDATE provider_invoice_records
SET claim_id = CONCAT('legacy-claim-', id)
WHERE claim_id IS NULL;

UPDATE provider_invoice_records
SET reservation_hash = CONCAT('0x', REPEAT('0', 64))
WHERE reservation_hash IS NULL;

ALTER TABLE provider_invoice_records
    MODIFY COLUMN claim_id VARCHAR(128) NOT NULL,
    MODIFY COLUMN reservation_hash CHAR(66) NOT NULL,
    ADD UNIQUE KEY uq_pir_claim_id (claim_id);

ALTER TABLE provider_payouts
    ADD COLUMN invoice_record_id BIGINT NULL COMMENT 'Claim invoice settled by this payment',
    ADD COLUMN claim_id VARCHAR(128) NULL COMMENT 'Stable settlement claim identifier',
    ADD COLUMN paid_by VARCHAR(42) NULL COMMENT 'Actor recording the verified payment',
    ADD COLUMN payment_ref VARCHAR(256) NULL COMMENT 'Unique external payment reference',
    ADD COLUMN payment_attestation VARCHAR(256) NULL COMMENT 'Financial-system or signed payment proof';

UPDATE provider_payouts
SET claim_id = CONCAT('legacy-claim-payout-', id),
    paid_by = 'legacy-migration',
    payment_ref = CONCAT('legacy-payment-', id),
    payment_attestation = 'legacy-migration'
WHERE claim_id IS NULL OR paid_by IS NULL OR payment_ref IS NULL OR payment_attestation IS NULL;

ALTER TABLE provider_payouts
    MODIFY COLUMN claim_id VARCHAR(128) NOT NULL,
    MODIFY COLUMN paid_by VARCHAR(42) NOT NULL,
    MODIFY COLUMN payment_ref VARCHAR(256) NOT NULL,
    MODIFY COLUMN payment_attestation VARCHAR(256) NOT NULL,
    ADD UNIQUE KEY uq_pp_payment_ref (payment_ref),
    ADD INDEX idx_pp_invoice (invoice_record_id),
    ADD CONSTRAINT fk_pp_invoice FOREIGN KEY (invoice_record_id)
        REFERENCES provider_invoice_records(id);
