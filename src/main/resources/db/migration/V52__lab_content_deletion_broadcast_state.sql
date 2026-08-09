-- Keep the local content hand-off state separate from the outcome of the
-- deleteLab broadcast. A prepared row must remain reconcilable even when the
-- RPC fails before web3j returns a receipt.
ALTER TABLE lab_content_deletion_outbox
    ADD COLUMN operation_key VARCHAR(255) NULL AFTER transaction_hash,
    ADD COLUMN broadcast_status VARCHAR(32) NOT NULL DEFAULT 'PREPARED' AFTER operation_key;

CREATE INDEX idx_lab_content_deletion_broadcast
    ON lab_content_deletion_outbox (broadcast_status, status, next_attempt_at);
