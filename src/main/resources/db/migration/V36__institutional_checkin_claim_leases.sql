-- Durable ownership for check-in outbox workers running on multiple replicas.
ALTER TABLE institutional_checkin_outbox
    ADD COLUMN claim_id CHAR(36) NULL AFTER version,
    ADD COLUMN claimed_by VARCHAR(128) NULL AFTER claim_id,
    ADD COLUMN claim_version BIGINT NULL AFTER claimed_by,
    ADD COLUMN claim_expires_at DATETIME(6) NULL AFTER claim_version,
    ADD KEY idx_checkin_outbox_claim (claim_id, claim_expires_at);
