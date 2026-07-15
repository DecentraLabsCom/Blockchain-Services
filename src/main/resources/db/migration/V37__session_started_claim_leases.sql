-- Durable ownership for SessionStarted publishers running on multiple replicas.
ALTER TABLE session_started_attestations
    ADD COLUMN onchain_claim_id CHAR(36) NULL AFTER onchain_version,
    ADD COLUMN onchain_claimed_by VARCHAR(128) NULL AFTER onchain_claim_id,
    ADD COLUMN onchain_claim_version BIGINT NULL AFTER onchain_claimed_by,
    ADD COLUMN onchain_claim_expires_at DATETIME(6) NULL AFTER onchain_claim_version,
    ADD KEY idx_session_started_claim (onchain_claim_id, onchain_claim_expires_at);
