-- Off-chain observation of the first concrete lab session derived from an issued credential.
-- These fields remain local audit data; they are not a replacement for future on-chain SessionStarted.

ALTER TABLE access_credential_audit
    ADD COLUMN session_id VARCHAR(128) NULL AFTER fmu_ticket_id,
    ADD COLUMN gateway_id VARCHAR(128) NULL AFTER session_id,
    ADD COLUMN session_observed_at DATETIME NULL AFTER expires_at,
    ADD COLUMN session_observation_type VARCHAR(32) NULL AFTER session_observed_at,
    ADD KEY idx_access_credential_session (session_id),
    ADD KEY idx_access_credential_gateway (gateway_id),
    ADD KEY idx_access_credential_observed (session_observed_at);
