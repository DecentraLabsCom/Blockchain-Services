ALTER TABLE lab_access_codes
    ADD COLUMN target_gateway_id VARCHAR(128) NULL AFTER lab_url,
    ADD KEY idx_lab_access_code_target (target_gateway_id, expires_at);

ALTER TABLE access_credential_audit
    ADD COLUMN target_gateway_id VARCHAR(128) NULL AFTER gateway_id,
    ADD KEY idx_access_credential_target_gateway (target_gateway_id);

ALTER TABLE institutional_checkin_outbox
    ADD COLUMN version BIGINT NOT NULL DEFAULT 0 AFTER attempts;
