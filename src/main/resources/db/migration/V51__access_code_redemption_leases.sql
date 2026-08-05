-- Keep a browser redemption pending while the gateway verifies the JWT and
-- prepares its local session state. Consumption happens only on commit.
ALTER TABLE lab_access_codes
    ADD COLUMN redemption_handle_hash CHAR(64) NULL AFTER consumed_at,
    ADD COLUMN redemption_expires_at DATETIME NULL AFTER redemption_handle_hash,
    ADD KEY idx_lab_access_redemption_lease (
        target_gateway_id, redemption_handle_hash, redemption_expires_at
    );
