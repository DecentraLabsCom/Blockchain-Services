ALTER TABLE lab_access_codes
    ADD COLUMN reservation_key VARCHAR(80) NULL,
    ADD COLUMN provisioning_generation BIGINT UNSIGNED NULL,
    ADD COLUMN recoverable_code VARCHAR(128) NULL,
    ADD COLUMN credential_expires_at DATETIME NULL,
    ADD COLUMN consumed_at DATETIME NULL,
    ADD CONSTRAINT uq_lab_access_delivery UNIQUE (reservation_key, provisioning_generation),
    ADD KEY idx_lab_access_delivery_recovery (
        reservation_key, provisioning_generation, consumed_at, credential_expires_at
    );
