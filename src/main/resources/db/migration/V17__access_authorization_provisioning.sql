-- Coordinates provisional provider access across backend instances.
-- Raw JWTs and Guacamole credentials are never stored here.
CREATE TABLE IF NOT EXISTS access_authorization_provisioning (
    reservation_key VARCHAR(80) NOT NULL,
    status VARCHAR(32) NOT NULL,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (reservation_key),
    INDEX idx_access_authorization_provisioning_status_updated (status, updated_at)
);

-- Submission and receipt confirmation are separate outbox phases.
ALTER TABLE institutional_checkin_outbox
    ADD KEY idx_checkin_outbox_receipts (status, updated_at);

-- Durable per-wallet nonce allocation for concurrent institutional check-ins.
ALTER TABLE institutional_checkin_outbox
    ADD COLUMN wallet_address VARCHAR(64) NULL AFTER institutional_wallet,
    ADD COLUMN nonce DECIMAL(78, 0) NULL AFTER tx_hash,
    ADD COLUMN submitted_at DATETIME NULL AFTER nonce,
    ADD COLUMN mined_at DATETIME NULL AFTER submitted_at,
    ADD UNIQUE KEY uk_checkin_outbox_wallet_nonce (wallet_address, nonce),
    ADD KEY idx_checkin_outbox_wallet_status (wallet_address, status, updated_at);

UPDATE institutional_checkin_outbox
SET wallet_address = institutional_wallet
WHERE wallet_address IS NULL;

ALTER TABLE institutional_checkin_outbox
    MODIFY COLUMN wallet_address VARCHAR(64) NOT NULL;

CREATE TABLE IF NOT EXISTS institutional_wallet_nonce (
    wallet_address VARCHAR(64) NOT NULL,
    next_nonce DECIMAL(78, 0) NOT NULL,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (wallet_address)
);

CREATE TABLE IF NOT EXISTS lab_access_codes (
    code_hash CHAR(64) NOT NULL,
    access_token TEXT NOT NULL,
    lab_url VARCHAR(2048) NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (code_hash),
    INDEX idx_lab_access_codes_expiry (expires_at)
);
