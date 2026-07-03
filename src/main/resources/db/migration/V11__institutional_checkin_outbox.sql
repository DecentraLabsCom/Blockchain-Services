-- Durable outbox for access-granted institutional check-ins.

CREATE TABLE IF NOT EXISTS institutional_checkin_outbox (
    id BIGINT NOT NULL AUTO_INCREMENT,
    reservation_key VARCHAR(80) NOT NULL,
    lab_id VARCHAR(64),
    institutional_wallet VARCHAR(64) NOT NULL,
    puc_hash VARCHAR(66) NOT NULL,
    access_session_id VARCHAR(128),
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    attempts INT NOT NULL DEFAULT 0,
    next_attempt_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    tx_hash VARCHAR(128),
    last_error TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_checkin_outbox_reservation (reservation_key),
    KEY idx_checkin_outbox_due (status, next_attempt_at),
    KEY idx_checkin_outbox_wallet (institutional_wallet)
);
