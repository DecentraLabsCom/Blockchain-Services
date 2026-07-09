-- Off-chain audit for concrete access credentials issued for a reservation.
-- Stores hashes/identifiers only; raw JWTs and raw session tickets must not be persisted.

CREATE TABLE IF NOT EXISTS access_credential_audit (
    id BIGINT NOT NULL AUTO_INCREMENT,
    reservation_key VARCHAR(80) NOT NULL,
    lab_id VARCHAR(64),
    puc_hash VARCHAR(66),
    access_type VARCHAR(32) NOT NULL,
    jwt_jti VARCHAR(128),
    guac_username VARCHAR(128),
    fmu_ticket_id VARCHAR(128),
    issued_at DATETIME,
    expires_at DATETIME,
    issuer_backend_id VARCHAR(128),
    credential_hash CHAR(64) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_access_credential_hash (credential_hash),
    KEY idx_access_credential_reservation (reservation_key),
    KEY idx_access_credential_jti (jwt_jti),
    KEY idx_access_credential_type (access_type),
    KEY idx_access_credential_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
