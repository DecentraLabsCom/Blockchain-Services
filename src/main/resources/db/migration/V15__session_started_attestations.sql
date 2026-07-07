-- Provider-signed off-chain evidence that an issued access credential produced
-- an observed lab session. This is the local audit source for future on-chain
-- SessionStarted submission.

CREATE TABLE IF NOT EXISTS session_started_attestations (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    reservation_key VARCHAR(66) NOT NULL,
    lab_id VARCHAR(128) NULL,
    puc_hash VARCHAR(66) NULL,
    signer_address VARCHAR(42) NOT NULL,
    gateway_id VARCHAR(128) NULL,
    session_id VARCHAR(128) NOT NULL,
    access_type VARCHAR(32) NOT NULL,
    started_at DATETIME NOT NULL,
    nonce VARCHAR(66) NOT NULL,
    credential_hash VARCHAR(64) NULL,
    client_proof_hash VARCHAR(66) NULL,
    digest VARCHAR(66) NOT NULL,
    signature VARCHAR(132) NOT NULL,
    credential_reference_type VARCHAR(32) NOT NULL,
    credential_reference_id VARCHAR(128) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_session_started_nonce (nonce),
    UNIQUE KEY uq_session_started_observation (reservation_key, session_id, access_type),
    KEY idx_session_started_reservation (reservation_key),
    KEY idx_session_started_signer (signer_address),
    KEY idx_session_started_started_at (started_at)
);
