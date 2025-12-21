-- WebAuthn credential storage.

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    puc VARCHAR(255) NOT NULL,
    credential_id VARCHAR(255) NOT NULL,
    public_key TEXT NOT NULL,
    aaguid VARCHAR(64),
    sign_count BIGINT DEFAULT 0,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP NULL,
    PRIMARY KEY (puc, credential_id),
    INDEX idx_webauthn_puc_active (puc, active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
