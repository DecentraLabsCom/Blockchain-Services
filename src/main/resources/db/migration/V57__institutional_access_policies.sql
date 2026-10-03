CREATE TABLE IF NOT EXISTS access_policy_profiles (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    institution_id VARCHAR(255) NOT NULL,
    name VARCHAR(200) NOT NULL,
    version INT NOT NULL,
    default_decision VARCHAR(16) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    groups_json JSON NOT NULL,
    overrides_json JSON NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_access_policy_profiles_institution (institution_id),
    CONSTRAINT chk_access_policy_default_decision CHECK (default_decision IN ('ALLOW', 'DENY'))
);

CREATE TABLE IF NOT EXISTS institutional_identity_contexts (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    institution_id VARCHAR(255) NOT NULL,
    identity_reference_hash CHAR(66) NOT NULL,
    auth_method VARCHAR(32) NOT NULL,
    issuer VARCHAR(500),
    attributes_json JSON NOT NULL,
    observed_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NULL,
    invalidated_at TIMESTAMP NULL,
    UNIQUE KEY uq_identity_context_reference (institution_id, identity_reference_hash),
    INDEX idx_identity_context_expiry (institution_id, expires_at)
);

CREATE TABLE IF NOT EXISTS access_policy_audit_events (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    institution_id VARCHAR(255) NOT NULL,
    policy_version INT NOT NULL,
    event_type VARCHAR(40) NOT NULL,
    actor VARCHAR(255),
    details_json JSON NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_access_policy_audit (institution_id, created_at)
);
