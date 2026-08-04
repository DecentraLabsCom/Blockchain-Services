-- Durable hand-off between confirmed on-chain lab deletion and filesystem
-- tombstoning. Rows are retained through PURGED for audit and recovery.
CREATE TABLE IF NOT EXISTS lab_content_deletion_outbox (
    id BIGINT NOT NULL AUTO_INCREMENT,
    lab_id DECIMAL(65, 0) NOT NULL,
    metadata_uri VARCHAR(2048) NULL,
    content_relative_path VARCHAR(512) NULL,
    transaction_hash VARCHAR(128) NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING_TOMBSTONE',
    attempts INT NOT NULL DEFAULT 0,
    next_attempt_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at DATETIME NULL,
    last_error VARCHAR(1024) NULL,
    lease_id VARCHAR(128) NULL,
    lease_expires_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_lab_content_deletion_lab (lab_id),
    KEY idx_lab_content_deletion_due (status, next_attempt_at, transaction_hash),
    KEY idx_lab_content_deletion_path (content_relative_path, status)
);
