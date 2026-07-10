-- Add fencing and lease heartbeats to installations that already ran V17.
-- Every statement is guarded so this migration is safe after a partial/manual
-- rollout and on both MySQL and MariaDB.

SET @schema_name = DATABASE();

SET @column_exists = (
    SELECT COUNT(*)
    FROM information_schema.columns
    WHERE table_schema = @schema_name
      AND table_name = 'access_authorization_provisioning'
      AND column_name = 'fencing_token'
);
SET @sql = IF(
    @column_exists = 0,
    'ALTER TABLE access_authorization_provisioning ADD COLUMN fencing_token CHAR(36) NULL AFTER status',
    'SELECT 1'
);
PREPARE add_fencing_token FROM @sql;
EXECUTE add_fencing_token;
DEALLOCATE PREPARE add_fencing_token;

SET @column_exists = (
    SELECT COUNT(*)
    FROM information_schema.columns
    WHERE table_schema = @schema_name
      AND table_name = 'access_authorization_provisioning'
      AND column_name = 'generation'
);
SET @sql = IF(
    @column_exists = 0,
    'ALTER TABLE access_authorization_provisioning ADD COLUMN generation BIGINT UNSIGNED NOT NULL DEFAULT 1 AFTER fencing_token',
    'SELECT 1'
);
PREPARE add_generation FROM @sql;
EXECUTE add_generation;
DEALLOCATE PREPARE add_generation;

SET @column_exists = (
    SELECT COUNT(*)
    FROM information_schema.columns
    WHERE table_schema = @schema_name
      AND table_name = 'access_authorization_provisioning'
      AND column_name = 'heartbeat_at'
);
SET @sql = IF(
    @column_exists = 0,
    'ALTER TABLE access_authorization_provisioning ADD COLUMN heartbeat_at DATETIME NULL AFTER generation',
    'SELECT 1'
);
PREPARE add_heartbeat_at FROM @sql;
EXECUTE add_heartbeat_at;
DEALLOCATE PREPARE add_heartbeat_at;

SET @column_exists = (
    SELECT COUNT(*)
    FROM information_schema.columns
    WHERE table_schema = @schema_name
      AND table_name = 'access_authorization_provisioning'
      AND column_name = 'expires_at'
);
SET @sql = IF(
    @column_exists = 0,
    'ALTER TABLE access_authorization_provisioning ADD COLUMN expires_at DATETIME NULL AFTER heartbeat_at',
    'SELECT 1'
);
PREPARE add_expires_at FROM @sql;
EXECUTE add_expires_at;
DEALLOCATE PREPARE add_expires_at;

-- Existing rows were created without a lease token. Give them a bounded,
-- immediately recoverable lease so no old row can block provisioning forever.
UPDATE access_authorization_provisioning
SET fencing_token = COALESCE(fencing_token, UUID()),
    heartbeat_at = COALESCE(heartbeat_at, updated_at, CURRENT_TIMESTAMP),
    expires_at = COALESCE(
        expires_at,
        DATE_ADD(COALESCE(updated_at, CURRENT_TIMESTAMP), INTERVAL 35 SECOND)
    )
WHERE fencing_token IS NULL
   OR heartbeat_at IS NULL
   OR expires_at IS NULL;

ALTER TABLE access_authorization_provisioning
    MODIFY COLUMN fencing_token CHAR(36) NOT NULL,
    MODIFY COLUMN heartbeat_at DATETIME NOT NULL,
    MODIFY COLUMN expires_at DATETIME NOT NULL;

SET @index_exists = (
    SELECT COUNT(*)
    FROM information_schema.statistics
    WHERE table_schema = @schema_name
      AND table_name = 'access_authorization_provisioning'
      AND index_name = 'idx_access_authorization_provisioning_status_expires'
);
SET @sql = IF(
    @index_exists = 0,
    'ALTER TABLE access_authorization_provisioning ADD KEY idx_access_authorization_provisioning_status_expires (status, expires_at)',
    'SELECT 1'
);
PREPARE add_expiry_index FROM @sql;
EXECUTE add_expiry_index;
DEALLOCATE PREPARE add_expiry_index;
