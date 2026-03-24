-- V7: Add merchant agreement version and action-by audit trail to provider_network_registry.
-- Persist merchant agreement id/version, require agreement status
-- before activation, and retain audit trail of who activated/suspended/terminated.

ALTER TABLE provider_network_registry
    ADD COLUMN agreement_version VARCHAR(64) NOT NULL DEFAULT '' AFTER contract_id,
    ADD COLUMN action_by         VARCHAR(42) NULL       AFTER suspension_reason;

-- Back-fill existing rows with a sentinel to signal pre-v7 records.
UPDATE provider_network_registry
SET agreement_version = 'pre-v7-migration'
WHERE agreement_version = '';
