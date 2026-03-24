-- V8: Add deterministic approval reference to provider_approvals table
-- approvalRef is the operator-supplied external reference (e.g. "APPROVAL-2026-0042")
-- that links this off-chain approval record back to the finance/approval system.

ALTER TABLE provider_approvals
    ADD COLUMN approval_ref VARCHAR(64) NULL COMMENT 'External approval reference for audit trail';

-- Back-fill pre-migration rows with a sentinel value
UPDATE provider_approvals
SET approval_ref = CONCAT('pre-v8-', id)
WHERE approval_ref IS NULL;
