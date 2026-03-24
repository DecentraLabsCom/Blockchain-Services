-- Billing domain schema: funding orders, credit accounts, provider network,
-- provider settlement, and MiCA compliance monitoring.

-- ============================================================================
-- A. Funding lifecycle (prepaid credit purchases)
-- ============================================================================

CREATE TABLE IF NOT EXISTS funding_orders (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    institution_address VARCHAR(42) NOT NULL,
    eur_gross_amount DECIMAL(18,2) NOT NULL,
    credit_amount   DECIMAL(24,1) NOT NULL,
    status          ENUM('DRAFT','INVOICED','PAID','CREDITED','CANCELLED') NOT NULL DEFAULT 'DRAFT',
    reference       VARCHAR(256),
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    expires_at      TIMESTAMP NULL,
    INDEX idx_fo_institution (institution_address),
    INDEX idx_fo_status (status),
    INDEX idx_fo_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS funding_invoices (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    funding_order_id BIGINT NOT NULL,
    invoice_number  VARCHAR(64) NOT NULL UNIQUE,
    eur_amount      DECIMAL(18,2) NOT NULL,
    issued_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    due_at          TIMESTAMP NULL,
    status          ENUM('ISSUED','PAID','CANCELLED') NOT NULL DEFAULT 'ISSUED',
    INDEX idx_fi_order (funding_order_id),
    INDEX idx_fi_status (status),
    FOREIGN KEY (funding_order_id) REFERENCES funding_orders(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS payment_reconciliations (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    funding_order_id BIGINT NOT NULL,
    payment_ref     VARCHAR(256) NOT NULL,
    eur_amount      DECIMAL(18,2) NOT NULL,
    payment_method  VARCHAR(64),
    reconciled_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_pr_order (funding_order_id),
    INDEX idx_pr_ref (payment_ref),
    FOREIGN KEY (funding_order_id) REFERENCES funding_orders(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- B. Credit account projections (off-chain mirror of on-chain credit ledger)
-- ============================================================================

CREATE TABLE IF NOT EXISTS credit_accounts (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    account_address VARCHAR(42) NOT NULL UNIQUE,
    available       DECIMAL(24,1) NOT NULL DEFAULT 0,
    locked          DECIMAL(24,1) NOT NULL DEFAULT 0,
    consumed        DECIMAL(24,1) NOT NULL DEFAULT 0,
    adjusted        DECIMAL(24,1) NOT NULL DEFAULT 0,
    expired         DECIMAL(24,1) NOT NULL DEFAULT 0,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_ca_address (account_address)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS credit_lots (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    account_address VARCHAR(42) NOT NULL,
    lot_index       INT NOT NULL,
    funding_order_id BIGINT NULL,
    eur_gross_amount DECIMAL(18,2) NULL,
    credit_amount   DECIMAL(24,1) NOT NULL,
    remaining       DECIMAL(24,1) NOT NULL,
    issued_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at      TIMESTAMP NULL,
    expired         BOOLEAN NOT NULL DEFAULT FALSE,
    INDEX idx_cl_account (account_address),
    INDEX idx_cl_expires (expires_at),
    INDEX idx_cl_active (expired, expires_at),
    UNIQUE KEY uq_cl_account_lot (account_address, lot_index)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS credit_movements (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    account_address VARCHAR(42) NOT NULL,
    lot_index       INT NULL,
    movement_type   ENUM('MINT','LOCK','CAPTURE','CANCEL','ADJUST','EXPIRE') NOT NULL,
    amount          DECIMAL(24,1) NOT NULL,
    reservation_ref VARCHAR(66) NULL,
    reference       VARCHAR(256) NULL,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_cm_account (account_address),
    INDEX idx_cm_type (movement_type),
    INDEX idx_cm_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- C. Provider network registry (limited-network membership)
-- ============================================================================

CREATE TABLE IF NOT EXISTS provider_network_registry (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    provider_address VARCHAR(42) NOT NULL,
    contract_id     VARCHAR(128) NOT NULL,
    effective_date  DATE NOT NULL,
    expiry_date     DATE NULL,
    status          ENUM('ACTIVE','SUSPENDED','TERMINATED') NOT NULL DEFAULT 'ACTIVE',
    suspension_reason VARCHAR(512) NULL,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_pnr_provider (provider_address),
    INDEX idx_pnr_status (status),
    INDEX idx_pnr_expiry (expiry_date),
    UNIQUE KEY uq_pnr_provider_contract (provider_address, contract_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- D. Provider settlement (receivable → invoice → approval → payout)
-- ============================================================================

CREATE TABLE IF NOT EXISTS provider_invoice_records (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    lab_id          VARCHAR(128) NOT NULL,
    provider_address VARCHAR(42) NOT NULL,
    invoice_ref     VARCHAR(256) NOT NULL,
    eur_amount      DECIMAL(18,2) NOT NULL,
    credit_amount   DECIMAL(24,1) NOT NULL,
    submitted_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status          ENUM('SUBMITTED','APPROVED','DISPUTED','PAID','CANCELLED') NOT NULL DEFAULT 'SUBMITTED',
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_pir_lab (lab_id),
    INDEX idx_pir_provider (provider_address),
    INDEX idx_pir_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS provider_approvals (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    invoice_record_id BIGINT NOT NULL,
    approved_by     VARCHAR(42) NOT NULL,
    eur_amount      DECIMAL(18,2) NOT NULL,
    approved_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_pa_invoice (invoice_record_id),
    FOREIGN KEY (invoice_record_id) REFERENCES provider_invoice_records(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS provider_payouts (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    lab_id          VARCHAR(128) NOT NULL,
    provider_address VARCHAR(42) NOT NULL,
    eur_amount      DECIMAL(18,2) NOT NULL,
    credit_amount   DECIMAL(24,1) NOT NULL,
    paid_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    bank_ref        VARCHAR(256) NULL,
    eurc_tx_hash    VARCHAR(80) NULL,
    usdc_tx_hash    VARCHAR(80) NULL,
    INDEX idx_pp_lab (lab_id),
    INDEX idx_pp_provider (provider_address)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- E. MiCA compliance monitoring
-- ============================================================================

CREATE TABLE IF NOT EXISTS mica_offer_volume (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    period_start    DATE NOT NULL,
    period_end      DATE NOT NULL,
    eur_volume      DECIMAL(18,2) NOT NULL DEFAULT 0,
    credit_volume   DECIMAL(24,1) NOT NULL DEFAULT 0,
    transaction_count INT NOT NULL DEFAULT 0,
    computed_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_mov_period (period_start, period_end)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
