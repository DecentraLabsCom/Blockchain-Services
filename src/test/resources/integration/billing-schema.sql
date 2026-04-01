-- H2-compatible billing domain schema for integration tests.
-- Mirrors V6 + V7 + V8 Flyway migrations without MySQL-specific syntax.
-- Credit columns use DECIMAL(24,5) — 1 EUR = 10 credits, max 5 decimal places.

-- ============================================================================
-- A. Funding lifecycle
-- ============================================================================

CREATE TABLE IF NOT EXISTS funding_orders (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    institution_address VARCHAR(42)     NOT NULL,
    eur_gross_amount DECIMAL(18,2)      NOT NULL,
    credit_amount   DECIMAL(24,5)       NOT NULL,
    status          VARCHAR(20)         NOT NULL DEFAULT 'DRAFT',
    reference       VARCHAR(256)        NULL,
    created_at      TIMESTAMP           NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP           NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at      TIMESTAMP           NULL
);

CREATE TABLE IF NOT EXISTS funding_invoices (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    funding_order_id BIGINT             NOT NULL,
    invoice_number  VARCHAR(64)         NOT NULL,
    eur_amount      DECIMAL(18,2)       NOT NULL,
    issued_at       TIMESTAMP           NULL,
    due_at          TIMESTAMP           NULL,
    status          VARCHAR(20)         NOT NULL DEFAULT 'ISSUED',
    FOREIGN KEY (funding_order_id) REFERENCES funding_orders(id)
);

CREATE TABLE IF NOT EXISTS payment_reconciliations (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    funding_order_id BIGINT             NOT NULL,
    payment_ref     VARCHAR(256)        NOT NULL,
    eur_amount      DECIMAL(18,2)       NOT NULL,
    payment_method  VARCHAR(64)         NULL,
    reconciled_at   TIMESTAMP           NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (funding_order_id) REFERENCES funding_orders(id)
);

-- ============================================================================
-- B. Credit account projections
-- ============================================================================

CREATE TABLE IF NOT EXISTS credit_accounts (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    account_address VARCHAR(42)         NOT NULL UNIQUE,
    available       DECIMAL(24,5)       NOT NULL DEFAULT 0,
    locked          DECIMAL(24,5)       NOT NULL DEFAULT 0,
    consumed        DECIMAL(24,5)       NOT NULL DEFAULT 0,
    adjusted        DECIMAL(24,5)       NOT NULL DEFAULT 0,
    expired         DECIMAL(24,5)       NOT NULL DEFAULT 0,
    updated_at      TIMESTAMP           NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS credit_lots (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    account_address VARCHAR(42)         NOT NULL,
    lot_index       INT                 NOT NULL,
    funding_order_id BIGINT             NULL,
    eur_gross_amount DECIMAL(18,2)      NULL,
    credit_amount   DECIMAL(24,5)       NOT NULL,
    remaining       DECIMAL(24,5)       NOT NULL,
    issued_at       TIMESTAMP           NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at      TIMESTAMP           NULL,
    expired         BOOLEAN             NOT NULL DEFAULT FALSE,
    UNIQUE (account_address, lot_index)
);

CREATE TABLE IF NOT EXISTS credit_movements (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    account_address VARCHAR(42)         NOT NULL,
    lot_index       INT                 NULL,
    movement_type   VARCHAR(20)         NOT NULL,
    amount          DECIMAL(24,5)       NOT NULL,
    reservation_ref VARCHAR(66)         NULL,
    reference       VARCHAR(256)        NULL,
    created_at      TIMESTAMP           NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- C. Provider network registry
-- ============================================================================

CREATE TABLE IF NOT EXISTS provider_network_registry (
    id                  BIGINT AUTO_INCREMENT PRIMARY KEY,
    provider_address    VARCHAR(42)         NOT NULL UNIQUE,
    contract_id         VARCHAR(128)        NOT NULL,
    agreement_version   VARCHAR(64)         NOT NULL DEFAULT '',
    effective_date      DATE                NULL,
    expiry_date         DATE                NULL,
    status              VARCHAR(20)         NOT NULL DEFAULT 'ACTIVE',
    suspension_reason   VARCHAR(256)        NULL,
    action_by           VARCHAR(42)         NULL,
    created_at          TIMESTAMP           NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP           NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- D. Provider settlement
-- ============================================================================

CREATE TABLE IF NOT EXISTS provider_invoice_records (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    lab_id          VARCHAR(128)        NOT NULL,
    provider_address VARCHAR(42)        NOT NULL,
    invoice_ref     VARCHAR(256)        NOT NULL,
    eur_amount      DECIMAL(18,2)       NOT NULL,
    credit_amount   DECIMAL(24,5)       NOT NULL DEFAULT 0,
    status          VARCHAR(20)         NOT NULL DEFAULT 'SUBMITTED',
    submitted_at    TIMESTAMP           NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP           NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS provider_approvals (
    id                  BIGINT AUTO_INCREMENT PRIMARY KEY,
    invoice_record_id   BIGINT              NOT NULL,
    approved_by         VARCHAR(42)         NOT NULL,
    approval_ref        VARCHAR(64)         NULL,
    eur_amount          DECIMAL(18,2)       NOT NULL,
    approved_at         TIMESTAMP           NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (invoice_record_id) REFERENCES provider_invoice_records(id)
);

CREATE TABLE IF NOT EXISTS provider_payouts (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    lab_id          VARCHAR(128)        NOT NULL,
    provider_address VARCHAR(42)        NOT NULL,
    eur_amount      DECIMAL(18,2)       NOT NULL,
    credit_amount   DECIMAL(24,5)       NOT NULL DEFAULT 0,
    bank_ref        VARCHAR(256)        NULL,
    eurc_tx_hash    VARCHAR(80)         NULL,
    usdc_tx_hash    VARCHAR(80)         NULL,
    paid_at         TIMESTAMP           NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- E. MiCA compliance monitoring
-- ============================================================================

CREATE TABLE IF NOT EXISTS mica_offer_volume (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    period_start    DATE                NOT NULL,
    period_end      DATE                NOT NULL,
    eur_volume      DECIMAL(18,2)       NOT NULL DEFAULT 0,
    credit_volume   DECIMAL(24,5)       NOT NULL DEFAULT 0,
    transaction_count INT               NOT NULL DEFAULT 0,
    computed_at     TIMESTAMP           NOT NULL DEFAULT CURRENT_TIMESTAMP
);
