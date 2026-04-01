-- Normalize all off-chain credit projections to 5 decimal places so they match
-- the on-chain raw unit scale (10 credits = 1 EUR, 100000 raw = 1 credit).

ALTER TABLE funding_orders
    MODIFY COLUMN credit_amount DECIMAL(24,5) NOT NULL;

ALTER TABLE credit_accounts
    MODIFY COLUMN available DECIMAL(24,5) NOT NULL DEFAULT 0,
    MODIFY COLUMN locked DECIMAL(24,5) NOT NULL DEFAULT 0,
    MODIFY COLUMN consumed DECIMAL(24,5) NOT NULL DEFAULT 0,
    MODIFY COLUMN adjusted DECIMAL(24,5) NOT NULL DEFAULT 0,
    MODIFY COLUMN expired DECIMAL(24,5) NOT NULL DEFAULT 0;

ALTER TABLE credit_lots
    MODIFY COLUMN credit_amount DECIMAL(24,5) NOT NULL,
    MODIFY COLUMN remaining DECIMAL(24,5) NOT NULL;

ALTER TABLE credit_movements
    MODIFY COLUMN amount DECIMAL(24,5) NOT NULL;

ALTER TABLE provider_invoice_records
    MODIFY COLUMN credit_amount DECIMAL(24,5) NOT NULL;

ALTER TABLE provider_payouts
    MODIFY COLUMN credit_amount DECIMAL(24,5) NOT NULL;

ALTER TABLE mica_offer_volume
    MODIFY COLUMN credit_volume DECIMAL(24,5) NOT NULL DEFAULT 0;
