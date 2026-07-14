-- Preserve signed transaction material before the first broadcast. This makes
-- a post-broadcast SQL failure recoverable without guessing the transaction
-- hash or allocating a replacement nonce.

ALTER TABLE institutional_checkin_outbox
    ADD COLUMN signed_raw_transaction LONGTEXT NULL AFTER tx_hash;

ALTER TABLE session_started_attestations
    ADD COLUMN onchain_signed_raw_transaction LONGTEXT NULL AFTER onchain_tx_hash;
