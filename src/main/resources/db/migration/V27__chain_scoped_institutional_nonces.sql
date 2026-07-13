-- One institutional wallet can operate against multiple EVM networks. Nonce
-- ownership must therefore be scoped by chain as well as address.
ALTER TABLE institutional_wallet_nonce
    DROP PRIMARY KEY,
    ADD COLUMN chain_id DECIMAL(65, 0) NOT NULL DEFAULT 0 FIRST,
    ADD PRIMARY KEY (chain_id, wallet_address);

ALTER TABLE institutional_checkin_outbox
    DROP INDEX uk_checkin_outbox_wallet_nonce,
    ADD COLUMN chain_id DECIMAL(65, 0) NULL AFTER wallet_address,
    ADD UNIQUE KEY uk_checkin_outbox_chain_wallet_nonce (chain_id, wallet_address, nonce);

ALTER TABLE session_started_attestations
    DROP INDEX uq_session_started_wallet_nonce,
    ADD COLUMN onchain_chain_id DECIMAL(65, 0) NULL AFTER onchain_wallet_address,
    ADD UNIQUE KEY uq_session_started_chain_wallet_nonce (
        onchain_chain_id, onchain_wallet_address, onchain_nonce
    );
