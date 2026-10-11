CREATE INDEX idx_provider_income_reservation_provider
    ON provider_income_reservations (chain_id, contract_address, provider_address);
