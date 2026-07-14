-- Keep replacement history isolated when a terminal outbox row is restarted.
-- Existing V34 rows belong to generation 1 by default.

ALTER TABLE institutional_checkin_outbox
    ADD COLUMN generation BIGINT UNSIGNED NOT NULL DEFAULT 1 AFTER id;

ALTER TABLE institutional_checkin_outbox_hash_history
    ADD COLUMN generation BIGINT UNSIGNED NOT NULL DEFAULT 1 AFTER outbox_id,
    DROP INDEX uk_checkin_hash_history,
    ADD UNIQUE KEY uk_checkin_hash_history (outbox_id, generation, tx_hash),
    DROP INDEX idx_checkin_hash_history_lookup,
    ADD KEY idx_checkin_hash_history_lookup (outbox_id, generation, replaced_at);
