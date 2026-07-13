-- Only one attestation may own on-chain publication for a reservation at a
-- time. NULL remains available to terminal failures and superseded evidence.
ALTER TABLE session_started_attestations
    ADD COLUMN onchain_reservation_guard VARCHAR(66) NULL,
    ADD CONSTRAINT uq_session_started_reservation_guard UNIQUE (onchain_reservation_guard);

CREATE TEMPORARY TABLE session_started_guard_winners (
    reservation_key VARCHAR(66) PRIMARY KEY,
    winner_id BIGINT NOT NULL
);

INSERT INTO session_started_guard_winners (reservation_key, winner_id)
SELECT reservation_key,
       COALESCE(
           MIN(CASE WHEN onchain_status = 'MINED_SUCCESS' THEN id END),
           MIN(CASE WHEN onchain_status IN (
               'SUBMITTED', 'STUCK_UNKNOWN', 'SUBMITTING', 'RETRY', 'QUEUED'
           ) THEN id END)
       )
FROM session_started_attestations
GROUP BY reservation_key
HAVING COALESCE(
    MIN(CASE WHEN onchain_status = 'MINED_SUCCESS' THEN id END),
    MIN(CASE WHEN onchain_status IN (
        'SUBMITTED', 'STUCK_UNKNOWN', 'SUBMITTING', 'RETRY', 'QUEUED'
    ) THEN id END)
) IS NOT NULL;

UPDATE session_started_attestations attestation
JOIN session_started_guard_winners winner
  ON winner.winner_id = attestation.id
SET attestation.onchain_reservation_guard = attestation.reservation_key;

UPDATE session_started_attestations attestation
JOIN session_started_guard_winners winner
  ON winner.reservation_key = attestation.reservation_key
 AND winner.winner_id <> attestation.id
SET attestation.onchain_status = 'SUPERSEDED',
    attestation.onchain_publish_locked_at = NULL,
    attestation.onchain_publish_last_error =
        'Superseded while installing the per-reservation publication guard'
WHERE attestation.onchain_status IN ('QUEUED', 'RETRY', 'SUBMITTING');

DROP TEMPORARY TABLE session_started_guard_winners;
