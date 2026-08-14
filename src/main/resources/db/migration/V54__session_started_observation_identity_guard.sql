-- The contract rejects a SessionStarted observation when gatewayId, sessionId
-- and accessType have already been used, regardless of reservationKey. Keep
-- that identity durable so concurrent gateway requests cannot create a second
-- attestation for the same on-chain observation.
CREATE TABLE IF NOT EXISTS session_started_observation_locks (
    gateway_id VARCHAR(128) NOT NULL,
    session_id VARCHAR(128) NOT NULL,
    access_type VARCHAR(32) NOT NULL,
    reservation_key VARCHAR(66) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (gateway_id, session_id, access_type),
    KEY idx_session_started_observation_lock_reservation (reservation_key)
);

-- Seed the guard from existing evidence. A mined success is preferred when
-- old data contains duplicate identities; the service still treats an older
-- same-reservation row as idempotent during the transition.
INSERT IGNORE INTO session_started_observation_locks (
    gateway_id, session_id, access_type, reservation_key
)
SELECT COALESCE(gateway_id, ''),
       session_id,
       access_type,
       COALESCE(
           MIN(CASE WHEN onchain_status = 'MINED_SUCCESS' THEN reservation_key END),
           MIN(reservation_key)
       )
FROM session_started_attestations
GROUP BY COALESCE(gateway_id, ''), session_id, access_type;
