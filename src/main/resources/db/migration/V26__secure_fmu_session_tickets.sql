-- FMU tickets are short-lived/reusable capabilities. Invalidate outstanding legacy
-- rows on upgrade so neither the bearer ticket nor its claims remain in plaintext.
DROP TABLE IF EXISTS fmu_session_tickets;

CREATE TABLE fmu_session_tickets (
    ticket_hash CHAR(64) PRIMARY KEY,
    lab_id VARCHAR(128),
    reservation_key VARCHAR(128),
    encrypted_claims TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_fmu_session_tickets_expires_at (expires_at),
    INDEX idx_fmu_session_tickets_lab_reservation (lab_id, reservation_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
