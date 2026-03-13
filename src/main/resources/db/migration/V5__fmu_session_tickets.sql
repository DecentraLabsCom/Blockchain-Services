-- FMU session tickets for one-time Gateway -> FMU proxy/session handoff.

CREATE TABLE IF NOT EXISTS fmu_session_tickets (
    session_ticket VARCHAR(40) PRIMARY KEY,
    lab_id VARCHAR(128),
    reservation_key VARCHAR(128),
    claims_json JSON NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_fmu_session_tickets_expires_at (expires_at),
    INDEX idx_fmu_session_tickets_used_at (used_at),
    INDEX idx_fmu_session_tickets_lookup (session_ticket, used_at, expires_at),
    INDEX idx_fmu_session_tickets_lab_reservation (lab_id, reservation_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
