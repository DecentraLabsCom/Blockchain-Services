-- Scope reservation projections to the access gateway that owns the lab.
ALTER TABLE lab_reservations
    ADD COLUMN access_uri VARCHAR(512) NULL AFTER lab_id;

ALTER TABLE lab_reservations
    ADD INDEX idx_lab_reservations_access_uri (access_uri);
