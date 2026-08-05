ALTER TABLE intents
    ADD COLUMN reservation_status VARCHAR(32) NULL AFTER reservation_key;
