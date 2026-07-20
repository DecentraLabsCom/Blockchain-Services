ALTER TABLE intents
    ADD COLUMN puc_hash VARCHAR(66) NULL AFTER reservation_key;

-- Backfill the non-reversible identity hash from legacy pending payloads.
-- Raw PUC values are never reconstructed or stored.
UPDATE intents
SET puc_hash = COALESCE(
    JSON_UNQUOTE(JSON_EXTRACT(payload_json, '$.reservationPayload.pucHash')),
    JSON_UNQUOTE(JSON_EXTRACT(payload_json, '$.actionPayload.pucHash'))
)
WHERE puc_hash IS NULL
  AND payload_json IS NOT NULL
  AND JSON_TYPE(payload_json) = 'OBJECT'
  AND (
      JSON_CONTAINS_PATH(payload_json, 'one', '$.reservationPayload.pucHash')
      OR JSON_CONTAINS_PATH(payload_json, 'one', '$.actionPayload.pucHash')
  );
