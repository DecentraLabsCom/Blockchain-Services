-- Remove request-time federation/WebAuthn material from payloads written by
-- earlier versions. Current payloads are minimal and encrypted at rest.
UPDATE intents
SET payload_json = JSON_REMOVE(
    payload_json,
    '$.samlAssertion',
    '$.stableUserIdMode',
    '$.webauthnCredentialId',
    '$.webauthnClientDataJSON',
    '$.webauthnAuthenticatorData',
    '$.webauthnSignature',
    '$.signature',
    '$.typedData'
)
WHERE payload_json IS NOT NULL
  AND JSON_TYPE(payload_json) = 'OBJECT'
  AND (
      JSON_CONTAINS_PATH(payload_json, 'one', '$.samlAssertion')
      OR JSON_CONTAINS_PATH(payload_json, 'one', '$.webauthnCredentialId')
      OR JSON_CONTAINS_PATH(payload_json, 'one', '$.webauthnClientDataJSON')
      OR JSON_CONTAINS_PATH(payload_json, 'one', '$.webauthnAuthenticatorData')
      OR JSON_CONTAINS_PATH(payload_json, 'one', '$.webauthnSignature')
      OR JSON_CONTAINS_PATH(payload_json, 'one', '$.signature')
      OR JSON_CONTAINS_PATH(payload_json, 'one', '$.typedData')
  );
