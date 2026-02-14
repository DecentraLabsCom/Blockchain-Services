# Authentication Service

This service issues JWTs using two entry points:

- Wallet challenge flow
- SAML flow with marketplace token cross-validation

Important runtime switch:

- Auth controllers are enabled only when `features.providers.enabled=true`.
- Repository default is `false` (`application.properties`), so `/auth/*` endpoints are disabled unless enabled.

## Wallet Flow

### 1) Challenge

- `GET /auth/message` (default purpose: `login`)
- Response:

```json
{
  "purpose": "login",
  "message": "Login request: <timestampMs>",
  "timestamp": "<timestampMs>"
}
```

### 2) Signature format

- Client signs `message` with `personal_sign`.
- API expects `signature = <65-byte-signature-hex><timestampHex13>`.
- Timestamp validity window: 5 minutes.
- Replay protection: same `wallet+timestamp` is rejected (`AntiReplayService`).

### 3) Authentication endpoints

- `POST /auth/wallet-auth`
  - Input: `wallet`, `signature`
  - Output: `{ "token": "..." }`

- `POST /auth/wallet-auth2`
  - Input: `wallet`, `signature`, and either `reservationKey` or `labId`
  - Output: `{ "token": "...", "labURL": "..." }`

Booking checks use `BlockchainBookingService` and require a valid active reservation for the signer.

## Check-in Message Mode

`GET /auth/message` also supports `purpose=checkin`:

- Query params: `signer`, and either `reservationKey` or `labId` (optional `puc`)
- Returns typed data payload for EIP-712 check-in signing (`typedData`), plus resolved `reservationKey`.

## SAML Flow

Endpoints:

- `POST /auth/saml-auth`
- `POST /auth/saml-auth2`

Request body:

```json
{
  "marketplaceToken": "<marketplace JWT>",
  "samlAssertion": "<base64 SAML assertion>",
  "labId": "42",
  "reservationKey": "0x..."
}
```

Validation pipeline:

1. Validate marketplace JWT signature using key from `marketplace.public-key-url`.
2. Validate SAML assertion signature and required attributes using `SamlValidationService`.
3. Cross-check `userid` and `affiliation` between marketplace JWT and SAML attributes.
4. If booking info is requested (`/auth/saml-auth2`), enforce booking entitlement:
   - `bookingInfoAllowed=true` OR
   - required scope (`auth.saml.required-booking-scope`, default `booking:read`).

SAML trust defaults:

- `saml.idp.trust-mode=whitelist` (default)
- `saml.trusted.idp={...}` map is used in whitelist mode
- Metadata URL resolution supports per-issuer/global overrides and assertion hints
- HTTPS metadata required by default (`saml.metadata.allow-http=false`)

## Discovery and Keys

- `GET /.well-known/openid-configuration`
- `GET /auth/jwks`

JWT signing keys:

- `PRIVATE_KEY_PATH` (default `/app/config/keys/private_key.pem`)
- `PUBLIC_KEY_PATH` (default `/app/config/keys/public_key.pem`)

## Error Semantics

- `400` invalid input / missing fields
- `401` authentication/signature/scope failures
- `503` upstream metadata/service unavailable (SAML mapped failures)
- `500` unexpected internal errors
