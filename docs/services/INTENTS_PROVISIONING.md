# Intents and Provisioning Services

This document covers:

- Intent submission and status endpoints (`/intents`)
- WebAuthn authorization ceremony for intents
- Institutional provisioning endpoints (`/institution-config`)

## Intents: Access and Auth

Base path:

- `endpoint.intents` (default `/intents`)

Authorization:

- When `intents.auth.enabled=true` (default), endpoints require `Authorization: Bearer <marketplace_jwt>`.
- JWT checks:
  - issuer = `intents.auth.issuer` (default `marketplace`)
  - audience = `intents.auth.audience` (default `blockchain-services`)
  - scope:
    - submit endpoints require `intents.auth.submit-scope` (default `intents:submit`)
    - status endpoints require `intents.auth.status-scope` (default `intents:status`)

## Intents: Endpoints

- `POST /intents`
  - Submits an intent directly.
  - Returns `IntentAckResponse` (`accepted` or `rejected`).

- `GET /intents/{requestId}`
  - Returns current intent execution state (`queued`, `in_progress`, `executed`, `failed`, `rejected`).

- `POST /intents/authorize`
  - Starts WebAuthn ceremony for an intent and returns:
    - `sessionId`
    - `ceremonyUrl`
    - `requestId`
    - `expiresAt`

- `GET /intents/authorize/status/{sessionId}`
  - Returns ceremony status (`PENDING`, `SUCCESS`, `FAILED`).

- `GET /intents/authorize/ceremony/{sessionId}`
  - Serves the HTML ceremony page used by browser/passkey flow.

- `POST /intents/authorize/complete`
  - Completes ceremony with signed WebAuthn assertion and executes the intent pipeline.
  - Uses `sessionId` as authorization context (no bearer token check in this endpoint by design).

## Intent Submission Model

Main object: `IntentSubmission`.

Required top-level fields:

- `meta`
- `signature` (EIP-712)
- `samlAssertion` (base64)
- `webauthnCredentialId`
- `webauthnClientDataJSON`
- `webauthnAuthenticatorData`
- `webauthnSignature`

Payload variants:

- `actionPayload` for non-reservation actions
- `reservationPayload` for reservation actions

Action discriminator:

- `meta.action` mapped to `IntentAction` enum.

## Validation Pipeline (IntentService)

1. Validate `meta` and payload shape by action type.
2. Validate SAML assertion and assertion hash consistency.
3. Enforce SAML replay protection.
4. Validate WebAuthn assertion (all actions except `REQUEST_FUNDS`).
5. Reject expired intents (`meta.expiresAt`) and nonce replay.
6. Verify EIP-712 signature (`Eip712IntentVerifier`) and optional trusted signer policy (`intent.trusted-signer`).
7. Persist and queue accepted intents.

ACK response:

- `accepted`: intent queued for execution
- `rejected`: validation/signature/replay/expiry failure

## Provisioning Endpoints (`/institution-config`)

These endpoints are localhost-restricted by `LocalhostOnlyFilter`.

- `GET /institution-config/status`
- `POST /institution-config/save-and-register`
- `POST /institution-config/retry-registration`
- `POST /institution-config/apply-provider-token`
- `POST /institution-config/apply-consumer-token`

Current recommended flow:

1. Apply provisioning token from Marketplace:
   - provider mode: `/apply-provider-token`
   - consumer mode: `/apply-consumer-token`
2. Service validates token against Marketplace JWKS.
3. Service persists config and attempts Marketplace registration.

Token request body:

```json
{
  "token": "<provisioning_jwt>"
}
```

## Provisioning Token Validation

`ProvisioningTokenService` validates:

- JWT signature using Marketplace JWKS endpoints
- issuer and audience
- replay protection via `jti`
- required claims and URL/email sanity checks

Marketplace registration is executed by `InstitutionRegistrationService` using:

- `/api/institutions/registerProvider`
- `/api/institutions/registerConsumer`

## Key Configuration

Intents:

- `intents.auth.enabled`
- `intents.auth.issuer`
- `intents.auth.audience`
- `intents.auth.submit-scope`
- `intents.auth.status-scope`
- `intent.domain.*`
- `intent.trusted-signer`

Provisioning:

- `marketplace.base-url`
- `public.base-url`
- `provider.*`
- `features.providers.registration.enabled`
