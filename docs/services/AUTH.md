# Authentication Service

This service issues JWTs through the institutional SAML flow with marketplace token cross-validation.

Important runtime switch:

- Auth controllers are enabled only when `features.providers.enabled=true`.
- Repository default is `false` (`application.properties`), so `/auth/*` endpoints are disabled unless enabled.

## SAML Flow

Endpoints:

- `POST /auth/authorize-and-issue`
- `POST /auth/access-credential`
- `POST /auth/checkin-institutional`
- `POST /auth/access-code/issue` (server-side, short-lived browser hand-off)
- `POST /auth/access-code/redeem` (single-use redemption)

Request body:

```json
{
  "marketplaceToken": "<marketplace JWT>",
  "samlAssertion": "<base64 SAML assertion>",
  "labId": "42",
  "reservationKey": "0x..."
}
```

```mermaid
sequenceDiagram
    participant Browser
    participant Marketplace
    participant Auth as blockchain-services auth
    participant Saml as SamlValidationService
    participant Chain as Smart contracts
    participant Gateway as Lab Gateway

    Browser->>Marketplace: user login + reservation context
    Browser->>Marketplace: request access
    Marketplace->>Auth: POST /auth/authorize-and-issue
    Auth->>Marketplace: validate marketplace JWT key
    Auth->>Saml: validate assertion and attributes
    Auth->>Chain: validate reservation and validity window
    Auth->>Gateway: stage disabled Guacamole access
    Auth->>Chain: poll reservation status
    Chain-->>Auth: ACCESS_AUTHORIZED
    Auth->>Chain: final status/window validation
    Auth->>Gateway: activate access
    Auth-->>Marketplace: signed lab-access JWT (server-side only)
    Marketplace->>Auth: POST /auth/access-code/issue
    Marketplace-->>Browser: opaque one-time access_code
    Browser->>Gateway: POST /auth/access with access_code
    Gateway->>Auth: POST /auth/access-code/redeem
    Gateway-->>Browser: 303 to clean URL + HttpOnly JTI cookie
```

Validation pipeline:

1. Validate marketplace JWT signature using key from `marketplace.public-key-url`.
2. Validate SAML assertion signature and required attributes using `SamlValidationService`.
3. Cross-check `userid` and `affiliation` between marketplace JWT and SAML attributes.
4. Cross-check `payerInstitutionWallet` with the authenticated institution; this claim identifies the payer institution, not the lab provider wallet.
5. Booking-aware access endpoints enforce booking entitlement:
   - `bookingInfoAllowed=true` OR
   - required scope (`auth.saml.required-booking-scope`, default `booking:read`).

Institutional check-in is handled through `/auth/checkin-institutional` and derives the signer context from the validated institutional request instead of a customer wallet-signature challenge.

For separate consumer and provider backends, check-in returns after transaction submission with its `txHash`; it does not wait for the receipt. The provider validates the Marketplace JWT and reservation (including the validity window), stages a physical Guacamole user disabled and without connection permissions, and prepares the access claims. Each attempt has a durable fencing token, generation, heartbeat and expiry; status changes and rollback ownership are conditional on that token. It also uses a distinct temporary Guacamole user, so a stale attempt cannot activate or delete the current attempt's user. The same lease is acquired when `ACCESS_AUTHORIZED` is already visible, closing the fast-path race with a provisional request. The JWT is signed, audited, and returned only after the reservation reaches `ACCESS_AUTHORIZED`; the provider polls only the reservation status for at most 27 seconds (`auth.access-authorization.wait-timeout-ms`), refreshing its lease on every poll, then performs a final full reservation/window validation before activating Guacamole. On timeout it returns `503 ACCESS_AUTHORIZATION_PENDING` with `Retry-After: 1` and removes only its own temporary Guacamole user. If the authorization transaction is mined reverted, it returns `409 ACCESS_AUTHORIZATION_REJECTED`. No JWT has been signed or persisted before authorization. OpenResty allows 60 seconds for `/auth`, so provisioning plus fenced cleanup can return that structured response instead of being cut off by the proxy.

When consumer and provider are the same backend, `/auth/authorize-and-issue` queues the institutional check-in in the local outbox, stages the provider access, and follows the same `ACCESS_AUTHORIZED` gate before activation and issuance.

The institutional check-in outbox separates transaction submission from receipt monitoring. Its lifecycle is `PENDING → SUBMITTING → SUBMITTED → MINED_SUCCESS` or `MINED_FAILED`, with `RETRY` and terminal `FAILED` for submission errors. Enqueue is idempotent: an existing row is never reset or reopened, so a transmitted hash and nonce cannot be reused accidentally. A later, fully revalidated access request may explicitly restart only `MINED_FAILED` or `FAILED`; that creates a clean generation by clearing the prior hash, nonce and submission timestamps. A submission worker persists the hash and a separate receipt monitor checks mining status. Nonces are allocated and persisted per signing wallet under a database row lock, so distinct reservations can be transmitted concurrently up to the wallet nonce order without waiting for receipts; an uncertain broadcast retains its reserved nonce for reconciliation/retry.

The submission and receipt workers run every two seconds by default. A transaction still pending after 15 seconds is repriced with its reserved nonce, which gives the replacement a chance to help the 27-second provider wait. The local broadcast lock is keyed by wallet rather than globally by JVM. Ethereum nonce ordering still permits head-of-line blocking when an earlier nonce is stuck; this is monitored and repriced but cannot be removed at the application layer.

The booking flow uses `/auth/authorize-and-issue`.

For physical Guacamole labs, Marketplace exchanges the signed credential for a 60-second opaque access code; issuance requires the Marketplace server's validated bearer token in `X-Marketplace-Authorization`. OpenResty redeems the code once with `AUTH_ACCESS_CODE_REDEEMER_TOKEN`, sets the secure JTI cookie and redirects to a clean URL. Codes use the persistent database atomically whenever a datasource exists; in-memory storage is used only without a datasource. Issuance validates the signed credential and derives the target URL from its claims, which bind its HTTPS Guacamole URL to its audience. FMU credentials do not use this Guacamole handoff: they remain JWT bearer credentials for the FMU flow.

When Guacamole accepts a reservation WebSocket (`101`), OpenResty records that opening timestamp in a local MySQL observation outbox. The ops worker delivers it to `/access-audit/internal/session-observed` with retry/backoff and marks it sent only when the backend replies with `recorded=true`; the backend then writes the local audit and the session-start attestation. Tunnel closure is not used as an observation timestamp.

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
- `409` access-authorization transaction rejected on-chain
- `503` upstream metadata/service unavailable (SAML mapped failures)
- `503` `ACCESS_AUTHORIZATION_PENDING` while on-chain authorization is not yet visible (`Retry-After: 1`)
- `500` unexpected internal errors
