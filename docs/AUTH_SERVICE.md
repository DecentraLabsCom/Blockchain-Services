# Authentication Service

Service that issues JWTs for DecentraLabs using two entry points: wallet challenges and SAML2 SSO. Authentication endpoints are enabled when `features.providers.enabled=true` (default).

## Supported flows
- Wallet challenge (`/auth/message` -> `/auth/wallet-auth*`) with on-chain reservation validation on the `*2` variant.
- SAML2 SSO (`/auth/saml-auth*`) with automatic IdP discovery and mandatory signature validation.
- JWKS + OIDC discovery for downstream verifiers.

## Wallet challenge (wallet-auth / wallet-auth2)
1) Ask for the challenge: `GET /auth/message` returns `{message:"Login request: <timestampMs>", timestamp:"<timestampMs>"}`.
2) Frontend signs `message` with `personal_sign`.
3) The signature sent to the API must be `<signatureHex><timestampHex>`, where `timestampHex` are the 13 hex chars of the millisecond timestamp. The service extracts the timestamp from the tail of the signature.
4) POST the payload:
```http
POST /auth/wallet-auth
{
  "wallet": "0xYourWallet",
  "signature": "0x<signature><timestampHex>"
}
```
- Timestamp validity window: 5 minutes.
- Anti replay: the same wallet+timestamp is rejected (can persist to `./data/antireplay-cache.json` when `antireplay.persistence.enabled=true`).
- Signature check: recover address from the signed message, compare against checksum wallet.

### With booking (`/auth/wallet-auth2`)
Payload adds either `reservationKey` (preferred, bytes32 hex) or `labId`:
```http
POST /auth/wallet-auth2
{
  "wallet": "0x...",
  "signature": "0x<signature><timestampHex>",
  "reservationKey": "0xabc..."  // or "labId": "42"
}
```
Booking resolution uses `BlockchainBookingService`:
- If `reservationKey` is present, it performs an O(1) lookup.
- Otherwise it scans the caller reservations for that `labId`.
- Status must be CONFIRMED or IN_USE and current time must be within `[start,end]`.
- Renter must equal the caller wallet.

JWT claims with booking:
- Standard: `iss`, `iat`, `jti`.
- Booking: `aud` (accessURI from contract), `sub` (accessKey), `nbf`, `exp`, `labId`.
Response body: `{ "token": "<jwt>", "labURL": "<accessURI>" }`.

Without booking the JWT only carries `wallet` plus standard claims and the response body is `{"token": "<jwt>"}`.

## SAML flows (saml-auth / saml-auth2)
Input fields:
```json
{
  "marketplaceToken": "<JWT signed by marketplace>",
  "samlAssertion": "<base64 SAML Assertion>",
  "labId": "42",            // optional, required if reservationKey is missing
  "reservationKey": "0xabc..." // optional
}
```
Validation steps:
1) Marketplace JWT is verified with the RSA public key fetched from `marketplace.public-key-url` (cached; refresh every `marketplace.key.cache-ms`).
2) SAML assertion is validated with signature using `SamlValidationService`:
   - Trust mode: `saml.idp.trust-mode=any|whitelist` (default `any`).
   - Whitelist mode requires issuers in `saml.trusted.idp.*`.
   - Metadata URL is read from `AuthenticatingAuthority` or `Extensions`; fallback to `<issuer>/metadata`.
   - Only HTTP/HTTPS URLs are allowed; private/loopback/metadata endpoints are rejected; signing certs are cached per issuer.
   - Required attributes: `userid`, `affiliation`; optional: `email`, `displayName`, `schacHomeOrganization`.
3) Cross-check: `userid` and `affiliation` must match between marketplace JWT and SAML.
4) Booking scope enforcement: when `auth.saml.require-booking-scope=true` (default) the marketplace token must carry either `bookingInfoAllowed=true` or the scope `booking:read` in `scope`/`scopes`.

Booking variant (`/auth/saml-auth2`): uses the provider wallet from the marketplace token (`institutionalProviderWallet`) and optional `puc` to resolve the reservation on-chain (same claims/response as wallet-auth2).

Non-booking variant (`/auth/saml-auth`): issues a JWT with `userid` and `affiliation` plus standard claims.

## Endpoints
- `GET /.well-known/openid-configuration`: issuer = `<baseDomain><auth.base-path>`; `authorization_endpoint` points to `/auth/wallet-auth2`; `jwks_uri` to `/auth/jwks`.
- `GET /auth/jwks`: JWKS built from the RSA public key at `public.key.path`.
- `GET /auth/message`: wallet challenge payload (see above).
- `POST /auth/wallet-auth`: wallet-only JWT.
- `POST /auth/wallet-auth2`: wallet JWT + booking claims and `labURL`.
- `POST /auth/saml-auth`: SAML JWT (no booking).
- `POST /auth/saml-auth2`: SAML JWT + booking claims and `labURL`.

Errors: bad input -> 400, signature/auth errors -> 401, unexpected issues -> 500 with `{ "error": "..." }`.

## Configuration highlights
- Contract: `contract.address` (required for booking lookups).
- JWT keys: `PRIVATE_KEY_PATH`, `PUBLIC_KEY_PATH`, optional `PUBLIC_CERTIFICATE_PATH` (all under `/app/config/keys` in Docker by default).
- Marketplace key: `marketplace.public-key-url`, optional `marketplace.key.cache-ms`.
- SAML: `saml.idp.trust-mode` (`any`/`whitelist`) and `saml.trusted.idp.*` map; signature validation is always enforced.
- Base domain: `BASE_DOMAIN` (otherwise derived from server name/port by `GatewayUrlResolver`).
- Booking scope: `auth.saml.require-booking-scope` (default true), `auth.saml.required-booking-scope` (default `booking:read`).

## Related docs
- `dev/SAML_AUTO_DISCOVERY.md`
- `dev/SAML_SIGNATURE_VALIDATION.md`
- `dev/WALLET_TREASURY.md`
