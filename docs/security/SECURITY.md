# Security configuration

This is the production baseline for the canonical backend. It complements the
route-specific guidance in [Authentication](../services/authentication/AUTH.md) and
[Wallet/Billing](../services/wallet/WALLET_BILLING.md).

## Secrets and keys

- Keep `.env`, private keys, wallet files and `/app/data` outside Git.
- Mount the JWT key pair read-only. The container template defaults to
  `PRIVATE_KEY_PATH=/app/data/keys/private_key.pem` and
  `PUBLIC_KEY_PATH=/app/data/keys/public_key.pem`.
- Keep `INSTITUTIONAL_WALLET_*`, RPC URLs and `ADMIN_ACCESS_TOKEN` in a secret
  manager or deployment environment.
- Persist the wallet encryption key at `WALLET_CONFIG_KEY_FILE` when the service
  generates it. Losing that key makes the encrypted wallet unrecoverable.
- Restrict private-key permissions (`0400` for private files on POSIX systems)
  and review the startup key checks.

## Network boundary

`LocalhostOnlyFilter` protects wallet, billing, dashboard, provisioning,
lab-admin and internal audit routes. The default is loopback-only.

To allow a private network, configure all of the relevant controls together:

```properties
ADMIN_DASHBOARD_LOCAL_ONLY=true
ADMIN_DASHBOARD_ALLOW_PRIVATE=true
SECURITY_ALLOW_PRIVATE_NETWORKS=true
ADMIN_ALLOWED_CIDRS=10.20.0.0/16,192.168.50.0/24
ADMIN_ACCESS_TOKEN_REQUIRED=true
```

Forwarded client IP headers are trusted only from
`SECURITY_TRUSTED_PROXY_CIDRS`. Extend that list only for known reverse proxies.
Tokens are accepted through the configured header or cookie; query-string
tokens are intentionally rejected.

Provider mode also enforces `ROLE_INTERNAL` on `/billing/admin/**`; a valid
`ADMIN_ACCESS_TOKEN` is therefore required even when the request originates on
localhost. Consumer-only deployments rely on the localhost/private-network
filter plus the configured access token.

## Authentication controls

- Marketplace JWTs are verified against the cached RSA key from
  `MARKETPLACE_PUBLIC_KEY_URL` and checked for issuer, audience, expiry and
  route-specific scope.
- SAML assertions require an XML signature and required identity attributes.
  `SAML_IDP_TRUST_MODE=any` is the development default; use `whitelist` with
  `SAML_TRUSTED_IDP` in production.
- SAML metadata is HTTPS-only by default and private, loopback, link-local and
  cloud-metadata targets are blocked. See [SAML Auto-Discovery](SAML_AUTO_DISCOVERY.md).
- WebAuthn challenges and intent authorization sessions are short-lived and
  single-use. The session-bound completion endpoint must not be treated as a
  general unauthenticated API.
- Institutional admin signatures use a five-minute timestamp/replay window.
  `ANTIREPLAY_PERSISTENCE_ENABLED=true` persists the timestamp cache for
  restarts; it does not turn the cache into a distributed lock.

## Access-code and observer credentials

- Browser access uses an opaque one-time code. Signed lab-access JWTs never go
  in URLs; OpenResty redeems by POST and sets a Secure/HttpOnly cookie.
- `ACCESS_CODE_REDEEMER_CREDENTIALS_JSON` is gateway-specific. Rotate a gateway
  credential independently and verify `X-Gateway-ID` against signed claims.
- FMU ticket redemption and session observation use short-lived,
  per-gateway observer JWTs with `ROLE_SESSION_OBSERVER`. Do not reuse the
  admin access token for observation.
- Keep `GUACAMOLE_PROVISIONER_ROUTES_JSON` explicit for remote/Lite gateways;
  never derive a remote credential from untrusted lab metadata.

## Wallet and transaction safety

- Persist MySQL, wallet data and all durable outboxes before production use.
- Institutional transaction producers reserve nonces durably by chain and
  wallet. Signed raw transaction plus local hash are persisted before the first
  broadcast.
- `STUCK_UNKNOWN` means the RPC outcome is genuinely uncertain. Reconcile the
  node, receipt and contract state before requeueing; deleting the row can create
  a nonce gap or duplicate a non-idempotent operation.
- Keep RPC failover endpoints under operator control and avoid embedding API
  keys in properties or documentation.

## Pre-deployment checklist

- [ ] Provider/consumer mode and Full/Lite topology are explicit.
- [ ] JWT key pair, wallet encryption key and database storage are persistent.
- [ ] SAML trust mode is `whitelist`; metadata HTTP is disabled.
- [ ] Marketplace public key and provisioning JWKS URLs use HTTPS.
- [ ] Admin routes are loopback/private-network restricted and token protected.
- [ ] Observer and gateway credentials are unique per gateway.
- [ ] `./mvnw test` and `./mvnw -DskipTests package` pass.
- [ ] `/actuator/health/readiness` is the orchestrator health check; `/health`
      is monitored for degraded queues and database errors.
