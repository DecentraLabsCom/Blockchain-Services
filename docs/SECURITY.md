# Security Configuration Guide

Minimum actions to keep `blockchain-services` safe in production.

## Keys and secrets
- JWT signing keys live outside the repo. Mount them at `/app/config/keys` and point `PRIVATE_KEY_PATH`/`PUBLIC_KEY_PATH` (defaults already target that folder). Use `chmod 400`/`444` on POSIX systems.
- `KeyService` validates key existence and warns on permissive permissions during startup.
- Marketplace tokens are verified with an RSA public key pulled from `marketplace.public-key-url` (HTTPS). Keep the endpoint controlled/trusted and monitor fetch errors.
- Never commit the institutional private key; `.env` is gitignored, prefer a secrets manager for `INSTITUTIONAL_WALLET_*` and RPC URLs.

## Institutional wallet handling
- Wallets are encrypted with AES-256-GCM + PBKDF2 (65,536 iterations) and stored in `./data/wallets.json`.
- The wallet password in `wallet-config.properties` is encrypted with `wallet.config.encryption-key`; the service can auto-generate and persist the key to `/app/data/.wallet-encryption-key` if none is provided. Persist `/app/data` in Docker so restarts can decrypt the wallet.
- Sensitive endpoints are behind `LocalhostOnlyFilter`: `/wallet`, `/billing`, `/billing/admin/notifications`, `/wallet-dashboard`, `/institution-config`, and `/onboarding/token`.
- `/onboarding/token/**` is currently reserved in security filters/CORS; there is no public controller endpoint in this repository version.
- Keep `security.allow-private-networks=false` unless you run behind a trusted private network and enforce a strong `security.access-token`.
- Forwarded client IP headers are only trusted from `security.trusted-proxy-cidrs` (default: loopback + Docker-style `172.16.0.0/12`). If your reverse proxy lives on different private ranges, set that property explicitly.
- The administrative dashboard also observes `admin.dashboard.local-only` and `admin.dashboard.allow-private`.
  - `admin.dashboard.local-only=true` keeps dashboard access limited to localhost by default.
  - `admin.dashboard.allow-private=true` allows private-network access only when `security.allow-private-networks=true` and token rules permit it.
  - `admin.dashboard.local-only=false` removes the locality check, but a valid admin access token is still required whenever `security.access-token.required=true`.
- Do not distribute `security.access-token` via query parameters. The backend accepts it only via header/cookie to avoid leaking it into logs, history, and referrers.
- Provisioning token JWKS fetches should keep bounded network waits; tune `PROVISIONING_TOKEN_HTTP_CONNECT_TIMEOUT_MS` and `PROVISIONING_TOKEN_HTTP_READ_TIMEOUT_MS` for your environment.
- `/wallet/reveal` exists for break-glass scenarios; leave it reachable only from loopback.
- `/billing/admin/**` requires a valid access token when `security.access-token.required=true` (default).

## Authentication hardening
- Wallet auth: 5-minute timestamp window + anti-replay cache (enable disk persistence with `antireplay.persistence.enabled=true` and set `antireplay.persistence.file.path`).
- SAML: signature validation is mandatory and auto-discovers IdP metadata (`saml.idp.trust-mode`, `saml.trusted.idp.*`). Booking paths require scope `booking:read` (configurable via `auth.saml.required-booking-scope`).
- Marketplace JWTs: signature checked against the cached RSA key; failures short-circuit the flow.

## RPC and contract settings
- Provide RPC URLs through env vars (`ETHEREUM_MAINNET_RPC_URL`, `ETHEREUM_SEPOLIA_RPC_URL`) instead of hardcoding API keys.
- Set `CONTRACT_ADDRESS` for the target Diamond deployment; leave `BASE_DOMAIN` unset when running behind the Lab Gateway so issuer URLs are derived automatically.

## Pre-deployment checklist
- [ ] RSA key pair mounted read-only; startup logs show the key file check passed.
- [ ] `.env` and secrets are not in git; secret manager or deployment env injects sensitive values.
- [ ] Institutional wallet configured and decryptable; `/app/data` persisted; `wallet.config.encryption-key` stored securely.
- [ ] Localhost-only protections intact (or fronted by a trusted reverse proxy); TLS terminated before the service.
- [ ] Anti-replay persistence enabled for multi-instance deployments.
- [ ] Marketplace public key endpoint reachable over HTTPS.
