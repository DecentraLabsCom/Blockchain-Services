# Deployment and configuration

This guide configures `blockchain-services` across its supported deployment
topologies.

## 1. Choose the topology

| Topology | Backend role | Required choices |
| --- | --- | --- |
| Lab Gateway Full | Provider and consumer backend used with the Gateway | Set `BLOCKCHAIN_SERVICES_MODE=provider-consumer`; configure the gateway as the local issuer and persist MySQL, `/app/data` and lab content. |
| Lab Gateway Lite | Edge that trusts a remote Full gateway | The parent gateway's `ISSUER` points at Full. This backend does not make Lite an identity authority. Configure only the edge capabilities that the deployment needs. |
| Standalone consumer | Institution wallet, funding and consumer operations | Set `BLOCKCHAIN_SERVICES_MODE=consumer-only`; provider routes and automation remain disabled. |

`BLOCKCHAIN_SERVICES_MODE` controls the backend role independently of the
gateway topology and must be set explicitly for new deployments:

```env
BLOCKCHAIN_SERVICES_MODE=consumer-only     # or provider-consumer
```

`FEATURES_PROVIDERS_ENABLED=false` remains the packaged fallback for older
configurations. An explicit mode wins over that flag. The parent gateway owns
the Full/Lite topology; changing `ISSUER` or adding a Lite access plane must not
change a backend from consumer-only to provider-consumer. Spring Security
rejects provider access routes and all `/lab-admin/**` routes in
`consumer-only` at the application boundary, and the provider Lab Admin
controller is not created. `/lab-content/**` remains the common public
read-only content surface. Network isolation remains required as defense in
depth for administrative and future surfaces.

## 2. Persistent state is required in production

The following data must survive a container restart:

| State | Location / setting | Why it is durable |
| --- | --- | --- |
| MySQL | `SPRING_DATASOURCE_*` | Flyway schema, WebAuthn credentials, access delivery, audit records, nonce/outbox state, intents, contract-event journal and lab-content deletion hand-off. |
| Backend data | `/app/data` | Wallet store, generated wallet configuration and JWT key material when those defaults are used. |
| Lab content | `LAB_CONTENT_BASE_PATH` | Uploaded metadata, images and documents; deletions are retained by tombstone before garbage collection. |
| Wallet encryption key | `WALLET_CONFIG_ENCRYPTION_KEY` or `WALLET_CONFIG_KEY_FILE` | Required to recover encrypted wallet material. |

`WEBAUTHN_CREDENTIALS_REQUIRE_DATABASE=true` and
`CONTRACT_EVENT_PERSISTENCE_REQUIRED=true` are production defaults. Turn either
off only in an isolated, memory-only development environment; doing so removes
restart-safe credential or event-processing guarantees.

## 3. Configure environment variables

Copy `.env.example` to `.env` for a standalone development deployment. For an
integrated gateway, use the parent `Lab Gateway` compose file and keep the root
gateway `.env` aligned with `blockchain-services/.env`. The backend template
lists backend runtime variables; the parent template owns gateway-edge values
such as `ISSUER`, `RESERVATION_PROJECTION_URL`,
`RESERVATION_PROJECTION_GATEWAY_ID` and the mounted
`RESERVATION_PROJECTION_TOKEN_FILE`. Do not run both compose topologies against
the same port or database.

Configure the following groups before enabling traffic. `.env.example` is the
complete deployable-name reference; `application.properties` defines defaults
and units.

| Group | Required settings | Notes |
| --- | --- | --- |
| Chain and wallet | `CONTRACT_ADDRESS`, `BLOCKCHAIN_NETWORK_ACTIVE`, RPC URL, `INSTITUTIONAL_WALLET_*` or an encrypted persisted wallet | The institutional wallet signs general automated transactions. Provider settlement additionally requires `PROVIDER_SETTLEMENT_APPROVER_PRIVATE_KEY` and `PROVIDER_SETTLEMENT_PAYER_PRIVATE_KEY`; keep all secrets outside Git. |
| Database | `SPRING_DATASOURCE_URL`, `SPRING_DATASOURCE_USERNAME`, `SPRING_DATASOURCE_PASSWORD` | Flyway validates migrations at startup. |
| Signing and Marketplace | `PRIVATE_KEY_PATH`, `PUBLIC_KEY_PATH`, `MARKETPLACE_PUBLIC_KEY_URL`, `PUBLIC_BASE_URL` | Mount private keys read-only and use HTTPS endpoints. |
| Provider mode | `FEATURES_PROVIDERS_ENABLED`, `FEATURES_PROVIDERS_REGISTRATION_ENABLED`, `FEATURES_ORGANIZATIONS_ENABLED`, `PROVIDER_RESERVATION_AVAILABILITY_LOCK_TIMEOUT_SECONDS` | Registration is independently feature-gated. Provider reservation confirmation/denial automation is enabled only when the provider flag is true and the wallet is the current lab owner or its authorized backend. Capacity checks use a shared MySQL advisory lock keyed by chain, contract and lab; all replicas that can confirm the same lab must use the same persistent database. |
| WebAuthn | `WEBAUTHN_RP_ID`, `WEBAUTHN_RP_ORIGINS`, `WEBAUTHN_AUTHENTICATOR_ATTACHMENT`, `WEBAUTHN_USER_VERIFICATION`, `WEBAUTHN_ATTESTATION_CONVEYANCE` | `preferred` verification is the default for browser/provider compatibility; `required` remains available as a strict policy. Only `none` attestation is accepted. |
| Intents and institutional sessions | `INTENT_PAYLOAD_ENCRYPTION_KEY`, `INTENTS_AUTH_*`, `AUTH_INSTITUTIONAL_SESSION_TTL_SECONDS`, `INTENT_DOMAIN_*`, `INTENT_AUTHORIZATION_SESSION_TTL_SECONDS`, `INTENT_AUTHORIZATION_SESSION_CLEANUP_INTERVAL_SECONDS`, `INTENT_AUTHORIZATION_SESSION_PROCESSING_LEASE_SECONDS` | The payload key is a base64/base64url 32-byte AES-256 key and is required for durable intent payloads and backend institutional session credentials. `AUTH_INSTITUTIONAL_SESSION_TTL_SECONDS` defaults to 3600 and is the absolute backend reauthentication horizon. WebAuthn authorization sessions and results are durable in MySQL; the lease fences completion across replicas. |
| SAML | `SAML_IDP_TRUST_MODE`, `SAML_TRUSTED_IDP`, `SAML_IDP_METADATA_OVERRIDE` | Use `whitelist` in production. |
| Admin boundary | `ADMIN_DASHBOARD_*`, `SECURITY_ALLOW_PRIVATE_NETWORKS`, `ADMIN_ALLOWED_CIDRS`, `ADMIN_ACCESS_TOKEN_*` | See [Security](../security/SECURITY.md). |
| Gateway integration | `ACCESS_CODE_REDEEMER_CREDENTIALS_JSON`, `SESSION_OBSERVER_CREDENTIALS_JSON`, `LAB_MANAGER_TOKEN*` | Credentials are per gateway; never reuse the admin token as an observer credential. |
| Lite reservation projection | `RESERVATION_PROJECTION_CREDENTIALS_JSON` | Full/backend side only. JSON is keyed by normalized gateway ID and each entry must contain a constant-time-compared `token` and HTTPS `accessUri`. The parent Lite gateway config uses `RESERVATION_PROJECTION_URL`, `RESERVATION_PROJECTION_GATEWAY_ID` and a mounted `RESERVATION_PROJECTION_TOKEN_FILE`. |
| Lab content | `LAB_CONTENT_BASE_PATH`, `LAB_CONTENT_RETENTION`, `LAB_CONTENT_GC_INTERVAL_MS`, `LAB_CONTENT_MAX_*` | The public content route serves only safe uploaded assets and generated metadata. |
| Lab metadata fetches | `LAB_METADATA_MAX_BYTES`, `LAB_METADATA_HTTP_*`, `LAB_METADATA_MAX_CONCURRENT_FETCHES`, `LAB_METADATA_LOCAL_*` | Remote metadata is HTTPS-only and bound to the provider origin registered on-chain. Keep local fixtures disabled in production. |
| Durable workers | `INSTITUTIONAL_*_OUTBOX_*`, `CONTRACT_EVENT_*`, `LAB_CONTENT_DELETION_OUTBOX_*`, `LAB_CONTENT_DELETION_RECONCILIATION_BATCH_SIZE`, `HEALTH_QUEUE_STUCK_THRESHOLD_SECONDS` | Tune only with an operator who owns reconciliation. Ambiguous deletion broadcasts remain blocked and must be reviewed as `STUCK_UNKNOWN`; do not cancel them by timeout alone. |

The less common runtime controls are intentionally also present in the
repository `.env.example`, including access-code encryption and cleanup,
institutional receipt polling, event websocket selection, FMU ticket persistence
and rate limits, SAML audience/recipient validation, WebAuthn origin overrides,
transaction-monitor leases, treasury collection/pruning and reservation timing.
Use the variable names and defaults from that template rather than inventing
property names from the Spring keys.

`CONTRACT_ADDRESS` has no packaged fallback and is mandatory. The service
does not become ready until it has queried the configured RPC and verified the
current deployment against the versioned manifests in
`src/main/resources/contract/`: expected chain ID, Diamond bytecode, Diamond
loupe interface, exact facet set and selector routing, ABI/selector manifest
hashes, expected owner/admin role, the critical `DiamondInit` address, and the
bytecode hash of every facet. A mismatch or an unavailable RPC fails startup;
it is not reported as a recoverable application health degradation.

The Sepolia manifest is pinned to
`0x1170d2D322Ff2cCeb20e6E79D2b3D2dfABFe6372`. Deploying a new Diamond requires
regenerating the ABI/selector manifest and updating the deployment manifest
and hashes in the same release. Do not disable
`CONTRACT_VERIFICATION_ENABLED` in a production deployment.

### External reservation timing

The coordinated reservation contract uses a five-minute pending-request TTL
and a ten-minute minimum lead before the laboratory start. Provider listeners
keep twelve block confirmations and use 15-second event polling, retry delay,
and a 30-second reconciliation cadence by default. If finality or provider
processing misses the on-chain deadline, the request remains unconfirmed and
expires without capturing credits; do not weaken the confirmation or
canonicality checks to compensate for the shorter window.

`INTENT_PAYLOAD_ENCRYPTION_KEY` must be a base64/base64url-encoded 32-byte
AES key. The Full Gateway setup prompts for it and generates one when the
answer is empty. A direct Docker start also generates it once when the
variable is empty and persists it at
`/app/data/.intent-payload-encryption-key`. Back up this key together with
the backend data volume and never replace it while encrypted intent rows are
being retained.

### WebAuthn authenticator attachment

The default `WEBAUTHN_AUTHENTICATOR_ATTACHMENT=platform` registers a
credential with the authenticator local to the user's device: for example,
Windows Hello, Touch ID, Face ID or an Android screen-lock authenticator.
`WEBAUTHN_USER_VERIFICATION=preferred` asks the browser/provider to verify the
user when possible but permits an assertion without the UV flag. Set it to
`required` when every registered client must return `UV=true`; the backend then
rejects registration and intent authorization when the flag is absent. Set it
to `discouraged` only when the deployment deliberately does not request UV.

The PIN or biometric dialog shown by a browser is not itself proof of WebAuthn
user verification. The signed authenticator-data UV flag is authoritative, and
support can vary by browser, operating system and passkey provider.

Set `WEBAUTHN_AUTHENTICATOR_ATTACHMENT=cross-platform` when the deployment is
intended to use an external FIDO2 security key or another roaming authenticator.
Leave it empty only when the deployment must accept local, external and hybrid
choices. The attachment setting applies when registering a credential; changing
it does not convert existing credentials, so users must register a new
credential after changing the setting.

### WebAuthn authorization hints and transports

The authorization ceremony sends each allowed credential by credential ID and
does not send the optional `hints` or `transports` fields to the browser. Those
fields are advisory, and stale or mixed values from a passkey provider can
prevent a valid browser/provider from selecting the credential. Registration
transport metadata is still retained for diagnostics, but it is not treated as
a security restriction.

## 4. Start and verify

For local development:

```bash
./mvnw test
./mvnw -DskipTests package
java -jar target/blockchain-services-1.0-SNAPSHOT.war
```

On Windows, use `./mvnw.cmd test` and `./mvnw.cmd -DskipTests package`.
The repository `docker-compose.yml` is suitable for a standalone backend. The
parent Lab Gateway compose topology is the correct entry point for Full or Lite
integration.

After startup, distinguish the probes:

| Endpoint | Use |
| --- | --- |
| `GET /actuator/health/liveness` | Process liveness. |
| `GET /actuator/health/readiness` | Orchestrator readiness, including SAML metadata health. |
| `GET /health` | Detailed operator view: mode, key/RPC/database status and durable-queue blockers. |

A detailed `DEGRADED` response or HTTP `503` from `/health` is an operational
signal. Inspect `queue_health_errors` and the affected durable tables before
retrying, deleting or recreating any transaction.

## 5. Upgrade checklist

1. Back up MySQL, persistent data, wallet encryption key and lab-content
   volume.
2. Run the packaged build and the test suite.
3. Deploy with Flyway enabled; do not manually skip migrations.
4. Confirm liveness, readiness and detailed `/health` separately.
5. Verify the intended provider/consumer mode, Marketplace key, SAML metadata
   status and one gateway-specific observer credential.
6. Review durable queues before and after the rollout. A `STUCK_UNKNOWN` row
   is evidence of an uncertain broadcast, not a request to submit a new nonce.

For access and key recovery controls, use [Security](../security/SECURITY.md).
Queue semantics and event replay are covered in private operator runbooks.
