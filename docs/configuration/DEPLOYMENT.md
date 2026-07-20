# Deployment and configuration

This guide configures the canonical backend at
`Lab Gateway/blockchain-services`. The parallel `Blockchain-Services/`
repository is not the default deployment target.

## 1. Choose the topology

| Topology | Backend role | Required choices |
| --- | --- | --- |
| Lab Gateway Full | Embedded provider and consumer backend | Enable provider features; configure the gateway as the local issuer and persist MySQL, `/app/data` and lab content. |
| Lab Gateway Lite | Edge that trusts a remote Full gateway | The parent gateway's `ISSUER` points at Full. This backend does not make Lite an identity authority. Configure only the edge capabilities that the deployment needs. |
| Standalone consumer | Institution wallet, funding and consumer operations | Leave provider features disabled unless a provider flow is intentionally enabled. |

`FEATURES_PROVIDERS_ENABLED=false` is the packaged default. It controls the
provider operating mode and the controllers that are explicitly conditional
(OIDC/JWKS and FMU endpoints). It is not a substitute for network isolation:
the SAML controller's `/auth` mappings are present in the application, so a
consumer-only deployment must not expose provider access routes as a public
integration surface.

## 2. Persistent state is required in production

The following data must survive a container restart:

| State | Location / setting | Why it is durable |
| --- | --- | --- |
| MySQL | `SPRING_DATASOURCE_*` | Flyway schema, WebAuthn credentials, access delivery, audit records, nonce/outbox state, intents and contract-event journal. |
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
gateway `.env` aligned with `blockchain-services/.env`. Do not run both compose
topologies against the same port or database.

Configure the following groups before enabling traffic. `.env.example` is the
complete deployable-name reference; `application.properties` defines defaults
and units.

| Group | Required settings | Notes |
| --- | --- | --- |
| Chain and wallet | `CONTRACT_ADDRESS`, `BLOCKCHAIN_NETWORK_ACTIVE`, RPC URL, `INSTITUTIONAL_WALLET_*` or an encrypted persisted wallet | The wallet signs automated transactions. Keep RPC credentials outside Git. |
| Database | `SPRING_DATASOURCE_URL`, `SPRING_DATASOURCE_USERNAME`, `SPRING_DATASOURCE_PASSWORD` | Flyway validates migrations at startup. |
| Signing and Marketplace | `PRIVATE_KEY_PATH`, `PUBLIC_KEY_PATH`, `MARKETPLACE_PUBLIC_KEY_URL`, `PUBLIC_BASE_URL` | Mount private keys read-only and use HTTPS endpoints. |
| Provider mode | `FEATURES_PROVIDERS_ENABLED`, `FEATURES_PROVIDERS_REGISTRATION_ENABLED`, `FEATURES_ORGANIZATIONS_ENABLED` | Registration is independently feature-gated. |
| WebAuthn | `WEBAUTHN_RP_ID`, `WEBAUTHN_RP_ORIGINS`, `WEBAUTHN_USER_VERIFICATION`, `WEBAUTHN_ATTESTATION_CONVEYANCE` | Verification is required; only `none` attestation is accepted. |
| Intents | `INTENT_PAYLOAD_ENCRYPTION_KEY`, `INTENTS_AUTH_*`, `INTENT_DOMAIN_*` | The payload key is a base64/base64url 32-byte AES-256 key and is required to persist execution payloads. |
| SAML | `SAML_IDP_TRUST_MODE`, `SAML_TRUSTED_IDP`, `SAML_IDP_METADATA_OVERRIDE` | Use `whitelist` in production. |
| Admin boundary | `ADMIN_DASHBOARD_*`, `SECURITY_ALLOW_PRIVATE_NETWORKS`, `ADMIN_ALLOWED_CIDRS`, `ADMIN_ACCESS_TOKEN_*` | See [Security](../security/SECURITY.md). |
| Gateway integration | `ACCESS_CODE_REDEEMER_CREDENTIALS_JSON`, `SESSION_OBSERVER_CREDENTIALS_JSON`, `LAB_MANAGER_TOKEN*` | Credentials are per gateway; never reuse the admin token as an observer credential. |
| Lab content | `LAB_CONTENT_BASE_PATH`, `LAB_CONTENT_RETENTION`, `LAB_CONTENT_GC_INTERVAL_MS`, `LAB_CONTENT_MAX_*` | The public content route serves only safe uploaded assets and generated metadata. |
| Durable workers | `INSTITUTIONAL_*_OUTBOX_*`, `CONTRACT_EVENT_*`, `HEALTH_QUEUE_STUCK_THRESHOLD_SECONDS` | Tune only with an operator who owns reconciliation. |

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
