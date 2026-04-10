---
description: >-
  Blockchain services connecting your institutional users and lab access control system to the blockchain
---

# Blockchain Services

Spring Boot service for DecentraLabs that provides:

- Authentication and authorization (`SAML`, `WebAuthn` onboarding, JWT/JWKS)
- Institutional wallet and treasury operations
- Intent submission and authorization flows
- Provider/consumer institutional provisioning

While it is designed so that it can be deployed as an independent container (use case for lab institutional consumers), it is also included in the Lab Gateway (use case for lab institutional providers). 

## Operating Modes

`blockchain-services` supports two deployment modes:

1. `provider+consumer` mode
   This is the full mode used when `blockchain-services` runs together with Lab Gateway. The institution acts as a lab provider and can also fund reservations for its own users.
   Available capabilities:
   - SAML/OIDC/JWKS authentication endpoints
   - provider registration and provider provisioning tokens
   - provider settlement and payout operations
   - wallet, treasury, intents, and consumer funding flows

2. `consumer-only` mode
   This is the standalone mode for institutions that do not publish labs and do not provide auth endpoints for third-party access. The institution only funds reservation and access costs for its own users.
   Available capabilities:
   - institutional wallet creation/import
   - treasury and reservation funding operations
   - consumer provisioning token application and consumer registration
   - intents and local administrative dashboard
   Not available in this mode:
   - SAML/OIDC/JWKS provider endpoints
   - manual provider registration UI
   - provider settlement and payout operations

<figure><img src=".gitbook/assets/DecentraLabs - Lab Access.png" alt=""><figcaption></figcaption></figure>

This service provides four main components:

1. **Authentication and Authorization Service**: institutional SAML2 JWT authentication, OIDC/JWKS discovery, and WebAuthn support.
2. **Institutional Wallet and Treasury**: Ethereum wallet management and treasury operations for institutional lab providers and consumers.
3. **Intent Authorization and Execution**: signed intent intake, WebAuthn ceremony, and on-chain execution/status tracking.
4. **Institution Provisioning**: provider/consumer token application and Marketplace registration flows.

Together, they bridge institutional access control systems (such as **Lab Gateway**) with blockchain smart contracts in one backend.

## ✨ Key Features

### Authentication and Authorization Service
- **SAML2 Integration**: dual-path SSO flows (`/auth/saml-auth` and `/auth/saml-auth2`).
- **JWT Management**: OIDC/JWKS discovery, JWT issuance, and claim/scope-based access checks.
- **Smart Contract Validation**: direct on-chain reservation/booking queries for booking-aware flows.

### Institutional Wallet and Treasury
- **Wallet Management**: create/import/reveal institutional wallets encrypted at rest (AES-256-GCM + PBKDF2).
- **Multi-Network Support**: Mainnet/Sepolia operations with active-network switching and RPC fallback.
- **Treasury Operations**: deposits, withdrawals, spending limits/periods, and institutional financial stats.
- **Reservation Engine**: metadata-driven auto-approval/denial hooks for reservation requests.
- **Event Monitoring**: contract event listener status and resilient event processing.

### Intents and Provisioning
- **Intent Authorization**: signed intent intake with JWT scope checks, SAML/WebAuthn validation, and EIP-712 verification.
- **WebAuthn Ceremony**: authorize/status/complete flow for intent execution.
- **Institution Provisioning**: provider/consumer token application, Marketplace JWKS validation, and registration flows.

## 🏗️ Architecture Overview

```
+------------------+     +------------------------+     +--------------------+
| Marketplace dApp | <-->| Auth Service           | <-->| Smart Contracts    |
| (User Frontend)  |     | - SAML2 SSO            |     | - Diamond proxy    |
|                  |     | - JWT generation       |     | - LAB token        |
|                  |     | - Booking validation   |     | - Reservations     |
+------------------+     +------------------------+     +--------------------+
         ^                         |                             ^
         |                         |                             |
    End Users                      v                             |
                        +------------------------+               |
                        | Wallet & Treasury      |---------------+
                        | - Wallet management    |
                        | - Treasury operations  |
                        | - Contract queries     |
                        | - Auto-approval engine |
                        +------------------------+
                                   |
                                   v
                        +------------------------+
                        | Intents                |
                        | - Intent intake        |
                        | - WebAuthn ceremony    |
                        | - Status and execution |
                        +------------------------+
                                   |
                                   v
                        +------------------------+
                        | Institution Config     |
                        | - Provider token apply |
                        | - Consumer token apply |
                        | - Registration flows   |
                        +------------------------+
                                   |
                                   v
                        +------------------------+
                        | Lab Gateway            |
                        | (Provider Access)      |
                        +------------------------+
```

## 🔌 API Overview

### Auth and identity

- `GET /.well-known/openid-configuration`
- `GET /auth/jwks`
- `POST /auth/saml-auth`
- `POST /auth/saml-auth2`
- `POST /auth/checkin-institutional`
- `POST /webauthn/register`
- `POST /webauthn/revoke`
- `POST /onboarding/webauthn/options`
- `POST /onboarding/webauthn/complete`

These endpoints are only active in `provider+consumer` mode.

### Wallet and billing administration

- `POST /wallet/create`
- `POST /wallet/import`
- `POST /wallet/reveal`
- `GET /wallet/{address}/balance`
- `GET /wallet/{address}/transactions`
- `GET /wallet/listen-events`
- `GET /wallet/networks`
- `POST /wallet/switch-network`
- `POST /billing/admin/execute`
- `GET /billing/admin/status`
- `GET /billing/admin/balance`
- `GET /billing/admin/transactions`
- `GET /billing/admin/contract-info`
- `GET /billing/admin/treasury-info`
- `GET /billing/admin/top-spenders`
- `GET|POST /billing/admin/notifications`

### Intents and provisioning

- `POST /intents`
- `GET /intents/{requestId}`
- `POST /intents/authorize`
- `GET /intents/authorize/status/{sessionId}`
- `GET /intents/authorize/ceremony/{sessionId}`
- `POST /intents/authorize/complete`
- `GET /institution-config/status`
- `POST /institution-config/save-and-register`
- `POST /institution-config/retry-registration`
- `POST /institution-config/apply-provider-token`
- `POST /institution-config/apply-consumer-token`

`/institution-config/save-and-register`, `/institution-config/retry-registration`, and `/institution-config/apply-provider-token` are provider-only flows.
`/institution-config/apply-consumer-token` is the consumer-only registration flow.

## 🚀 Quick Start (Local)

### Consumer-only standalone

1. Build:

```bash
./mvnw clean package -DskipTests
```

2. Run with consumer mode defaults or set them explicitly:

```bash
FEATURES_PROVIDERS_ENABLED=false \
FEATURES_PROVIDERS_REGISTRATION_ENABLED=false \
java -jar target/blockchain-services-1.0-SNAPSHOT.war
```

3. Open `http://localhost:8080/wallet-dashboard`, create or import the institutional wallet, and apply a consumer provisioning token.

4. Verify:

- `http://localhost:8080/health`
- `http://localhost:8080/wallet-dashboard`

### Provider+consumer with Lab Gateway

1. Build:

```bash
./mvnw clean package -DskipTests
```

2. Run:

```bash
java -jar target/blockchain-services-1.0-SNAPSHOT.war
```

3. Verify:

- `http://localhost:8080/health`
- `http://localhost:8080/wallet-dashboard`

## 🐳 Quick Start (Docker)

1. Copy template env:

```bash
cp .env.example .env
```

2. Provide JWT keys in `./config/keys` (or adjust `PRIVATE_KEY_PATH` / `PUBLIC_KEY_PATH`).

3. Start:

```bash
docker compose up -d
```

4. Open `http://localhost:8080/wallet-dashboard` to create/import the institutional wallet.

For consumer-only standalone deployments, keep:

```env
FEATURES_PROVIDERS_ENABLED=false
FEATURES_PROVIDERS_REGISTRATION_ENABLED=false
ADMIN_DASHBOARD_LOCAL_ONLY=true
ADMIN_DASHBOARD_ALLOW_PRIVATE=false
ADMIN_ALLOWED_CIDRS=
SECURITY_ALLOW_PRIVATE_NETWORKS=false
```

For full Lab Gateway deployments, enable the full provider surface:

```env
FEATURES_PROVIDERS_ENABLED=true
FEATURES_PROVIDERS_REGISTRATION_ENABLED=true
```

If you want `wallet-dashboard` and the wallet/billing administrative routes to be reachable from private network ranges instead of localhost only, use:

```env
ADMIN_DASHBOARD_LOCAL_ONLY=true
ADMIN_DASHBOARD_ALLOW_PRIVATE=true
SECURITY_ALLOW_PRIVATE_NETWORKS=true
ADMIN_ALLOWED_CIDRS=10.20.0.0/16,192.168.50.0/24
ADMIN_ACCESS_TOKEN_REQUIRED=true
ADMIN_ACCESS_TOKEN=your_strong_token
```

Leave `ADMIN_ALLOWED_CIDRS` empty if you want to allow any private range. Set it if you want access limited to specific private subnets only.
If you disable `ADMIN_DASHBOARD_LOCAL_ONLY`, keep `ADMIN_ACCESS_TOKEN_REQUIRED=true` and send the token via header or cookie, not query string.

## ⚙️ Configuration Files

**Repository structure:**
```
.env.example                  # Environment template (tracked in git)
.env                          # Local config (gitignored)
data/
└── wallet-config.properties  # Auto-generated wallet address + encrypted password (gitignored)
keys/                         # RSA keys (gitignored)
├── private_key.pem           # JWT signing key
└── public_key.pem            # JWT verification key
src/main/resources/
└── application.properties    # Compiled into WAR
```

**Docker container structure:**
```
/app/
├── blockchain-services.war   # Application
├── config/
│   └── keys/                 # Mounted from ./keys
│       ├── private_key.pem
│       └── public_key.pem
├── data/                     # Persistent volume
│   └── wallets.json          # Encrypted wallets
└── logs/                     # Mounted from ./logs
```

> 💡 Configuration priority: Environment variables > `.env` (local file) > application.properties.
> For the institutional wallet specifically: env vars / secrets manager > `wallet-config.properties` (auto-generated `institutional.wallet.address` + encrypted password) > persisted wallet metadata.

## 🔒 Security Essentials

- Never commit secrets or private keys.
- Keep wallet/billing routes behind trusted network/proxy boundaries.
- If private-network access is enabled, enforce `ADMIN_ACCESS_TOKEN`.
- Keep SAML trust mode on whitelist for production.
- In `consumer-only` mode, JWT signing keys are not required for readiness because provider auth endpoints are disabled.

## 🔔 Reservation Notifications (email + ICS)

- Enable with `NOTIFICATIONS_MAIL_ENABLED=true` and choose driver `NOTIFICATIONS_MAIL_DRIVER=smtp|graph|noop` (default: noop).
- Common settings: `NOTIFICATIONS_MAIL_FROM`, `NOTIFICATIONS_MAIL_DEFAULT_TO` (comma-separated), and `NOTIFICATIONS_MAIL_TIMEZONE` (IANA zone, e.g., `Europe/Madrid`).
- SMTP driver: configure `NOTIFICATIONS_MAIL_SMTP_HOST`, `PORT`, `USERNAME`, `PASSWORD`, plus `NOTIFICATIONS_MAIL_SMTP_STARTTLS` when required.
- Microsoft Graph driver: `NOTIFICATIONS_MAIL_GRAPH_TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET`, `GRAPH_FROM` (UPN/mailbox with Mail.Send app permission).
- ICS invite attached when start/end are available; subject `Reserva aprobada: <lab>` and body includes lab, window, renter, payer, and tx hash.
- Runtime config (localhost): `GET/POST /billing/admin/notifications` to view/update settings; persisted at `./data/notifications-config.json`.

## 📊 Monitoring & Health Checks

Actuator endpoints for monitoring and Kubernetes probes (restrict `/actuator/**` at the proxy if exposed publicly):

- `GET /actuator/health/liveness` (liveness probe)
- `GET /actuator/health/readiness` (readiness probe)
- `GET /actuator/prometheus` (Prometheus scrape)
- `GET /actuator/metrics` (metrics index)
- `GET /actuator/info` (service metadata)

Use `/actuator/health/readiness` for Docker and orchestrator health checks. Keep `/health` for detailed, app-specific status pages:

Health endpoint available at `/health`:

```json
{
  "status": "UP",
  "operating_mode": "consumer-only",
  "timestamp": "2025-11-09T12:00:00Z",
  "service": "blockchain-services",
  "version": "1.0.0",
  "marketplace_key_cached": true,
  "institution_registered": true,
  "jwt_validation": "ready",
  "endpoints": {
    "saml-auth": "disabled (providers flag off)",
    "saml-auth2": "disabled (providers flag off)",
    "checkin-institutional": "disabled (providers flag off)",
    "jwks": "disabled (providers flag off)",
    "wallet-create": "available (localhost)",
    "wallet-balance": "available (localhost)",
    "billing": "available (localhost)",
    "health": "available"
  }
}
```

## 🤝 Contributing

1. Fork the project
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open Pull Request

## 📄 License

See [LICENSE](LICENSE) file for details.
