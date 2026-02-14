---
description: >-
  Blockchain services connecting your institutional users and lab access control system to the blockchain
---

# Blockchain Services

Spring Boot service for DecentraLabs that provides:

- Authentication and authorization (`wallet`, `SAML`, `WebAuthn` onboarding)
- Institutional wallet and treasury operations
- Intent submission and authorization flows
- Provider/consumer institutional provisioning

While it is designed so that it can be deployed as an independent container (use case for lab institutional consumers), it is also included in the Lab Gateway (use case for lab institutional providers). 

<figure><img src=".gitbook/assets/DecentraLabs - Lab Access.png" alt=""><figcaption></figcaption></figure>

This service provides four main components:

1. **Authentication and Authorization Service**: Web3-based JWT authentication with wallet challenges, SAML2 SSO integration, and WebAuthn support.
2. **Institutional Wallet and Treasury**: Ethereum wallet management and treasury operations for institutional lab providers and consumers.
3. **Intent Authorization and Execution**: signed intent intake, WebAuthn ceremony, and on-chain execution/status tracking.
4. **Institution Provisioning**: provider/consumer token application and Marketplace registration flows.

Together, they bridge institutional access control systems (such as **Lab Gateway**) with blockchain smart contracts in one backend.

## Key Features

### Authentication and Authorization Service
- **Wallet Challenges**: Web3 signature-based authentication with wallet verification.
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
| (User Frontend)  |     | - Wallet challenges    |     | - Diamond proxy    |
|                  |     | - SAML2 SSO            |     | - LAB token        |
|                  |     | - JWT generation       |     | - Reservations     |
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

## Current Defaults

- Java 21, Spring Boot 4.0.2
- `features.providers.enabled=false` in repository defaults
  - This means `/auth/*` provider endpoints are disabled unless you enable providers.
- Wallet/treasury/admin UI routes are restricted by localhost/private-network controls.

## API Overview

### Auth and identity

- `GET /.well-known/openid-configuration`
- `GET /auth/jwks`
- `GET /auth/message`
- `POST /auth/wallet-auth`
- `POST /auth/wallet-auth2`
- `POST /auth/saml-auth`
- `POST /auth/saml-auth2`
- `POST /auth/checkin`
- `POST /auth/checkin-institutional`
- `POST /webauthn/register`
- `POST /webauthn/revoke`
- `POST /onboarding/webauthn/options`
- `POST /onboarding/webauthn/complete`

### Wallet and treasury

- `POST /wallet/create`
- `POST /wallet/import`
- `POST /wallet/reveal`
- `GET /wallet/{address}/balance`
- `GET /wallet/{address}/transactions`
- `GET /wallet/listen-events`
- `GET /wallet/networks`
- `POST /wallet/switch-network`
- `POST /treasury/admin/execute`
- `GET /treasury/admin/status`
- `GET /treasury/admin/balance`
- `GET /treasury/admin/transactions`
- `GET /treasury/admin/contract-info`
- `GET /treasury/admin/treasury-info`
- `GET /treasury/admin/top-spenders`
- `GET|POST /treasury/admin/notifications`

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

## Quick Start (Local)

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

## Quick Start (Docker)

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

## Configuration Files

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

## Security Essentials

- Never commit secrets or private keys.
- Keep wallet/treasury routes behind trusted network/proxy boundaries.
- If private-network access is enabled, enforce `SECURITY_ACCESS_TOKEN`.
- Keep SAML trust mode on whitelist for production.

## Reservation Notifications (email + ICS)

- Enable with `NOTIFICATIONS_MAIL_ENABLED=true` and choose driver `NOTIFICATIONS_MAIL_DRIVER=smtp|graph|noop` (default: noop).
- Common settings: `NOTIFICATIONS_MAIL_FROM`, `NOTIFICATIONS_MAIL_DEFAULT_TO` (comma-separated), and `NOTIFICATIONS_MAIL_TIMEZONE` (IANA zone, e.g., `Europe/Madrid`).
- SMTP driver: configure `NOTIFICATIONS_MAIL_SMTP_HOST`, `PORT`, `USERNAME`, `PASSWORD`, plus `NOTIFICATIONS_MAIL_SMTP_STARTTLS` when required.
- Microsoft Graph driver: `NOTIFICATIONS_MAIL_GRAPH_TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET`, `GRAPH_FROM` (UPN/mailbox with Mail.Send app permission).
- ICS invite attached when start/end are available; subject `Reserva aprobada: <lab>` and body includes lab, window, renter, payer, and tx hash.
- Runtime config (localhost): `GET/POST /treasury/admin/notifications` to view/update settings; persisted at `./data/notifications-config.json`.

## 📊 Monitoring & Health Checks

Actuator endpoints for monitoring and Kubernetes probes (restrict `/actuator/**` at the proxy if exposed publicly):

- `GET /actuator/health/liveness` (liveness probe)
- `GET /actuator/health/readiness` (readiness probe)
- `GET /actuator/prometheus` (Prometheus scrape)
- `GET /actuator/metrics` (metrics index)
- `GET /actuator/info` (service metadata)

Keep `/health` for the detailed, app-specific checks used by Docker and external status pages:

Health endpoint available at `/health`:

```json
{
  "status": "UP",
  "timestamp": "2025-11-09T12:00:00Z",
  "service": "blockchain-services",
  "version": "1.0.0",
  "marketplace_key_cached": true,
  "jwt_validation": "ready",
  "endpoints": {
    "wallet-auth": "available",
    "wallet-auth2": "available",
    "saml-auth": "available",
    "saml-auth2": "available",
    "jwks": "available",
    "message": "available",
    "wallet-create": "available (localhost only)",
    "wallet-balance": "available (localhost only)",
    "treasury-reservations": "available (localhost only)",
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
