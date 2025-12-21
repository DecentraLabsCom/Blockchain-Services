---
description: >-
  Blockchain services connecting your institutional users and lab access control system to the blockchain
---

# Blockchain Services

[![Build & Test](https://github.com/DecentraLabsCom/blockchain-services/actions/workflows/tests.yml/badge.svg)](https://github.com/DecentraLabsCom/blockchain-services/actions/workflows/tests.yml)
[![Security Scan](https://github.com/DecentraLabsCom/blockchain-services/actions/workflows/security.yml/badge.svg)](https://github.com/DecentraLabsCom/blockchain-services/actions/workflows/security.yml)
[![Release](https://github.com/DecentraLabsCom/blockchain-services/actions/workflows/release.yml/badge.svg)](https://github.com/DecentraLabsCom/blockchain-services/actions/workflows/release.yml)

Comprehensive Spring Boot service for the DecentraLabs ecosystem that combines authentication, authorization, and institutional treasury management with full Ethereum wallet capabilities. While it is designed so that it can be deployed as an independent container, it is recommended to use it with the Lab Gateway. 

<figure><img src=".gitbook/assets/DecentraLabs - Lab Access.png" alt=""><figcaption></figcaption></figure>

This service provides two main components:

1. **Authentication & Authorization Service**: Web3-based JWT authentication with wallet challenges and SAML2 SSO integration
2. **Institutional Wallet & Treasury**: Complete Ethereum wallet management and treasury operations for institutional lab providers and consumers

Together, they offer a bridge between institutional access control systems (like the **Lab Gateway** in the figure above) and blockchain-based smart contracts.

## 📚 Documentation Structure

This documentation is organized into specialized sections:

* **[Authentication Service](AUTH_SERVICE.md)** - Wallet challenges, SAML2 SSO, JWT generation and validation
* **[Institutional Wallet & Treasury](WALLET_TREASURY.md)** - Ethereum wallet management, treasury operations, and smart contract interactions

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
                        | Lab Gateway            |
                        | (Provider Access)      |
                        +------------------------+
```

## 🛠️ Technology Stack

### Core Framework
- **Spring Boot** - Application framework with embedded Tomcat
- **Java** - LTS version with modern language features
- **Maven** - Build automation and dependency management

### Security & Authentication
- **Spring Security** - Authentication and authorization
- **JJWT** - JWT generation and validation
- **Bouncy Castle** - Cryptographic operations (AES-256-GCM, PBKDF2)

### Blockchain Integration
- **Web3j** - Ethereum client library for smart contract interactions
- **Netty** - Async I/O for RPC communication
- **OkHttp** - HTTP client with connection pooling

### Data Processing
- **Jackson** - JSON serialization/deserialization
- **Lombok** - Boilerplate code reduction
- **Bucket4j** - Rate limiting for API endpoints

### Deployment & Operations
- **Docker** - Containerized deployment with multi-stage builds
- **Tomcat Embedded** - Servlet container (via Spring Boot)
- **GitHub Actions** - CI/CD for build, test, security scanning, and releases

## 🚀 Key Features

### Authentication & Authorization Service
- **Wallet Challenges**: Web3 signature-based authentication with blockchain verification
- **SAML2 Integration**: Dual-path SSO (auth-only and booking-aware flows)
- **JWT Management**: JWKS discovery, dynamic key rotation, and claim-based authorization
- **Smart Contract Validation**: Direct on-chain reservation and booking queries

### Institutional Wallet & Treasury
- **Wallet Management**: Create/import encrypted institutional wallets (AES-256-GCM + PBKDF2)
- **Multi-Network Support**: Mainnet/Sepolia/Goerli with automatic RPC failover
- **Treasury Operations**: Deposits, withdrawals, spending limits, and user financial stats
- **Reservation Engine**: Metadata-driven auto-approval/denial based on lab availability
- **Event Monitoring**: Real-time blockchain event listening and status reporting

## 🔧 API Overview

### Authentication Endpoints (`/auth`)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/.well-known/openid-configuration` | GET | OIDC discovery metadata |
| `/auth/jwks` | GET | JSON Web Keys for token validation |
| `/auth/message` | GET | Get wallet challenge message |
| `/auth/wallet-auth` | POST | Wallet authentication (no booking) |
| `/auth/wallet-auth2` | POST | Wallet authentication + authorization |
| `/auth/saml-auth` | POST | SAML2 authentication |
| `/auth/saml-auth2` | POST | SAML2 authentication + authorization |

### WebAuthn Onboarding Endpoints (`/onboarding/webauthn`)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/onboarding/webauthn/key-status/{stableUserId}` | GET | Check if user has registered credentials |
| `/onboarding/webauthn/options` | POST | Get credential creation options (challenge) |
| `/onboarding/webauthn/complete` | POST | Complete registration with attestation |
| `/onboarding/webauthn/status/{sessionId}` | GET | Poll for onboarding session result |

> These endpoints implement the dedicated onboarding endpoint from the Federated SSO Architecture spec.
> The browser talks directly to the WIB for WebAuthn credential registration, ensuring the SP never sees
> the challenge or user signature.

### WebAuthn Credential Management (`/webauthn`)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/webauthn/register` | POST | Register pre-authenticated credential (legacy) |
| `/webauthn/revoke` | POST | Revoke a user's credential |

### Wallet Endpoints (`/wallet`) 🔒 *localhost only*
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/wallet/create` | POST | Create new encrypted wallet |
| `/wallet/import` | POST | Import existing wallet |
| `/wallet/{address}/balance` | GET | Get ETH and LAB token balance |
| `/wallet/{address}/transactions` | GET | Get transaction history |
| `/wallet/listen-events` | GET | Event listener status |
| `/wallet/networks` | GET | List available networks |
| `/wallet/switch-network` | POST | Switch active network |
| `/wallet/reveal` | POST | Reveal institutional private key (localhost + password) |

### Treasury Endpoints (`/treasury`) 🔒 *localhost only*
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/treasury/reservations` | POST | Create reservation (auto-approved/denied) |
| `/treasury/admin/execute` | POST | Execute treasury admin operations |

> 🔒 Wallet and Treasury endpoints are protected by `LocalhostOnlyFilter` and only accept requests from `127.0.0.1` / `::1`

## 🛠️ Quick Start

### Prerequisites

* Java 21+
* Maven 3.6+
* Docker (optional, for containerized deployment)

### Local Development

1. **Build the project:**
   ```bash
   mvn clean package -DskipTests
   ```

2. **Run locally:**
   ```bash
   java -jar target/auth-1.0-SNAPSHOT.war
   ```

3. **Access the service:**
   - Health check: http://localhost:8080/health
   - OIDC discovery: http://localhost:8080/auth/.well-known/openid-configuration
   - JWKS endpoint: http://localhost:8080/auth/jwks

### Docker Deployment (Development)

> ⚠️ **IMPORTANT**: Docker deployment requires RSA keys and wallet configuration that are NOT included in the repository.

1. **Generate RSA keys for JWT signing:**
   ```bash
   mkdir -p keys
   openssl genrsa -out keys/private_key.pem 2048
   openssl rsa -in keys/private_key.pem -pubout -out keys/public_key.pem
   chmod 400 keys/*.pem
   ```

2. **Start services (dev; `docker-compose.override.yml` is auto-loaded to expose port 8080):**
   ```bash
   docker compose up -d
   ```

   This compose file starts a MySQL container and wires `SPRING_DATASOURCE_*` from `MYSQL_*` in your `.env`.

   **Production (no port exposure):**
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
   ```

   **Database migrations:** When `SPRING_DATASOURCE_URL` is configured, Flyway automatically creates the
   auth, WebAuthn, and intents tables on startup. This is how Lab Gateway keeps the schema in sync.

3. **Configure institutional wallet:**
   
   Open http://localhost:8080/wallet-dashboard in your browser
   
   - **Create new wallet:** Click "Create Wallet" → Set password → Save credentials
   - **Import existing:** Click "Import Wallet" → Provide private key + password
   - The backend automatically encrypts the private key into `/app/data/wallets.json`, stores the address and an AES-GCM–encrypted password in `/app/data/wallet-config.properties` (`institutional.wallet.password.encrypted`), and hot-reloads the institutional wallet.
   
   > 💡 Nothing else to configure unless you want to override the wallet via environment variables (see below).

> 💡 **Testing APIs:** For manual testing, use `test-wallet-local.sh` / `test-wallet-local.ps1`

> 💡 **Reverse Proxy:** When this project is consumed as a submodule behind OpenResty, use `docker-compose.yml` + `docker-compose.prod.yml` so the container stays on the internal network without publishing `8080`.

### 📦 CI/CD & Production Deployment

This project uses a **security-first deployment approach**:

#### GitHub Actions Workflows

| Pipeline | Purpose | Output | Trigger |
|----------|---------|--------|---------|
| **Build & Test** | Validates code quality | Test results | Every PR/push |
| **Security Scan** | Detects vulnerabilities | Security alerts | Weekly + PR |
| **Release** | Creates versioned artifacts | WAR + checksums | Git tag `v*.*.*` |
| **Docker Image** | Builds container | Docker image | Manual dispatch |

#### Secrets Management

- ✅ `.env.example` tracked (public template). Copy it to `.env` locally (gitignored) before running anything.
- 🔐 `keys/*.pem` gitignored (generate per environment)
- 🔐 Wallet address/password captured through `/wallet-dashboard` → private key encrypted into `/app/data/wallets.json`, password stored as `institutional.wallet.password.encrypted` inside `wallet-config.properties`. Persist `wallet.config.encryption-key` separately (env/secrets manager) or let the service auto-generate it into `/app/data/.wallet-encryption-key` (configurable via `wallet.config.encryption-key-file`). Just ensure that `/app/data` is a persistent volume so restarts can decrypt the password; provide env overrides only if you need full external secret management.

#### Production Deployment Steps

1. **Download release artifacts:**
   ```bash
   # Get latest release WAR
   wget https://github.com/DecentraLabsCom/blockchain-services/releases/latest/download/blockchain-services-X.Y.Z.war
   
   # Verify integrity
   sha256sum -c blockchain-services-X.Y.Z.war.sha256
   ```

2. **Prepare environment:**
   ```bash
   # Generate RSA keys
   mkdir -p keys
   openssl genrsa -out keys/private_key.pem 2048
   openssl rsa -in keys/private_key.pem -pubout -out keys/public_key.pem
   chmod 400 keys/*.pem

   # Copy .env file and edit it in case you need it
   cp .env.example .env
   
   # For improved security, configure production secrets in AWS/Azure secret manager
   # INSTITUTIONAL_WALLET_PASSWORD
   # RPC URLs with API keys
   ```

3. **Deploy:**
   ```bash
   docker-compose up -d
   ```

4. **Configure institutional wallet:**
   
   Access http://your-domain/wallet-dashboard and create/import the wallet.

> ⚠️ **CRITICAL:** Never commit secrets. Use AWS Secrets Manager / Azure Key Vault for production.

## ⚙️ Configuration

### Critical Environment Variables

| Variable | Required | Description | Default |
|----------|----------|-------------|---------|
| `CONTRACT_ADDRESS` | 🔴 Yes | DecentraLabs contract address | - |
| `WALLET_ADDRESS` | 🔴 Yes | Institutional wallet address | - |
| `BLOCKCHAIN_NETWORK_ACTIVE` | 🟡 Recommended | Initial network (`mainnet`/`sepolia`) | `sepolia` |
| `ETHEREUM_MAINNET_RPC_URL` | 🟡 Recommended | Mainnet RPC endpoints (comma-separated) | Public RPCs |
| `ETHEREUM_SEPOLIA_RPC_URL` | 🟡 Recommended | Sepolia RPC endpoints (comma-separated) | Public RPCs |

### Optional Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SPRING_PROFILES_ACTIVE` | Active Spring profile | `default` |
| `JAVA_OPTS` | JVM options | - |
| `SPRING_DATASOURCE_URL` | JDBC URL for MySQL (enables persistence + migrations) | - |
| `SPRING_DATASOURCE_USERNAME` | MySQL username | - |
| `SPRING_DATASOURCE_PASSWORD` | MySQL password | - |
| `ALLOWED_ORIGINS` | CORS allowed origins | - |
| `PRIVATE_KEY_PATH` | Path to JWT private key | `config/keys/private_key.pem` |
| `PUBLIC_KEY_PATH` | Path to JWT public key | `config/keys/public_key.pem` |
| `ADMIN_DASHBOARD_LOCAL_ONLY` | `true` blocks `/treasury/admin/**` unless request is localhost/private and internally authenticated | `true` |
| `ADMIN_DASHBOARD_ALLOW_PRIVATE` | Allow private network access for admin endpoints (requires internal token) | `false` |
| `SECURITY_ALLOW_PRIVATE_NETWORKS` | Allow private networks for internal endpoints (requires internal token) | `false` |
| `SECURITY_INTERNAL_TOKEN` | Shared secret for internal endpoints (`/wallet`, `/treasury`, `/wallet-dashboard`) | - |
| `SECURITY_INTERNAL_TOKEN_HEADER` | Header name for internal token | `X-Internal-Token` |
| `SECURITY_INTERNAL_TOKEN_COOKIE` | Cookie name for internal token | `internal_token` |
| `SECURITY_INTERNAL_TOKEN_REQUIRED` | Require internal token for private networks | `true` |
| `SAML_IDP_TRUST_MODE` | `whitelist` or `any` for IdP trust | `any` |
| `SAML_METADATA_ALLOW_HTTP` | Allow HTTP metadata URLs (not recommended) | `false` |
> When deploying behind a reverse proxy, set `SECURITY_ALLOW_PRIVATE_NETWORKS=true` and a strong `SECURITY_INTERNAL_TOKEN`.
> Configure the proxy to send `X-Internal-Token` (or the `internal_token` cookie) when calling `/wallet`, `/treasury`, and `/wallet-dashboard`.
> For local dev, set `SECURITY_INTERNAL_TOKEN_REQUIRED=false` to skip the token check.


### WebAuthn Onboarding Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `WEBAUTHN_RP_ID` | Relying Party ID (domain users see in browser) | `${BASE_DOMAIN}` or `localhost` |
| `WEBAUTHN_RP_NAME` | Display name for the RP | `DecentraLabs Gateway` |
| `WEBAUTHN_RP_ORIGINS` | Allowed origins for attestation (comma-separated) | `https://localhost,https://localhost:443` |
| `WEBAUTHN_TIMEOUT_MS` | Ceremony timeout in milliseconds | `120000` |
| `WEBAUTHN_SESSION_TTL_SECONDS` | Challenge expiration time | `300` |
| `WEBAUTHN_ATTESTATION_CONVEYANCE` | `none`, `indirect`, or `direct` | `none` |
| `WEBAUTHN_AUTHENTICATOR_ATTACHMENT` | `platform`, `cross-platform`, or empty | (empty) |
| `WEBAUTHN_RESIDENT_KEY` | `required`, `preferred`, or `discouraged` | `preferred` |
| `WEBAUTHN_USER_VERIFICATION` | `required`, `preferred`, or `discouraged` | `preferred` |

> **Important for Lab Gateway:** When deploying behind the Lab Gateway, set `WEBAUTHN_RP_ID` to the gateway's
> public domain (e.g., `lab.institution.edu`) and ensure `WEBAUTHN_RP_ORIGINS` includes all HTTPS variants
> of the gateway URL. The `BASE_DOMAIN` env var, if set, is used as the default RP ID.

### Configuration Files

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

### Example Docker Run

```bash
docker run -p 8080:8080 \
  -e CONTRACT_ADDRESS=0xYourContractAddress \
  -e WALLET_ADDRESS=0xYourWalletAddress \
  -e ETHEREUM_SEPOLIA_RPC_URL=https://your-rpc-endpoint \
  -v /secure/keys:/app/config/keys:ro \
  blockchain-services:latest
```

## 🔐 Security

**CRITICAL**: This service handles sensitive cryptographic keys and blockchain transactions.

### Security Checklist

- ✅ Private keys provided via environment variables (never hardcoded)
- ✅ RSA keys mounted with proper permissions (`chmod 400`)
- ✅ RPC URLs configured with authenticated endpoints
- ✅ Localhost-only filters enabled for sensitive operations
- ✅ Internal token required when allowing private network access
- ✅ CORS origins restricted to trusted domains

## Reservation Notifications (email + ICS)

- Enable with `NOTIFICATIONS_MAIL_ENABLED=true` and choose driver `NOTIFICATIONS_MAIL_DRIVER=smtp|graph|noop` (default: noop).
- Common settings: `NOTIFICATIONS_MAIL_FROM`, `NOTIFICATIONS_MAIL_DEFAULT_TO` (comma-separated), and `NOTIFICATIONS_MAIL_TIMEZONE` (IANA zone, e.g., `Europe/Madrid`).
- SMTP driver: configure `NOTIFICATIONS_MAIL_SMTP_HOST`, `PORT`, `USERNAME`, `PASSWORD`, plus `NOTIFICATIONS_MAIL_SMTP_STARTTLS` when required.
- Microsoft Graph driver: `NOTIFICATIONS_MAIL_GRAPH_TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET`, `GRAPH_FROM` (UPN/mailbox with Mail.Send app permission).
- ICS invite attached when start/end are available; subject `Reserva aprobada: <lab>` and body includes lab, window, renter, payer, and tx hash.
- Runtime config (localhost): `GET/POST /treasury/admin/notifications` to view/update settings; persisted at `./data/notifications-config.json`.

## 📊 Monitoring & Health Checks

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
