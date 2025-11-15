---
description: >-
  Blockchain services connecting your institutional users and lab access control system to the blockchain
---

# Blockchain Services

[![Build & Test](https://github.com/DecentraLabsCom/blockchain-services/actions/workflows/tests.yml/badge.svg)](https://github.com/DecentraLabsCom/blockchain-services/actions/workflows/tests.yml)

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

### Treasury Endpoints (`/treasury`) 🔒 *localhost only*
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/treasury/reservations` | POST | Create reservation (auto-approved/denied) |
| `/treasury/admin/execute` | POST | Execute treasury admin operations |

> 🔒 Wallet and Treasury endpoints are protected by `LocalhostOnlyFilter` and only accept requests from `127.0.0.1` / `::1`

**For detailed API documentation, see:**
- [Authentication Service API](AUTH_SERVICE.md#api-reference)
- [Wallet & Treasury API](WALLET_TREASURY.md#api-reference)

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

### Docker Deployment

1. **Build Docker image:**
   ```bash
   docker build -t blockchain-services:latest .
   ```

2. **Run with Docker Compose:**
   ```bash
   docker-compose up -d
   ```

3. **Test wallet endpoints (from inside container):**
   ```bash
   docker exec blockchain-services sh -c 'curl http://localhost:8080/wallet/create \
     -H "Content-Type: application/json" \
     -d "{\"password\":\"TestPassword123\"}"'
   ```

> ⚠️ **Production Deployment**: Never run in production without proper security configuration. See the [Configuration](#configuration) section below.

## ⚙️ Configuration

### Critical Environment Variables

| Variable | Required | Description | Default |
|----------|----------|-------------|---------|
| `CONTRACT_ADDRESS` | 🔴 Yes | Diamond contract address | - |
| `WALLET_ADDRESS` | 🔴 Yes | Institutional wallet address | - |
| `BLOCKCHAIN_NETWORK_ACTIVE` | 🟡 Recommended | Initial network (`mainnet`/`sepolia`) | `sepolia` |
| `ETHEREUM_MAINNET_RPC_URL` | 🟡 Recommended | Mainnet RPC endpoints (comma-separated) | Public RPCs |
| `ETHEREUM_SEPOLIA_RPC_URL` | 🟡 Recommended | Sepolia RPC endpoints (comma-separated) | Public RPCs |

### Optional Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SPRING_PROFILES_ACTIVE` | Active Spring profile | `default` |
| `JAVA_OPTS` | JVM options | - |
| `ALLOWED_ORIGINS` | CORS allowed origins | - |
| `PRIVATE_KEY_PATH` | Path to JWT private key | `config/keys/private_key.pem` |
| `PUBLIC_KEY_PATH` | Path to JWT public key | `config/keys/public_key.pem` |
| `BASE_DOMAIN` | Base URL for JWT claims | `http://localhost` |

### Configuration Files

```
config/
├── application.properties    # Main configuration
└── keys/
    ├── private_key.pem       # JWT signing key
    └── public_key.pem        # JWT verification key
```

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
- ✅ CORS origins restricted to trusted domains

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

## 🔗 Related Documentation

- [Authentication Service Details](AUTH_SERVICE.md)
- [Wallet & Treasury Details](WALLET_TREASURY.md)
