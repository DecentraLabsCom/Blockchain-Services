---
description: >-
  Authentication and authorization service connecting your lab access control system to the blockchain
---

# Blockchain Auth Service

JWT authentication microservice for the DecentraLabs ecosystem with full Ethereum wallet capabilities.

<figure><img src=".gitbook/assets/DecentraLabs - Lab Access.png" alt=""><figcaption></figcaption></figure>

This microservice provides web3-based JWT tokens and offers a bridge between institutional access control systems (like the **Lab Gateway** in the figure above) with the blockchain-based smart contracts. **Now extended with complete Ethereum wallet functionality** for creating, managing, and interacting with blockchain assets.

The following image shows the sequence diagram that illustrates the process for authenticating and authorizing a (wallet-logged in) user in the lab provider infrastructure through DecentraLabs.

```mermaid
sequenceDiagram
    autonumber
    participant U as User Browser
    participant D as Marketplace
    participant W as Wallet
    participant AS as Auth Service
    participant SC as Smart Contracts
    participant PG as Lab Gateway

    U->>D: Open lab page and connect wallet
    D->>W: Request wallet connection
    W-->>D: Return wallet address

    D->>AS: Ask for signable challenge for address
    AS-->>D: Send challenge with address and time data

    D->>W: Prompt user to sign challenge
    W-->>D: Return signature

    D->>AS: Submit address and signature
    AS->>AS: Verify signature against address
    AS->>SC: Query active reservation for address
    SC-->>AS: Return reservation data lab id access uri access key start end

    AS->>AS: Create JWT with iss iat jti aud sub nbf exp labId
    AS-->>D: Return JWT to dApp

    D->>U: Redirect user to provider access uri with jwt parameter
    U->>PG: Request guacamole path carrying jwt
    Note over PG: Gateway starts its own verification flow
```

The process for authenticating and authorizing an SSO-logged in user will be added and described here when this feature is fully implemented.

## 🚀 Features

### Authentication & Authorization
* **Wallet Authentication**: Wallet signature verification
* **JWT Authentication**: JWT token validation
* **SAML Authentication**: SSO integration with marketplace
* **Dynamic Key Retrieval**: Automatic public key downloading
* **Blockchain Integration**: Smart contract integration

### 🆕 Ethereum Wallet Management
* **Wallet Creation**: Generate new Ethereum wallets with encrypted private keys
* **Wallet Import**: Import from private key or BIP39 mnemonic phrases
* **Multi-Network Support**: Mainnet, Sepolia, Goerli networks
* **Balance Queries**: Real-time ETH balance checking
* **Transaction Signing**: Secure transaction and message signing
* **Transaction Broadcasting**: Send signed transactions to network
* **Event Listening**: Monitor smart contract events
* **Transaction History**: Basic transaction history (extensible)

### Infrastructure
* **Health Monitoring**: Health endpoint for monitoring
* **Maven Deployment**: Maven-ready to be deployed in production
* **Docker Ready**: Multi-stage build containerization
* **Spring Boot 2.7**: Modern Java framework

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Marketplace   │───▶│   Auth Service  │───▶│   Blockchain    │
│   Frontend      │    │   (JWT + Keys)  │    │   (Contracts)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🔧 Endpoints

### Health Check Endpoint
* `GET /health` - Health check

### OIDC Endpoint
* `GET /auth/.well-known/openid-configuration` - OIDC discovery metadata

### Authentication Endpoints
* `GET /auth/jwks` - JSON Web Keys
* `GET /auth/message` - Wallet challenge message
* `POST /auth/wallet-auth` - Wallet authentication (doesn't check bookings)
* `POST /auth/wallet-auth2` - Wallet authentication + authorization (checks bookings)
* `POST /auth/saml-auth` - SAML2 authentication
* `POST /auth/saml-auth2` - SAML2 authentication + authorization

### ?? Wallet Endpoints (localhost only)
* `POST /wallet/create`
* `POST /wallet/import`
* `GET /wallet/{address}/balance`
* `GET /wallet/{address}/transactions`
* `GET /wallet/listen-events`
* `GET /wallet/networks`
* `POST /wallet/switch-network`

### ?? Treasury Endpoints (localhost only)
* `POST /treasury/reservations` – triple validation + metadata-driven auto-approval/denial
* `POST /treasury/admin/execute` – institutional admin operations (localhost + wallet ownership)

> Reservations are always auto-approved/denied based on lab metadata (available days/hours and maintenance windows).
>
> Todas las rutas anteriores están protegidas por un filtro que sólo acepta peticiones cuyo `remoteAddr` sea `127.0.0.1` / `::1`.
## 🛠️ Local Development

### Prerequisites

* Java 18+
* Maven 3.6+

### Build

```bash
mvn clean package -DskipTests
```

### Run

```bash
java -jar target/auth-1.0-SNAPSHOT.war
```

## 🐳 Docker

### Multi-Stage Build

```bash
docker build -t blockchain-services:latest .
```

### Run

⚠️ **SECURITY NOTICE**: Never run in production without configuring environment variables. See [SECURITY.md](SECURITY.md) for detailed security configuration.

```bash
# Development (with mock values - NOT FOR PRODUCTION)
docker run -p 8080:8080 \
  -v $(pwd)/config:/app/config:ro \
  -v $(pwd)/keys:/app/config/keys:ro \
  blockchain-services:latest

# Production (with proper secrets)
docker run -p 8080:8080 \
  -e WALLET_PRIVATE_KEY=0xYourActualPrivateKey \
  -e CONTRACT_ADDRESS=0xYourContractAddress \
  -e RPC_URL=https://your-rpc-endpoint \
  -e WALLET_ADDRESS=0xYourWalletAddress \
  -e WALLET_ENCRYPTION_SALT=YourSecureSalt \
  -v /secure/keys:/app/config/keys:ro \
  blockchain-services:latest
```

### Testing Wallet Endpoints Locally

⚠️ **IMPORTANT**: Due to `LocalhostOnlyFilter` security restrictions, wallet endpoints (`/wallet/*`, `/treasury/*`) can only be accessed from localhost (`127.0.0.1`).

**For development/testing on your local machine**, you must execute curl commands **inside the Docker container**:

```bash
# Create a new wallet
docker exec blockchain-services sh -c 'curl -X POST http://localhost:8080/wallet/create \
  -H "Content-Type: application/json" \
  -d "{\"password\":\"TestPassword123\"}"'

# Check wallet balance
docker exec blockchain-services curl http://localhost:8080/wallet/0xYourAddress/balance
```

**In production**, when you have a frontend web application running in another Docker container on the same network, it can access these endpoints directly:

```bash
# From another container in the same Docker network
curl -X POST http://blockchain-services:8080/wallet/create \
  -H "Content-Type: application/json" \
  -d '{"password":"myStrongPassword"}'
```

## 🔐 Security

**CRITICAL**: This service handles sensitive cryptographic keys and blockchain transactions.

### Required Security Configurations

1. **Private Keys**: Must be provided via environment variables (never hardcoded)
2. **RSA Keys**: Must be mounted with proper permissions (chmod 400)
3. **Encryption Salt**: Must be changed from default value
4. **RPC URLs**: Should be configured with environment variables

**📖 See [SECURITY.md](SECURITY.md) for complete security guide including:**
- Environment variable configuration
- Key rotation procedures
- Permission validation
- Incident response procedures

## ⚙️ Configuration

### Critical Environment Variables (Production)

* `WALLET_PRIVATE_KEY` - 🔴 **REQUIRED** Ethereum wallet private key
* `CONTRACT_ADDRESS` - 🔴 **REQUIRED** Smart contract address
* `RPC_URL` - 🔴 **REQUIRED** Blockchain RPC endpoint
* `WALLET_ADDRESS` - 🔴 **REQUIRED** Wallet address
* `WALLET_ENCRYPTION_SALT` - 🟡 **RECOMMENDED** Salt for wallet encryption
* `ETHEREUM_MAINNET_RPC_URL` - 🟡 **RECOMMENDED** Mainnet RPC with API key
* `ETHEREUM_SEPOLIA_RPC_URL` - 🟡 **RECOMMENDED** Sepolia RPC with API key

### Optional Environment Variables

* `SPRING_PROFILES_ACTIVE` - Active profile (default, docker, prod)
* `JAVA_OPTS` - JVM options
* `ALLOWED_ORIGINS` - Allowed CORS origins
* `PRIVATE_KEY_PATH` - Path to JWT private key
* `PUBLIC_KEY_PATH` - Path to JWT public key

### 🆕 Wallet Configuration

```properties
# Ethereum Network RPC URLs (use environment variables in production)
ethereum.mainnet.rpc.url=${ETHEREUM_MAINNET_RPC_URL:https://mainnet.infura.io/v3/YOUR_PROJECT_ID}
ethereum.sepolia.rpc.url=${ETHEREUM_SEPOLIA_RPC_URL:https://sepolia.infura.io/v3/YOUR_PROJECT_ID}
ethereum.goerli.rpc.url=${ETHEREUM_GOERLI_RPC_URL:https://goerli.infura.io/v3/YOUR_PROJECT_ID}

# Wallet Security Settings
wallet.encryption.salt=DecentraLabs2025
wallet.default.network=sepolia
wallet.max.transactions.per.hour=100
wallet.max.balance.checks.per.minute=60

# Gas Settings
ethereum.gas.price.default=20
ethereum.gas.limit.default=21000
ethereum.gas.limit.contract=100000
```

### Configuration Files

* `config/application.properties` - Main configuration
* `keys/private_key.pem` - JWT private key
* `keys/public_key.pem` - JWT public key

## 🔐 Security

* Non-root user execution
* JWT validation with rotatable keys
* CORS configured
* Integrated health checks

## 📊 Monitoring

Health endpoint available at `/health`:

```json
{
  "status": "UP",
  "timestamp": "2025-10-30T12:00:00Z",
  "service": "blockchain-services",
  "version": "1.0.0",
  "marketplace_key_cached": true,
  "marketplace_key_url": "https://marketplace-decentralabs.vercel.app/.well-known/public-key.pem",
  "jwt_validation": "ready",
  "endpoints": {
    "wallet-auth": "available",
    "wallet-auth2": "available", 
    "saml-auth": "available",
    "saml-auth2": "available",
    "jwks": "available",
    "message": "available",
    "wallet-create": "available (localhost only)",
    "wallet-import": "available (localhost only)",
    "wallet-balance": "available (localhost only)",
    "wallet-transactions": "available (localhost only)",
    "wallet-listen-events": "available (localhost only)",
    "wallet-networks": "available (localhost only)",
    "wallet-switch-network": "available (localhost only)",
    "health": "available"
  }
}
```

## 🔐 Authentication Flow Example

### 1. Wallet Challenge
```
GET /auth/message

Response:
{
  "message": "Login request: 1695478400",
  "timestamp": "1695478400"
}
```

### 2. Signature Verification
```
POST /auth/wallet-auth2
{
  "wallet": "0x742d35Cc6E7C0532f3E8bc8F3aF1c567aE7aF2",
  "signature": "0x1234567890abcdef...",
  "reservationKey": "0xabc123..."
}

Response:
{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "labURL": "https://yourdomain.com/guacamole/?jwt=..."
}
```

> The endpoint can also receive `labId` (as a string) instead of `reservationKey`.

## 🆕 Wallet Operations Examples

### 1. Create New Wallet *(localhost only)*
```bash
curl -X POST http://localhost:8080/wallet/create \
  -H "Content-Type: application/json" \
  -d '{"password": "mySecurePassword"}'
```

### 2. Import Wallet *(localhost only)*
```bash
curl -X POST http://localhost:8080/wallet/import \
  -H "Content-Type: application/json" \
  -d '{
    "privateKey": "0x...",
    "password": "mySecurePassword"
  }'
```

### 3. Check Balance *(localhost only)*
```bash
curl http://localhost:8080/wallet/0x742d35Cc6634C0532925a3b844Bc454e4438f44e/balance
```

### 4. Switch Network *(localhost only)*
```bash
curl -X POST http://localhost:8080/wallet/switch-network \
  -H "Content-Type: application/json" \
  -d '{"networkId": "mainnet"}'
```

### 3. Lab Access
The JWT token contains lab access permissions based on blockchain reservations:

```json
{
  "iss": "https://yourdomain.com/auth",
  "iat": 1695478400,
  "jti": "b3d7f4a8-6c9e-4b21-9a5d-387bf7e6f7a2",
  "aud": "https://yourdomain.com/guacamole",
  "sub": "your-lab-credential",
  "nbf": 1695480000,
  "exp": 1695482000,
  "labId": 42
}
```

#### JWT Claims Reference
**Always present:**
- `iss` (Issuer): URL of the service issuing the token
- `iat` (Issued At): Token creation timestamp
- `jti` (JWT ID): Unique token identifier

**Added for auth2, when there is an on-chain reservation (`wallet-auth2` / `saml-auth2`):**
- `aud` (Audience): URL where the token will be used (lab access)
- `sub` (Subject): Credential/subject used for access
- `nbf` (Not Before): Start of validity (reservation start)
- `exp` (Expiration): End of validity (reservation end)
- `labId`: Numeric identifier of the laboratory

**Claims specific to simple authentication (`wallet-auth` / `saml-auth`):**
- `wallet`: Authenticated wallet address
- `userid`: SAML user identifier
- `affiliation`: SAML user affiliation

## 🚀 Deployment

See [Docker Deployment Guide](dev/DOCKER_DEPLOYMENT_GUIDE.md) for complete Docker Compose deployment instructions.

When running the container, mount configuration and key material under `/app/config` so the service can read them:

```bash
docker run \
  -v /path/to/application.properties:/app/config/application.properties:ro \
  -v /path/to/keys:/app/config/keys:ro \
  -p 8080:8080 \
  decentralabs/blockchain-services:latest
```

## 🤝 Contributing

1. Fork the project
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open Pull Request

