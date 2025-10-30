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

### Authentication Endpoints
* `POST /auth/message` - Wallet challenge
* `POST /auth/auth` - Authentication only
* `POST /auth/auth2` - Authentication + authorization
* `GET /auth/jwks` - JSON Web Keys
* `POST /auth/marketplace-auth` - Marketplace auth
* `POST /auth/marketplace-auth2` - Marketplace auth2
* `GET /auth/health` - Health check

### 🆕 Wallet Endpoints
* `POST /auth/wallet/create` - Create new Ethereum wallet
* `POST /auth/wallet/import` - Import wallet from private key/mnemonic
* `GET /auth/wallet/{address}/balance` - Get ETH balance
* `POST /auth/wallet/sign-message` - Sign message with wallet
* `POST /auth/wallet/sign-transaction` - Sign Ethereum transaction
* `POST /auth/wallet/send-transaction` - Broadcast signed transaction
* `GET /auth/wallet/{address}/transactions` - Get transaction history
* `POST /auth/wallet/listen-events` - Setup contract event listener
* `GET /auth/wallet/networks` - List available networks
* `POST /auth/wallet/switch-network` - Switch active network

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
java -jar target/auth-service.war
```

## 🐳 Docker

### Multi-Stage Build

```bash
docker build -t auth-service:latest .
```

### Run

```bash
docker run -p 8080:8080 \
  -v $(pwd)/config:/app/config:ro \
  -v $(pwd)/keys:/app/keys:ro \
  auth-service:latest
```

## ⚙️ Configuration

### Environment Variables

* `SPRING_PROFILES_ACTIVE` - Active profile (default, docker, prod)
* `JAVA_OPTS` - JVM options
* `CONTRACT_ADDRESS` - Contract address
* `RPC_URL` - Blockchain node URL
* `WALLET_ADDRESS` - Wallet address
* `ALLOWED_ORIGINS` - Allowed CORS origins

### 🆕 Wallet Configuration

```properties
# Ethereum Network RPC URLs
ethereum.mainnet.rpc.url=https://mainnet.infura.io/v3/YOUR_PROJECT_ID
ethereum.sepolia.rpc.url=https://sepolia.infura.io/v3/YOUR_PROJECT_ID
ethereum.goerli.rpc.url=https://goerli.infura.io/v3/YOUR_PROJECT_ID

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

Health endpoint available at `/auth/health`:

```json
{
  "status": "UP",
  "components": {
    "marketplace-key": {
      "status": "UP",
      "details": {
        "keyAvailable": true,
        "lastUpdated": "2025-09-28T10:00:00Z"
      }
    }
  }
}
```

## 🔐 Authentication Flow Example

### 1. Wallet Challenge
```
POST /auth/message
{
  "wallet_address": "0x742d35Cc6E7C0532f3E8bc8F3aF1c567aE7aF2"
}

Response:
{
  "message": "0x742d35Cc6E7C0532f3E8bc8F3aF1c567aE7aF2:1695478400",
  "timestamp": 1695478400
}
```

### 2. Signature Verification
```
POST /auth/auth2
{
  "wallet_address": "0x742d35Cc6E7C0532f3E8bc8F3aF1c567aE7aF2",
  "signature": "0x1234567890abcdef...",
  "message": "0x742d35Cc6E7C0532f3E8bc8F3aF1c567aE7aF2:1695478400"
}

Response:
{
  "jwt": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "redirect_url": "https://yourdomain.com/guacamole/?jwt=..."
}
```

## 🆕 Wallet Operations Examples

### 1. Create New Wallet
```bash
curl -X POST http://localhost:8080/auth/wallet/create \
  -H "Content-Type: application/json" \
  -d '{"password": "mySecurePassword"}'
```

### 2. Check Balance
```bash
curl http://localhost:8080/auth/wallet/0x742d35Cc6634C0532925a3b844Bc454e4438f44e/balance
```

### 3. Sign Transaction
```bash
curl -X POST http://localhost:8080/auth/wallet/sign-transaction \
  -H "Content-Type: application/json" \
  -d '{
    "encryptedPrivateKey": "base64_encoded_key",
    "password": "mySecurePassword",
    "to": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
    "value": "0.01"
  }'
```

### 4. Switch Network
```bash
curl -X POST http://localhost:8080/auth/wallet/switch-network \
  -H "Content-Type: application/json" \
  -d '{"networkId": "mainnet"}'
```

### 3. Lab Access
The JWT token contains lab access permissions based on blockchain reservations:

```json
{
  "iss": "https://yourdomain.com/auth",
  "aud": "https://yourdomain.com/guacamole",
  "sub": "0x742d35Cc6E7C0532f3E8bc8F3aF1c567aE7aF2",
  "labs": [
    {
      "provider": "university-chemistry",
      "lab_id": "reactor-control-01",
      "reservation_id": "res_894736",
      "valid_until": 1695482000
    }
  ],
  "exp": 1695482000,
  "iat": 1695478400
}
```

## 🚀 Deployment

See [Docker Deployment Guide](dev/DOCKER_DEPLOYMENT_GUIDE.md) for complete Docker Compose deployment instructions.

## 📝 Documentation

### Core Documentation
* [WAR Deployment Guide](dev/DEPLOYMENT_GUIDE_WAR.md)
* [Docker Deployment Guide](dev/DOCKER_DEPLOYMENT_GUIDE.md)
* [Health Endpoint](dev/HEALTH_ENDPOINT.md)
* [JWT Implementation](dev/JWT_IMPLEMENTATION.md)

### 🆕 Wallet Documentation
* [Wallet APIs Guide](WALLET_README.md) - Complete wallet functionality documentation
* [Test Script](test-wallet-apis.sh) - Bash script to test all wallet endpoints
* [Integration Tests](src/test/java/decentralabs/auth/controller/WalletControllerIntegrationTest.java) - JUnit tests

## 🤝 Contributing

1. Fork the project
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open Pull Request