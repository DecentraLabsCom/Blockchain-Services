---
description: >-
  Authentication and authorization service connecting your lab access control
  system to the blockchain
---

# Auth Service - JWT Authentication

JWT authentication microservice for DecentraLabs Marketplace.

<figure><img src=".gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

This microservice provides web3-based JWT tokens and offers a bridge between institutional access control systems (like the **Lab Gateway** in the figure above) with the blockchain-based smart contracts.

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

- **JWT Authentication**: JWT token validation
- **Dynamic Key Retrieval**: Automatic public key downloading
- **Blockchain Integration**: Smart contract integration
- **Health Monitoring**: Health endpoint for monitoring
- **Docker Ready**: Multi-stage build containerization

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Marketplace   │───▶│   Auth Service  │───▶│   Blockchain    │
│   Frontend      │    │   (JWT + Keys)  │    │   (Contracts)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🔧 Endpoints

- `POST /auth/auth` - Main authentication
- `POST /auth/auth2` - Alternative authentication  
- `GET /auth/jwks` - JSON Web Keys
- `POST /auth/marketplace-auth` - Marketplace authentication
- `POST /auth/guacamole` - Guacamole integration
- `GET /auth/health` - Health check

## 🛠️ Local Development

### Prerequisites
- Java 11+
- Maven 3.6+

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
- `SPRING_PROFILES_ACTIVE` - Active profile (default, docker, prod)
- `JAVA_OPTS` - JVM options
- `CONTRACT_ADDRESS` - Contract address
- `RPC_URL` - Blockchain node URL
- `WALLET_ADDRESS` - Wallet address
- `ALLOWED_ORIGINS` - Allowed CORS origins

### Configuration Files
- `config/application.properties` - Main configuration
- `keys/private_key.pem` - JWT private key
- `keys/public_key.pem` - JWT public key

## 🔐 Security

- Non-root user execution
- JWT validation with rotatable keys
- CORS configured
- Integrated health checks

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

## 🚀 Deployment

See [Docker Deployment Guide](dev/DOCKER_DEPLOYMENT_GUIDE.md) for complete Docker Compose deployment instructions.

## 📝 Documentation

- [WAR Deployment Guide](dev/DEPLOYMENT_GUIDE_WAR.md)
- [Docker Deployment Guide](dev/DOCKER_DEPLOYMENT_GUIDE.md)
- [Health Endpoint](dev/HEALTH_ENDPOINT.md)
- [JWT Implementation](dev/JWT_IMPLEMENTATION.md)

## 🤝 Contributing

1. Fork the project
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open Pull Request