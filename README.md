# Auth Service - JWT Authentication

JWT authentication microservice for DecentraLabs Marketplace.

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

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.