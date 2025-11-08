# Build Stage - Compiles the source code
FROM maven:3.9-eclipse-temurin-21 AS builder

WORKDIR /build

# Copy POM first for better Docker layer caching
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source code and build
COPY src ./src
RUN mvn clean package -DskipTests -B

# Verify WAR was created
RUN test -f target/blockchain-services-1.0-SNAPSHOT.war

#########################################
# Runtime Stage - Imagen final optimizada
#########################################
FROM eclipse-temurin:21-jre

# Metadata
LABEL maintainer="DecentraLabs <tech@decentralabs.com>"
LABEL version="1.0.0"
LABEL description="Blockchain Services - Auth + Wallet/Treasury APIs"

# Install required packages
RUN apt-get update && apt-get install -y \
    curl \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Create app user for security
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Application directory
WORKDIR /app

# Copy WAR from builder stage (renamed for clarity)
COPY --from=builder /build/target/blockchain-services-1.0-SNAPSHOT.war ./blockchain-services.war

# Copy configuration and scripts (will be mounted as volumes)
# COPY config/application.properties ./config/
# COPY keys/ ./config/keys/
# COPY scripts/entrypoint.sh ./entrypoint.sh
# COPY scripts/health-check.sh ./health-check.sh

# Create directories for mounted volumes
RUN mkdir -p ./config/keys ./logs ./scripts ./data

# Copy default scripts (can be overridden by volumes)
COPY docker/entrypoint.sh ./entrypoint.sh
COPY docker/health-check.sh ./health-check.sh

# Make scripts executable and set ownership
RUN chmod +x ./entrypoint.sh ./health-check.sh && \
    chown -R appuser:appuser /app

# Set secure permissions for data directory (wallet storage)
RUN chmod 700 ./data

# Switch to non-root user
USER appuser

# Environment variables documentation (these MUST be provided at runtime)
# CRITICAL SECURITY VARIABLES (required for production):
ENV CONTRACT_ADDRESS="" \
    RPC_URL=""

# INSTITUTIONAL WALLET CONFIGURATION:
# The institutional wallet is used for ALL automated transactions.
# 
# SETUP (one-time):
# 1. Start container: docker-compose up -d
# 2. Create wallet: curl -X POST http://localhost:8080/wallet/create -d '{"password":"YourPassword"}'
# 3. Configure environment variables with the returned address and your password
# 4. Restart container: docker-compose restart
#
# SECURITY:
# - Wallet private key is AES-256-GCM encrypted in /app/data/wallets.json (never in plain text)
# - Only the password is in environment variables (rotatable)
# - Use AWS Secrets Manager / Azure Key Vault for production
# - Never commit the password to version control
ENV INSTITUTIONAL_WALLET_ADDRESS="" \
    INSTITUTIONAL_WALLET_PASSWORD=""

# OPTIONAL SECURITY VARIABLES (recommended to override defaults):
# - WALLET_ENCRYPTION_SALT: Salt for wallet encryption (change from default)
# - WALLET_PERSISTENCE_ENABLED: Enable wallet persistence (true/false)
# - WALLET_FILE_PATH: Path to wallet storage file (default: /app/data/wallets.json)
# - ETHEREUM_MAINNET_RPC_URL: Mainnet RPC endpoint with your API key
# - ETHEREUM_SEPOLIA_RPC_URL: Sepolia testnet RPC endpoint with your API key
# - PRIVATE_KEY_PATH: Path to JWT private key (default: /app/config/keys/private_key.pem)
# - PUBLIC_KEY_PATH: Path to JWT public key (default: /app/config/keys/public_key.pem)

# Example Docker run command:
# docker run -d \
#   -e INSTITUTIONAL_WALLET_ADDRESS=0xYourWalletAddress \
#   -e INSTITUTIONAL_WALLET_PASSWORD=YourSecurePassword \
#   -e CONTRACT_ADDRESS=0xYourContractAddress \
#   -e RPC_URL=https://your-rpc-url \
#   -e WALLET_ENCRYPTION_SALT=YourRandomSalt \
#   -e WALLET_PERSISTENCE_ENABLED=true \
#   -v /secure/path/keys:/app/config/keys:ro \
#   -v /secure/path/data:/app/data \
#   -p 8080:8080 \
#   blockchain-services:latest

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD ./health-check.sh

# Entry point
ENTRYPOINT ["./entrypoint.sh"]
