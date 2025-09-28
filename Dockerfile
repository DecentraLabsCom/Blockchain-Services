# Build Stage - Compila el código fuente
FROM maven:3.8.6-openjdk-11 AS builder

WORKDIR /build

# Copy POM first for better Docker layer caching
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source code and build
COPY src ./src
RUN mvn clean package -DskipTests -B

# Verify WAR was created
RUN test -f target/auth-service.war

#########################################
# Runtime Stage - Imagen final optimizada
#########################################
FROM openjdk:11-jre-slim

# Metadata
LABEL maintainer="DecentraLabs <tech@decentralabs.com>"
LABEL version="1.0.0"
LABEL description="Auth Service - JWT Authentication for Marketplace"

# Install required packages
RUN apt-get update && apt-get install -y \
    curl \
    netcat \
    && rm -rf /var/lib/apt/lists/*

# Create app user for security
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Application directory
WORKDIR /app

# Copy WAR from builder stage
COPY --from=builder /build/target/auth-service.war ./auth-service.war

# Copy configuration and scripts (will be mounted as volumes)
# COPY config/application.properties ./config/
# COPY keys/ ./keys/
# COPY scripts/entrypoint.sh ./entrypoint.sh
# COPY scripts/health-check.sh ./health-check.sh

# Create directories for mounted volumes
RUN mkdir -p ./config ./keys ./logs ./scripts

# Copy default scripts (can be overridden by volumes)
COPY docker/entrypoint.sh ./entrypoint.sh
COPY docker/health-check.sh ./health-check.sh

# Make scripts executable and set ownership
RUN chmod +x ./entrypoint.sh ./health-check.sh && \
    chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD ./health-check.sh

# Entry point
ENTRYPOINT ["./entrypoint.sh"]