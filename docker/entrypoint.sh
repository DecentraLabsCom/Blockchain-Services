#!/bin/bash
# docker/entrypoint.sh - Default entrypoint (can be overridden)

set -e

echo "Starting Blockchain Services..."
echo "Environment: ${SPRING_PROFILES_ACTIVE:-default}"
echo "Java Options: ${JAVA_OPTS:-default}"

# Wait for dependencies
echo "Waiting for dependencies..."
if [ -n "$MYSQL_HOST" ]; then
    echo "Waiting for MySQL at $MYSQL_HOST:${MYSQL_PORT:-3306}..."
    while ! nc -z $MYSQL_HOST ${MYSQL_PORT:-3306}; do
        sleep 1
    done
    echo "MySQL is ready!"
fi

# Check configuration (if mounted)
if [ -f "./config/application.properties" ]; then
    CONFIG_LOCATION="file:./config/application.properties"
    echo "Using mounted configuration"
else
    CONFIG_LOCATION="classpath:application.properties"
    echo "Using default configuration"
fi

# Ensure keys exist (generate if missing)
KEY_DIR="./config/keys"
mkdir -p "$KEY_DIR"
if [ ! -f "$KEY_DIR/private_key.pem" ]; then
    echo "Private key not found. Generating RSA key pair..."
    openssl genrsa -out "$KEY_DIR/private_key.pem" 2048
    openssl rsa -in "$KEY_DIR/private_key.pem" -pubout -out "$KEY_DIR/public_key.pem"
    cp "$KEY_DIR/public_key.pem" "$KEY_DIR/certificate.pem"
    echo "Generated RSA key pair in $KEY_DIR"
else
    echo "Private key found in $KEY_DIR"
fi

# Start application
echo "Starting Blockchain Services application..."
exec java $JAVA_OPTS -jar blockchain-services.war \
    --spring.config.location=${CONFIG_LOCATION} \
    --spring.profiles.active=${SPRING_PROFILES_ACTIVE:-default}
