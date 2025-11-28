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

# Ensure keys exist (generate if missing or too old)
KEY_DIR="./config/keys"
mkdir -p "$KEY_DIR"
KEY_FILE="$KEY_DIR/private_key.pem"
PUB_FILE="$KEY_DIR/public_key.pem"
MAX_KEY_AGE_SECONDS="${JWT_KEY_MAX_AGE_SECONDS:-31536000}" # 12 months por defecto

regen_keys=false
if [ ! -f "$KEY_FILE" ]; then
    regen_keys=true
    echo "Private key not found. Generating RSA key pair..."
else
    # Check age of existing key
    now_ts=$(date +%s)
    # GNU stat (-c) fallback to BSD stat (-f)
    mod_ts=$(stat -c %Y "$KEY_FILE" 2>/dev/null || stat -f %m "$KEY_FILE" 2>/dev/null || echo "$now_ts")
    age=$((now_ts - mod_ts))
    if [ "$age" -gt "$MAX_KEY_AGE_SECONDS" ]; then
        echo "Private key older than $MAX_KEY_AGE_SECONDS seconds. Rotating..."
        regen_keys=true
    else
        echo "Private key found in $KEY_DIR (age ${age}s, below rotation threshold)"
    fi
fi

if [ "$regen_keys" = true ]; then
    openssl genrsa -out "$KEY_FILE" 2048
    openssl rsa -in "$KEY_FILE" -pubout -out "$PUB_FILE"
    chmod 600 "$KEY_FILE"
    chmod 644 "$PUB_FILE"
    echo "Generated RSA key pair in $KEY_DIR"
fi

# Start application
echo "Starting Blockchain Services application..."
exec java $JAVA_OPTS -jar blockchain-services.war \
    --spring.config.location=${CONFIG_LOCATION} \
    --spring.profiles.active=${SPRING_PROFILES_ACTIVE:-default}
