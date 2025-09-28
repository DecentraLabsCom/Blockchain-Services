#!/bin/bash
# docker/entrypoint.sh - Default entrypoint (can be overridden)

set -e

echo "🚀 Starting Auth Service..."
echo "Environment: ${SPRING_PROFILES_ACTIVE:-default}"
echo "Java Options: ${JAVA_OPTS:-default}"

# Wait for dependencies
echo "⏳ Waiting for dependencies..."
if [ -n "$MYSQL_HOST" ]; then
    echo "Waiting for MySQL at $MYSQL_HOST:${MYSQL_PORT:-3306}..."
    while ! nc -z $MYSQL_HOST ${MYSQL_PORT:-3306}; do
        sleep 1
    done
    echo "✅ MySQL is ready!"
fi

# Check configuration (if mounted)
if [ -f "./config/application.properties" ]; then
    CONFIG_LOCATION="file:./config/application.properties"
    echo "✅ Using mounted configuration"
else
    CONFIG_LOCATION="classpath:application.properties"
    echo "⚠️  Using default configuration"
fi

# Check keys (if mounted)
if [ -f "./keys/private_key.pem" ]; then
    echo "✅ Private key found"
else
    echo "⚠️  Private key not found - some features may not work"
fi

# Start application
echo "🔄 Starting Auth Service application..."
exec java $JAVA_OPTS -jar auth-service.war \
    --spring.config.location=${CONFIG_LOCATION} \
    --spring.profiles.active=${SPRING_PROFILES_ACTIVE:-default}