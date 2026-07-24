#!/bin/bash
# docker/entrypoint.sh - Default entrypoint (can be overridden)

set -e

echo "Starting Blockchain Services..."
echo "Environment: ${SPRING_PROFILES_ACTIVE:-default}"
echo "Java Options: ${JAVA_OPTS:-default}"

# Java 21.0.10+ disables TLS_RSA_* in jdk.tls.disabledAlgorithms. The
# SIR2/RedIRIS metadata endpoint still requires TLS_RSA_WITH_AES_256_CBC_SHA256.
# Build a small appended security-properties file before starting Java so the
# override is applied before JSSE initializes. It is enabled only when the
# issuer-specific legacy-rsa SAML profile is configured.
if [[ "${SAML_IDP_METADATA_TLS_PROFILE:-}" == *legacy-rsa* ]]; then
    JAVA_HOME_RESOLVED="${JAVA_HOME:-}"
    if [ -z "$JAVA_HOME_RESOLVED" ]; then
        JAVA_BIN_RESOLVED="$(readlink -f "$(command -v java)")"
        JAVA_HOME_RESOLVED="$(dirname "$(dirname "$JAVA_BIN_RESOLVED")")"
    fi

    JAVA_SECURITY_FILE="$JAVA_HOME_RESOLVED/conf/security/java.security"
    LEGACY_RSA_SECURITY_FILE="/tmp/blockchain-services-legacy-rsa.security"
    if [ ! -r "$JAVA_SECURITY_FILE" ]; then
        echo "ERROR: Java security properties file not found: $JAVA_SECURITY_FILE" >&2
        exit 1
    fi

    awk '
        BEGIN {
            collecting = 0
            found = 0
            value = ""
        }
        {
            if (!collecting) {
                if ($0 !~ /^[[:space:]]*jdk[.]tls[.]disabledAlgorithms[[:space:]]*=/) {
                    next
                }
                collecting = 1
                found = 1
                line = $0
                sub(/^[^=]*=[[:space:]]*/, "", line)
            } else {
                line = $0
            }

            continued = (line ~ /\\[[:space:]]*$/)
            sub(/\\[[:space:]]*$/, "", line)
            value = value " " line

            if (!continued) {
                count = split(value, tokens, ",")
                cleaned = ""
                for (i = 1; i <= count; i++) {
                    token = tokens[i]
                    sub(/^[[:space:]]+/, "", token)
                    sub(/[[:space:]]+$/, "", token)
                    if (token == "" || token == "TLS_RSA_*" || token == "TLS_RSA_") {
                        continue
                    }
                    if (cleaned != "") {
                        cleaned = cleaned ", "
                    }
                    cleaned = cleaned token
                }
                print "jdk.tls.disabledAlgorithms=" cleaned
                exit
            }
        }
        END {
            if (!found) {
                exit 1
            }
        }
    ' "$JAVA_SECURITY_FILE" > "$LEGACY_RSA_SECURITY_FILE"

    if [ ! -s "$LEGACY_RSA_SECURITY_FILE" ]; then
        echo "ERROR: Could not create legacy RSA Java security override" >&2
        exit 1
    fi

    JAVA_OPTS="${JAVA_OPTS:-} -Djava.security.properties=$LEGACY_RSA_SECURITY_FILE"
    export JAVA_OPTS
    echo "Legacy RSA Java security override enabled from $LEGACY_RSA_SECURITY_FILE"
fi

# Wait for dependencies
echo "Waiting for dependencies..."

# Extract MySQL host from SPRING_DATASOURCE_URL if MYSQL_HOST not set
if [ -z "$MYSQL_HOST" ] && [ -n "$SPRING_DATASOURCE_URL" ]; then
    # Parse jdbc:mysql://host:port/db from URL
    MYSQL_HOST=$(echo "$SPRING_DATASOURCE_URL" | sed -n 's|.*://\([^:/]*\).*|\1|p')
    MYSQL_PORT=$(echo "$SPRING_DATASOURCE_URL" | sed -n 's|.*://[^:]*:\([0-9]*\)/.*|\1|p')
    MYSQL_PORT=${MYSQL_PORT:-3306}
fi

MYSQL_HOST=${MYSQL_HOST:-mysql}
MYSQL_PORT=${MYSQL_PORT:-3306}
MYSQL_WAIT_TIMEOUT=${MYSQL_WAIT_TIMEOUT:-120}

echo "Waiting for MySQL at $MYSQL_HOST:$MYSQL_PORT (timeout: ${MYSQL_WAIT_TIMEOUT}s)..."
waited=0
while ! nc -z "$MYSQL_HOST" "$MYSQL_PORT" 2>/dev/null; do
    if [ "$waited" -ge "$MYSQL_WAIT_TIMEOUT" ]; then
        echo "WARNING: MySQL port not available after ${MYSQL_WAIT_TIMEOUT}s, proceeding anyway..."
        break
    fi
    sleep 2
    waited=$((waited + 2))
done

if nc -z "$MYSQL_HOST" "$MYSQL_PORT" 2>/dev/null; then
    echo "MySQL port is open. Waiting for database to be ready..."
    # Additional wait for MySQL to complete initialization
    sleep 5
fi

echo "MySQL is ready!"

# Check configuration (if mounted)
if [ -f "./config/application.properties" ]; then
    CONFIG_LOCATION="file:./config/application.properties"
    echo "Using mounted configuration"
else
    CONFIG_LOCATION="classpath:application.properties"
    echo "Using default configuration"
fi

# Ensure keys exist (generate if missing or too old)
# Prefer explicit key paths from env so JWT keys can live outside read-only cert mounts.
KEY_FILE="${PRIVATE_KEY_PATH:-/app/data/keys/private_key.pem}"
PUB_FILE="${PUBLIC_KEY_PATH:-/app/data/keys/public_key.pem}"
KEY_DIR="$(dirname "$KEY_FILE")"
PUB_DIR="$(dirname "$PUB_FILE")"
mkdir -p "$KEY_DIR" "$PUB_DIR"
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
    chmod 600 "$PUB_FILE"
    echo "Generated RSA key pair in $KEY_DIR"
fi

# Start application
echo "Starting Blockchain Services application..."
exec java $JAVA_OPTS -jar blockchain-services.war \
    --spring.config.location=${CONFIG_LOCATION} \
    --spring.profiles.active=${SPRING_PROFILES_ACTIVE:-default}
