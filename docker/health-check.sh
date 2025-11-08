#!/bin/bash
# docker/health-check.sh - Default health check

# Internal health check for Docker
curl -f http://localhost:8080/health >/dev/null 2>&1

if [ $? -eq 0 ]; then
    exit 0
else
    echo "Health check failed"
    exit 1
fi
