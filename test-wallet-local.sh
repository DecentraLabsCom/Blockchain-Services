#!/bin/bash

# OPTIONAL: Manual API testing script (via docker exec)
# This script is provided for developers who want to test wallet APIs via CLI.
# 
# Most users should use the web UI instead:
#   http://localhost:8080/wallet-dashboard
#
# Test Wallet Endpoints Locally (via docker exec)
# This script demonstrates how to test wallet endpoints from your local machine
# by executing curl commands inside the Docker container.

CONTAINER_NAME="blockchain-services"

echo "🔍 Checking if container is running..."
if ! docker ps | grep -q "$CONTAINER_NAME"; then
    echo "❌ Container '$CONTAINER_NAME' is not running!"
    echo "   Run: docker-compose up -d"
    exit 1
fi

echo "✅ Container is running"
echo ""

# Test 1: Create a wallet
echo "📝 Test 1: Creating a new wallet..."
WALLET_RESPONSE=$(docker exec $CONTAINER_NAME sh -c 'curl -s -X POST http://localhost:8080/wallet/create \
  -H "Content-Type: application/json" \
  -d "{\"password\":\"TestPassword123\"}"')

echo "$WALLET_RESPONSE" | jq '.' 2>/dev/null || echo "$WALLET_RESPONSE"
echo ""

# Extract address if successful
WALLET_ADDRESS=$(echo "$WALLET_RESPONSE" | jq -r '.address // empty' 2>/dev/null)

if [ -n "$WALLET_ADDRESS" ]; then
    echo "✅ Wallet created successfully!"
    echo "   Address: $WALLET_ADDRESS"
    echo ""
    
    # Test 2: Check balance
    echo "📊 Test 2: Checking wallet balance..."
    BALANCE_RESPONSE=$(docker exec $CONTAINER_NAME curl -s "http://localhost:8080/wallet/$WALLET_ADDRESS/balance")
    echo "$BALANCE_RESPONSE" | jq '.' 2>/dev/null || echo "$BALANCE_RESPONSE"
    echo ""
    
    # Test 3: Get transaction history
    echo "📜 Test 3: Getting transaction history..."
    TX_RESPONSE=$(docker exec $CONTAINER_NAME curl -s "http://localhost:8080/wallet/$WALLET_ADDRESS/transactions")
    echo "$TX_RESPONSE" | jq '.' 2>/dev/null || echo "$TX_RESPONSE"
    echo ""
else
    echo "❌ Failed to create wallet"
    exit 1
fi

# Test 4: List available networks
echo "🌐 Test 4: Listing available networks..."
NETWORKS_RESPONSE=$(docker exec $CONTAINER_NAME curl -s "http://localhost:8080/wallet/networks")
echo "$NETWORKS_RESPONSE" | jq '.' 2>/dev/null || echo "$NETWORKS_RESPONSE"
echo ""

# Test 5: Get event listener status
echo "👂 Test 5: Checking event listener status..."
EVENTS_RESPONSE=$(docker exec $CONTAINER_NAME curl -s "http://localhost:8080/wallet/listen-events")
echo "$EVENTS_RESPONSE" | jq '.' 2>/dev/null || echo "$EVENTS_RESPONSE"
echo ""

echo "✅ All tests completed!"
echo ""
echo "💡 Note: These commands use 'docker exec' to run inside the container"
echo "   because LocalhostOnlyFilter blocks external requests."
echo ""
echo "📖 For more examples, see: dev/WALLET_README.md"
