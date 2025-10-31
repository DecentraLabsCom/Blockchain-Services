#!/bin/bash

# Example script to test the new wallet APIs
# Usage: ./test-wallet-apis.sh
#
# SECURITY NOTE: ALL wallet endpoints are restricted to localhost only:
# - POST /wallet/create
# - POST /wallet/import
# - GET /wallet/networks
# - GET /wallet/{address}/balance
# - GET /wallet/{address}/transactions
# - POST /wallet/sign-message
# - POST /wallet/sign-transaction
# - POST /wallet/send-transaction
# - POST /wallet/listen-events
# - POST /wallet/switch-network
#
# This script runs from localhost, so all endpoints should work.

BASE_URL="http://localhost:8080"
WALLET_PASSWORD="testPassword123"

echo "🚀 Testing Wallet Blockchain APIs"
echo "====================================="

# 1. Create wallet
echo -e "\n1. Creating new wallet..."
CREATE_RESPONSE=$(curl -s -X POST "$BASE_URL/wallet/create" \
  -H "Content-Type: application/json" \
  -d "{\"password\": \"$WALLET_PASSWORD\"}")

echo "Response: $CREATE_RESPONSE"

# Extract data from response
WALLET_ADDRESS=$(echo $CREATE_RESPONSE | jq -r '.address')
ENCRYPTED_KEY=$(echo $CREATE_RESPONSE | jq -r '.encryptedPrivateKey')

if [ "$WALLET_ADDRESS" = "null" ] || [ -z "$WALLET_ADDRESS" ]; then
    echo "❌ Error: Could not create wallet"
    exit 1
fi

echo "✅ Wallet created: $WALLET_ADDRESS"

# 1b. Create wallet with private key returned (for automatic setup)
# NOTE: This endpoint is only accessible from localhost for security reasons
echo -e "\n1b. Creating wallet with private key returned..."
AUTO_CREATE_RESPONSE=$(curl -s -X POST "$BASE_URL/wallet/create" \
  -H "Content-Type: application/json" \
  -d "{\"returnPrivateKey\": true}")

echo "Response: $AUTO_CREATE_RESPONSE"

AUTO_WALLET_ADDRESS=$(echo $AUTO_CREATE_RESPONSE | jq -r '.address')
AUTO_PRIVATE_KEY=$(echo $AUTO_CREATE_RESPONSE | jq -r '.privateKey')

if [ "$AUTO_WALLET_ADDRESS" = "null" ] || [ -z "$AUTO_WALLET_ADDRESS" ]; then
    echo "❌ Error: Could not create auto wallet"
else
    echo "✅ Auto wallet created: $AUTO_WALLET_ADDRESS"
    echo "🔑 Private key: $AUTO_PRIVATE_KEY"
fi

# 1c. Import wallet (for automatic setup)
# NOTE: This endpoint is also only accessible from localhost for security reasons
echo -e "\n1c. Importing wallet from private key..."
IMPORT_RESPONSE=$(curl -s -X POST "$BASE_URL/wallet/import" \
  -H "Content-Type: application/json" \
  -d "{\"privateKey\": \"$AUTO_PRIVATE_KEY\", \"password\": \"importPassword\"}")

echo "Response: $IMPORT_RESPONSE"

# 2. Get balance
echo -e "\n2. Checking balance..."
BALANCE_RESPONSE=$(curl -s "$BASE_URL/wallet/$WALLET_ADDRESS/balance")
echo "Response: $BALANCE_RESPONSE"

# 3. Sign message
echo -e "\n3. Signing message..."
SIGN_RESPONSE=$(curl -s -X POST "$BASE_URL/wallet/sign-message" \
  -H "Content-Type: application/json" \
  -d "{
    \"encryptedPrivateKey\": \"$ENCRYPTED_KEY\",
    \"password\": \"$WALLET_PASSWORD\",
    \"message\": \"Hello from DecentraLabs!\"
  }")

echo "Response: $SIGN_RESPONSE"

# 4. List networks
echo -e "\n4. Listing available networks..."
NETWORKS_RESPONSE=$(curl -s "$BASE_URL/wallet/networks")
echo "Response: $NETWORKS_RESPONSE"

# 5. Switch to mainnet
echo -e "\n5. Switching to mainnet..."
SWITCH_RESPONSE=$(curl -s -X POST "$BASE_URL/wallet/switch-network" \
  -H "Content-Type: application/json" \
  -d "{\"networkId\": \"mainnet\"}")

echo "Response: $SWITCH_RESPONSE"

echo -e "\n🎉 All tests completed!"
echo "Note: For real transactions you would need ETH in the wallet and configure valid RPC URLs"