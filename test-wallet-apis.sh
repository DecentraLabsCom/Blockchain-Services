#!/bin/bash

# Example script to test the new wallet APIs
# Usage: ./test-wallet-apis.sh

BASE_URL="http://localhost:8080/auth"
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