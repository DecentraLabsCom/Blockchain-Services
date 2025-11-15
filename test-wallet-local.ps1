# OPTIONAL: Manual API testing script (via docker exec)
# This script is provided for developers who want to test wallet APIs via CLI.
# 
# Most users should use the web UI instead:
#   http://localhost:8080/wallet-dashboard
#
# Test Wallet Endpoints Locally (via docker exec)
# This script demonstrates how to test wallet endpoints from your local machine
# by executing curl commands inside the Docker container.

$ContainerName = "blockchain-services"

Write-Host "🔍 Checking if container is running..." -ForegroundColor Cyan
$containerRunning = docker ps --format "{{.Names}}" | Select-String -Pattern "^$ContainerName$" -Quiet

if (-not $containerRunning) {
    Write-Host "❌ Container '$ContainerName' is not running!" -ForegroundColor Red
    Write-Host "   Run: docker-compose up -d" -ForegroundColor Yellow
    exit 1
}

Write-Host "✅ Container is running" -ForegroundColor Green
Write-Host ""

# Test 1: Create a wallet
Write-Host "📝 Test 1: Creating a new wallet..." -ForegroundColor Cyan
$walletResponse = docker exec $ContainerName sh -c 'curl -s -X POST http://localhost:8080/wallet/create -H "Content-Type: application/json" -d "{\"password\":\"TestPassword123\"}"'

try {
    $walletJson = $walletResponse | ConvertFrom-Json
    $walletJson | ConvertTo-Json -Depth 10
    Write-Host ""
    
    if ($walletJson.success -eq $true) {
        $walletAddress = $walletJson.address
        Write-Host "✅ Wallet created successfully!" -ForegroundColor Green
        Write-Host "   Address: $walletAddress" -ForegroundColor Yellow
        Write-Host ""
        
        # Test 2: Check balance
        Write-Host "📊 Test 2: Checking wallet balance..." -ForegroundColor Cyan
        $balanceResponse = docker exec $ContainerName curl -s "http://localhost:8080/wallet/$walletAddress/balance"
        try {
            $balanceJson = $balanceResponse | ConvertFrom-Json
            $balanceJson | ConvertTo-Json -Depth 10
        } catch {
            Write-Host $balanceResponse
        }
        Write-Host ""
        
        # Test 3: Get transaction history
        Write-Host "📜 Test 3: Getting transaction history..." -ForegroundColor Cyan
        $txResponse = docker exec $ContainerName curl -s "http://localhost:8080/wallet/$walletAddress/transactions"
        try {
            $txJson = $txResponse | ConvertFrom-Json
            $txJson | ConvertTo-Json -Depth 10
        } catch {
            Write-Host $txResponse
        }
        Write-Host ""
    } else {
        Write-Host "❌ Failed to create wallet" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host $walletResponse
    Write-Host "❌ Failed to parse wallet response" -ForegroundColor Red
    exit 1
}

# Test 4: List available networks
Write-Host "🌐 Test 4: Listing available networks..." -ForegroundColor Cyan
$networksResponse = docker exec $ContainerName curl -s "http://localhost:8080/wallet/networks"
try {
    $networksJson = $networksResponse | ConvertFrom-Json
    $networksJson | ConvertTo-Json -Depth 10
} catch {
    Write-Host $networksResponse
}
Write-Host ""

# Test 5: Get event listener status
Write-Host "👂 Test 5: Checking event listener status..." -ForegroundColor Cyan
$eventsResponse = docker exec $ContainerName curl -s "http://localhost:8080/wallet/listen-events"
try {
    $eventsJson = $eventsResponse | ConvertFrom-Json
    $eventsJson | ConvertTo-Json -Depth 10
} catch {
    Write-Host $eventsResponse
}
Write-Host ""

Write-Host "✅ All tests completed!" -ForegroundColor Green
Write-Host ""
Write-Host "💡 Note: These commands use 'docker exec' to run inside the container" -ForegroundColor Yellow
Write-Host "   because LocalhostOnlyFilter blocks external requests." -ForegroundColor Yellow
Write-Host ""
Write-Host "📖 For more examples, see: dev/WALLET_README.md" -ForegroundColor Cyan
