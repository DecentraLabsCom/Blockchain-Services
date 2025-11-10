# Institutional Wallet & Treasury

The Institutional Wallet & Treasury component provides complete Ethereum wallet management and smart contract interaction capabilities for lab providers in the DecentraLabs ecosystem.

## Overview

This component enables institutional consumers and providers to:
- Create and manage encrypted Ethereum wallets
- Interact with the Diamond smart contract for treasury operations
- Manage spending limits and user financial stats

Additionaly, for lab providers, this also enables to:
- Handle lab reservations with automatic approval/denial
- Monitor blockchain events and transaction status

## Features

### Wallet Management
- **Wallet Creation**: Generate new HD wallets with secure password encryption
- **Wallet Import**: Import existing wallets using private keys
- **Multi-Network Support**: Mainnet, Sepolia, and Goerli testnets
- **Secure Storage**: AES-256-GCM encryption with PBKDF2 key derivation

### Treasury Operations
- **Deposits**: Add funds to institutional treasury
- **Withdrawals**: Remove funds from treasury
- **Spending Limits**: Set and manage per-user spending limits
- **Spending Periods**: Configure time-based spending windows
- **Financial Stats**: Query user spending history and limits

### Reservation Management
- **Auto-Approval Engine**: Metadata-driven reservation approval/denial
- **Time Validation**: Check availability against lab schedules
- **Maintenance Windows**: Respect configured maintenance periods
- **Triple Validation**: User limits, lab availability, and time constraints

### Blockchain Integration
- **Balance Queries**: ETH and LAB token balances
- **Transaction History**: Lightweight transaction tracking
- **Event Listening**: Real-time smart contract event monitoring
- **RPC Failover**: Automatic fallback across multiple RPC endpoints

## API Reference

### Wallet Endpoints 🔒

> ⚠️ All wallet endpoints are **localhost-only** for security. Requests must originate from `127.0.0.1` or `::1`.

#### Create Wallet

Create a new encrypted wallet.

```http
POST /wallet/create
Content-Type: application/json

{
  "password": "SecurePassword123!"
}
```

**Response:**
```json
{
  "address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
  "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  "message": "Wallet created successfully"
}
```

> ⚠️ **CRITICAL**: Save the mnemonic securely. It cannot be recovered if lost.

#### Import Wallet

Import an existing wallet using a private key.

```http
POST /wallet/import
Content-Type: application/json

{
  "privateKey": "0x4c0883a69102937d6231471b5dbb6204fe512961708279f8b1d4e3d3e1d4f8a4",
  "password": "SecurePassword123!"
}
```

**Response:**
```json
{
  "address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
  "message": "Wallet imported successfully"
}
```

#### Get Balance

Get ETH and LAB token balances for a wallet.

```http
GET /wallet/{address}/balance
```

Or use fallback to default wallet:
```http
GET /wallet//balance
```

**Response:**
```json
{
  "address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
  "ethBalance": "1.234567890123456789",
  "labBalance": "1000.500000",
  "network": "sepolia"
}
```

> 💡 LAB token uses 6 decimals, formatted accordingly in response.

#### Get Transactions

Get transaction history for a wallet.

```http
GET /wallet/{address}/transactions
```

Or use fallback to default wallet:
```http
GET /wallet//transactions
```

**Response:**
```json
{
  "address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
  "transactionCount": 42,
  "recentTransactions": [
    {
      "hash": "0xabc123...",
      "from": "0x742d35Cc...",
      "to": "0x123abc...",
      "value": "0.1",
      "timestamp": 1699545600
    }
  ]
}
```

#### Event Listener Status

Get status of blockchain event listener.

```http
GET /wallet/listen-events
```

**Response:**
```json
{
  "status": "running",
  "network": "sepolia",
  "contractAddress": "0xC332F296d698bb05Fbad7863131F36085F6ce66d",
  "baseDomain": "http://localhost:8080",
  "lastBlockProcessed": 1234567
}
```

#### List Networks

Get available blockchain networks.

```http
GET /wallet/networks
```

**Response:**
```json
{
  "networks": ["mainnet", "sepolia", "goerli"],
  "active": "sepolia"
}
```

#### Switch Network

Switch active blockchain network.

```http
POST /wallet/switch-network
Content-Type: application/json

{
  "networkId": "mainnet"
}
```

**Response:**
```json
{
  "message": "Network switched to mainnet",
  "network": "mainnet"
}
```

### Treasury Endpoints 🔒

> ⚠️ All treasury endpoints are **localhost-only** for security.

#### Create Reservation

Create a new lab reservation with automatic approval/denial.

```http
POST /treasury/reservations
Content-Type: application/json

{
  "providerAddress": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
  "userAddress": "0x123abc456def789...",
  "labId": 42,
  "startTime": 1699545600,
  "endTime": 1699549200,
  "estimatedCost": "50.000000"
}
```

**Validation Process:**
1. **User Financial Validation**: Checks spending limit and available allowance
2. **Lab Availability Validation**: Verifies lab is open during requested time
3. **Maintenance Window Check**: Ensures no scheduled maintenance

**Response (Auto-Approved):**
```json
{
  "status": "approved",
  "reservationKey": "0xabc123...",
  "transactionHash": "0xdef456...",
  "message": "Reservation approved and created on-chain"
}
```

**Response (Auto-Denied):**
```json
{
  "status": "denied",
  "reason": "Lab is closed on Sundays",
  "validationResults": {
    "userFinancial": true,
    "labAvailability": false,
    "noMaintenance": true
  }
}
```

#### Execute Treasury Admin Operation

Execute administrative treasury operations.

```http
POST /treasury/admin/execute
Content-Type: application/json

{
  "operation": "DEPOSIT_TREASURY",
  "providerAddress": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
  "amount": "1000.000000",
  "walletPassword": "SecurePassword123!"
}
```

**Supported Operations:**

| Operation | Description | Required Parameters |
|-----------|-------------|---------------------|
| `DEPOSIT_TREASURY` | Add LAB tokens to treasury | `amount`, `walletPassword` |
| `WITHDRAW_TREASURY` | Remove LAB tokens from treasury | `amount`, `walletPassword` |
| `SET_USER_LIMIT` | Set spending limit for user | `userAddress`, `limitAmount`, `walletPassword` |
| `SET_SPENDING_PERIOD` | Set spending period duration | `periodSeconds`, `walletPassword` |
| `RESET_SPENDING_PERIOD` | Reset current spending period | `walletPassword` |

**Response:**
```json
{
  "status": "success",
  "transactionHash": "0xabc123...",
  "operation": "DEPOSIT_TREASURY",
  "message": "Successfully deposited 1000 LAB to treasury"
}
```

## Architecture

### Wallet Storage

Wallets are stored encrypted using:
- **Algorithm**: AES-256-GCM
- **Key Derivation**: PBKDF2 with SHA-256
- **Iterations**: 65,536
- **Salt**: Per-wallet random salt + optional global pepper

```
Stored Wallet Structure:
{
  "address": "0x...",
  "encryptedPrivateKey": "base64-encoded-ciphertext",
  "salt": "base64-encoded-salt",
  "iv": "base64-encoded-iv"
}
```

### Multi-Network Support

The service maintains separate Web3j instances for each network:

```java
Map<String, Web3j> networkClients = {
  "mainnet": Web3j.build(...),
  "sepolia": Web3j.build(...),
  "goerli": Web3j.build(...)
}
```

RPC endpoints support comma-separated fallback URLs:
```properties
ethereum.sepolia.rpc.url=https://rpc1.sepolia.org,https://rpc2.sepolia.org,https://rpc3.sepolia.org
```

### Reservation Auto-Approval Engine

```
┌─────────────────────────────────┐
│  Reservation Request Received   │
└──────────────┬──────────────────┘
               │
               v
┌─────────────────────────────────┐
│  Validate User Financial Stats  │
│  - Check spending limit          │
│  - Verify remaining allowance    │
└──────────────┬──────────────────┘
               │
               v
┌─────────────────────────────────┐
│  Validate Lab Availability      │
│  - Check operating hours         │
│  - Verify day of week            │
└──────────────┬──────────────────┘
               │
               v
┌─────────────────────────────────┐
│  Check Maintenance Windows      │
│  - No scheduled maintenance      │
└──────────────┬──────────────────┘
               │
               v
       ┌───────┴────────┐
       │                │
       v                v
   ┌───────┐      ┌──────────┐
   │APPROVE│      │  DENY    │
   └───────┘      └──────────┘
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `WALLET_ADDRESS` | Default institutional wallet | - |
| `WALLET_ENCRYPTION_SALT` | Global encryption pepper | `DecentraLabsTestSalt` |
| `CONTRACT_ADDRESS` | Diamond contract address | - |
| `BLOCKCHAIN_NETWORK_ACTIVE` | Initial active network | `sepolia` |
| `ETHEREUM_MAINNET_RPC_URL` | Mainnet RPC endpoints | Public RPCs |
| `ETHEREUM_SEPOLIA_RPC_URL` | Sepolia RPC endpoints | Public RPCs |
| `ETHEREUM_GOERLI_RPC_URL` | Goerli RPC endpoints | Public RPCs |

### Application Properties

```properties
# Wallet Configuration
wallet.address=${WALLET_ADDRESS:}
wallet.encryption.salt=${WALLET_ENCRYPTION_SALT:DecentraLabsTestSalt}

# Network Configuration
blockchain.network.active=${BLOCKCHAIN_NETWORK_ACTIVE:sepolia}

# RPC Endpoints (comma-separated for failover)
ethereum.mainnet.rpc.url=${ETHEREUM_MAINNET_RPC_URL:https://eth.public-rpc.com,https://rpc.flashbots.net}
ethereum.sepolia.rpc.url=${ETHEREUM_SEPOLIA_RPC_URL:https://rpc.sepolia.org}
ethereum.goerli.rpc.url=${ETHEREUM_GOERLI_RPC_URL:https://rpc.goerli.mudit.blog}

# Contract Configuration
contract.address=${CONTRACT_ADDRESS:}
```

### Lab Metadata for Auto-Approval

Lab metadata should be stored in the smart contract or backend with the following structure:

```json
{
  "labId": 42,
  "name": "Physics Lab 1",
  "availability": {
    "daysOfWeek": [1, 2, 3, 4, 5],  // Monday-Friday
    "startHour": 8,
    "endHour": 18
  },
  "maintenanceWindows": [
    {
      "start": "2025-11-10T00:00:00Z",
      "end": "2025-11-10T23:59:59Z",
      "reason": "Equipment upgrade"
    }
  ],
  "autoConfirm": true
}
```

## Integration Examples

### Creating Provider Wallet

```bash
# From inside Docker container
curl -X POST http://localhost:8080/wallet/create \
  -H "Content-Type: application/json" \
  -d '{"password":"ProviderSecurePassword123!"}'
```

### Depositing to Treasury

```bash
curl -X POST http://localhost:8080/treasury/admin/execute \
  -H "Content-Type: application/json" \
  -d '{
    "operation": "DEPOSIT_TREASURY",
    "providerAddress": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
    "amount": "10000.000000",
    "walletPassword": "ProviderSecurePassword123!"
  }'
```

### Creating Reservation

```bash
curl -X POST http://localhost:8080/treasury/reservations \
  -H "Content-Type: application/json" \
  -d '{
    "providerAddress": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
    "userAddress": "0x123abc456def...",
    "labId": 42,
    "startTime": 1699545600,
    "endTime": 1699549200,
    "estimatedCost": "50.000000"
  }'
```

### Checking Balance

```bash
# Specific address
curl http://localhost:8080/wallet/0x742d35Cc6634C0532925a3b844Bc454e4438f44e/balance

# Default wallet
curl http://localhost:8080/wallet//balance
```

## Web Dashboard

Located at `/static/wallet-dashboard/` - Treasury admin interface with:
- Contract address and network information
- Provider wallet balance display
- Treasury admin operations:
  - Set user spending limits
  - Configure spending periods
  - Reset spending periods
  - Deposit/withdraw treasury funds (requires additional UI)

## Related Documentation

- [Authentication Service](AUTH_SERVICE.md)
