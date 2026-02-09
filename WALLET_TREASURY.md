# Institutional Wallet & Treasury

Operational guide for the wallet and treasury endpoints that run on the same Spring Boot service. All wallet/treasury/dashboards are protected by `LocalhostOnlyFilter` (loopback only unless `security.allow-private-networks=true`).

## Wallet endpoints (`/wallet`)
- `POST /wallet/create` {"password": "..."}
  - Generates a new wallet, encrypts the private key with AES-256-GCM + PBKDF2, stores it in `./data/wallets.json`, writes `wallet-config.properties` (address + encrypted password) and reloads the institutional wallet.
- `POST /wallet/import` {"privateKey" or "mnemonic", "password"}
  - Same side effects as create; replaces the previously stored institutional wallet.
- `POST /wallet/reveal` {"password": "..."}
  - Returns the institutional private key if the password decrypts the stored wallet (localhost only).
- `GET /wallet/{address}/balance`
  - Returns ETH and LAB balances (LAB has 6 decimals) plus active network. The LAB token address is read from the Diamond contract.
- `GET /wallet/{address}/transactions`
  - Basic transaction count placeholder (no indexer integration yet).
- `GET /wallet/listen-events`
  - Reports configured contract address/network; event listeners are wired at startup.
- `GET /wallet/networks` and `POST /wallet/switch-network`
  - Networks exposed: `mainnet` and `sepolia` with automatic RPC failover (comma-separated URLs). Switching publishes a `NetworkSwitchEvent` to other components.

Example create request:
```http
POST /wallet/create
{
  "password": "StrongPassword123!"
}
```

## Treasury reservations (`/treasury/reservations`)
- Request fields (`InstitutionalReservationRequest`):
  - `marketplaceToken` (JWT signed by marketplace)
  - `samlAssertion` (Base64 SAML, must be signed)
  - `userId`, `institutionId`, `labId`, `startTime`, `endTime`
  - Optional: `userCount`, `budgetCode`, `metadata`, `timestamp`
- Validation: same 3 layers as `/auth/saml-auth*` (marketplace JWT -> SAML signature/issuer -> cross-check `userid`/`affiliation`).
- On success it signs `institutionalReservationRequest` on the Diamond contract with the institutional wallet and returns:
```json
{
  "success": true,
  "transactionHash": "0x...",
  "institutionId": "<affiliation>",
  "userId": "<userid>",
  "labId": "42",
  "startTime": "2025-11-20T10:00",
  "endTime": "2025-11-20T11:00"
}
```
Errors are returned with `success:false` and an `error` message.

## Treasury admin (`/treasury/admin/execute`)
- Requires loopback client **and** `adminWalletAddress` matching the configured institutional wallet.
- `operation` is one of:
  - `AUTHORIZE_BACKEND` (backendAddress)
  - `REVOKE_BACKEND`
  - `ADMIN_RESET_BACKEND` (providerAddress, optional backendAddress)
  - `SET_USER_LIMIT` (spendingLimit, uint256)
  - `SET_SPENDING_PERIOD` (spendingPeriod seconds)
  - `RESET_SPENDING_PERIOD`
  - `DEPOSIT_TREASURY` (amount, uint256)
  - `WITHDRAW_TREASURY` (amount, uint256)
- Each call is signed with the institutional wallet. Responses include `success`, `message`, `transactionHash`, and operation-specific fields.

Example admin request:
```http
POST /treasury/admin/execute
{
  "adminWalletAddress": "0xProvider...",
  "operation": "SET_USER_LIMIT",
  "spendingLimit": "10000000"
}
```

## Admin dashboards (read only, localhost)
- `GET /treasury/admin/status` -> wallet configured?, contract address, marketplace URL, networks.
- `GET /treasury/admin/balance` -> institutional balances (all networks or specific `chainId`).
- `GET /treasury/admin/treasury-info` -> spending limit/period and treasury balance (defaults shown if the wallet is not registered yet).
- `GET /treasury/admin/top-spenders` -> aggregated local stats for institutional users.
- `GET /treasury/admin/transactions` -> recent locally recorded admin/reservation transactions.
- `GET /treasury/admin/contract-info` -> contract address + networks.

## Wallet dashboard UI
Served from `/wallet-dashboard` (loopback only). Use it to create/import the institutional wallet; it writes `wallet-config.properties` and reloads the wallet without restarting the service.

## Invite token onboarding
Endpoint: `POST /onboarding/token/apply` (enabled when `features.organizations.enabled=true`).
- Expects `{ "token": "<payload>.<hmac>", "walletAddress": "optional" }`.
- Token payload is Base64URL-encoded JSON with `inviteId`, `issuer`, `institutionWallet` (optional), `organizations` (list of domains), `issuedAt`, `expiresAt`.
- HMAC-SHA256 signature uses `organization.invite.hmac-secret`. `organization.invite.default-issuer` fills missing issuer.
- Applies `grantInstitutionRole` on the Diamond contract for each organization using the institutional wallet.

## Configuration quick reference
- Contract/RPC: `CONTRACT_ADDRESS`, `ETHEREUM_MAINNET_RPC_URL`, `ETHEREUM_SEPOLIA_RPC_URL`, `BLOCKCHAIN_NETWORK_ACTIVE`.
- Wallet persistence/encryption: `wallet.persistence.*`, `wallet.config.encryption-key`, `wallet.config.encryption-key-file`.
- Localhost protections: `security.allow-private-networks` (false recommended outside Docker bridge).
- Marketplace/SAML settings are shared with the auth service (see `AUTH_SERVICE.md`).
