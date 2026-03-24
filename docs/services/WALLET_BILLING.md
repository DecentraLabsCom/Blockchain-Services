# Institutional Wallet and Billing Admin

Operational guide for wallet, billing admin, and related local dashboards.

## Access Model

Sensitive routes are protected by `LocalhostOnlyFilter`:

- `/wallet/**`
- `/billing/**`
- `/wallet-dashboard/**`
- `/institution-config/**`
- `/billing/admin/notifications/**`

Private-network access can be enabled with:

- `security.allow-private-networks=true`
- `security.access-token` (required when `security.access-token.required=true`)

## Wallet Endpoints (`/wallet`)

- `POST /wallet/create`
  - Input: `{ "password": "..." }`
  - Creates a wallet, stores encrypted private key, writes wallet config, reloads institutional wallet.

- `POST /wallet/import`
  - Input: `{ "privateKey" | "mnemonic", "password": "..." }`
  - Imports and replaces the active institutional wallet.

- `POST /wallet/reveal`
  - Input: `{ "password": "..." }`
  - Reveals private key (localhost-restricted, break-glass endpoint).

- `GET /wallet/{address}/balance`
- `GET /wallet/{address}/transactions`
- `GET /wallet/listen-events`
- `GET /wallet/networks`
- `POST /wallet/switch-network`

## Billing Admin (`/billing/admin/execute`)

Endpoint:

- `POST /billing/admin/execute`

Security requirements:

1. Request must pass localhost/private-network restrictions.
2. `adminWalletAddress` must match configured institutional wallet.
3. EIP-712 signature is mandatory (`timestamp` + `signature` fields).
4. Signature timestamp window is 5 minutes and replay-protected.

Supported operations:

- `AUTHORIZE_BACKEND`
- `REVOKE_BACKEND`
- `ADMIN_RESET_BACKEND`
- `SET_USER_LIMIT`
- `SET_SPENDING_PERIOD`
- `RESET_SPENDING_PERIOD`
- `ISSUE_SERVICE_CREDITS`
- `ADJUST_SERVICE_CREDITS`
- `TRANSITION_PROVIDER_RECEIVABLE_STATE`
- `COLLECT_LAB_PAYOUT`

Minimal example:

```json
{
  "adminWalletAddress": "0x...",
  "operation": "SET_USER_LIMIT",
  "spendingLimit": "100",
  "timestamp": 1730000000000,
  "signature": "0x..."
}
```

## Billing Read-Only Admin Endpoints

- `GET /billing/admin/status`
- `GET /billing/admin/balance`
- `GET /billing/admin/transactions`
- `GET /billing/admin/contract-info`
- `GET /billing/admin/billing-info`
- `GET /billing/admin/top-spenders`
- `GET|POST /billing/admin/notifications`
- `POST /billing/admin/notifications/test`

## Wallet Dashboard and Provisioning

UI routes:

- `/wallet-dashboard/`
- `/institution-config/`

Provisioning token application (current flow):

- `POST /institution-config/apply-provider-token`
- `POST /institution-config/apply-consumer-token`

Note:

- `/onboarding/token/**` is currently protected in filters/CORS, but there is no public controller endpoint in this repository version.

## Configuration Quick Reference

- Contract/RPC: `CONTRACT_ADDRESS`, `ETHEREUM_MAINNET_RPC_URL`, `ETHEREUM_SEPOLIA_RPC_URL`, `BLOCKCHAIN_NETWORK_ACTIVE`
- Wallet persistence: `wallet.persistence.file.path`, `wallet.config.encryption-key`, `wallet.config.encryption-key-file`
- Access control: `security.allow-private-networks`, `security.access-token`, `security.access-token.required`
