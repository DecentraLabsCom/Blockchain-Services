# API reference

This is an implementation-oriented navigation reference for the canonical
backend. It lists the controller mappings currently present in this repository;
it is not an OpenAPI schema. Request and response fields are defined by the DTOs
beside each controller, and route-specific validations remain authoritative.

## Access legend

| Label | Meaning |
| --- | --- |
| Marketplace/service JWT | Validated by `MarketplaceEndpointAuthService`, with the route's required scope where stated. |
| Gateway credential | Per-gateway redeemer credential or observer JWT; never the admin token. |
| Admin boundary | `LocalhostOnlyFilter` plus the deployment's network/token policy. Billing admin also needs `ROLE_INTERNAL` in provider mode. |
| Conditional | Controller exists only when its feature property is enabled. |

## Identity, access and evidence

| Method | Path | Boundary / purpose |
| --- | --- | --- |
| GET | `/auth/jwks` | Conditional provider controller; public key set for verifying backend JWTs. |
| POST | `/auth/authorize-and-issue` | Booking-aware SAML/Marketplace access delivery. |
| POST | `/auth/access-credential` | Provider access-credential flow. |
| POST | `/auth/checkin-institutional` | Institutional check-in; returns `202` while queued. |
| POST | `/auth/checkin-institutional/status` | Check-in status for its bound reservation context. |
| POST | `/auth/access-code/redeem` | Gateway credential and `X-Gateway-ID`; one-time opaque code redemption. |
| POST | `/auth/fmu/session-ticket/issue` | Conditional provider controller; booking bearer and FMU claims. |
| POST | `/auth/fmu/session-ticket/redeem` | Conditional provider controller; observer JWT (`ROLE_SESSION_OBSERVER`). |
| POST | `/auth/fmu/provider-describe-token` | Conditional provider controller; Marketplace/service JWT. |
| POST | `/access-audit/internal/session-observed` | Observer JWT; records durable runtime observation. |
| GET | `/access-audit/internal/reservations/{reservationKey}` | Admin/internal boundary; audit and attestation summary. |

`AuthController` maps OIDC discovery at `/.well-known/openid-configuration`,
but the current security allow-list is `/auth/.well-known/*`. Consequently the
discovery mapping is not a supported reachable integration endpoint until those
two mappings are aligned. Use `/auth/jwks` only when provider mode is enabled.

## WebAuthn

| Method | Path | Boundary / purpose |
| --- | --- | --- |
| GET | `/onboarding/webauthn/key-status/{stableUserId}` | Marketplace service JWT with `onboarding:webauthn`. |
| POST | `/onboarding/webauthn/options` | Marketplace service JWT; creates registration ceremony. |
| POST | `/onboarding/webauthn/complete` | Session-bound browser completion. |
| GET | `/onboarding/webauthn/status/{sessionId}` | Marketplace service JWT; reads ceremony result. |
| GET | `/onboarding/webauthn/ceremony/{sessionId}` | Session-bound browser ceremony page. |
| POST | `/webauthn/revoke` | Marketplace JWT with `webauthn:manage`; PUC-scoped when present. |

There is no `/webauthn/register` controller. Registration is the onboarding
ceremony above.

## Intents and institutional configuration

| Method | Path | Boundary / purpose |
| --- | --- | --- |
| POST | `/intents` | Marketplace JWT with submit scope. |
| GET | `/intents/{requestId}` | Marketplace JWT with status scope. |
| POST | `/intents/{requestId}/registration-mined` | Marketplace JWT with registration-mined scope. |
| POST | `/intents/authorize` | Marketplace JWT with authorize scope. |
| GET | `/intents/authorize/status/{sessionId}` | Marketplace JWT with status scope. |
| GET | `/intents/authorize/ceremony/{sessionId}` | Session-bound ceremony page. |
| POST | `/intents/authorize/complete` | Session-bound completion. |
| POST | `/intents/authorize/client-error` | Session-bound ceremony diagnostic. |
| GET | `/institution-config/status` | Admin boundary; configuration and registration status. |
| POST | `/institution-config/apply-pairing-challenge` | Admin boundary; signed pairing offer. |
| POST | `/institution-config/complete-pairing` | Admin boundary; final pairing/registration. |
| POST | `/institution-config/apply-provider-token` | Admin boundary; provider automation, feature-gated by service policy. |
| POST | `/institution-config/apply-consumer-token` | Admin boundary; consumer automation. |
| POST | `/institution-config/save-and-register` | Retired endpoint; rejects editable-form registration. |
| POST | `/institution-config/retry-registration` | Retired endpoint; a new pairing is required. |

## Wallet and billing

| Method | Path | Boundary / purpose |
| --- | --- | --- |
| GET | `/wallet/health` | Health exception to the admin boundary. |
| POST | `/wallet/create`, `/wallet/import`, `/wallet/reveal` | Admin boundary; create, import or break-glass reveal wallet material. |
| GET | `/wallet/{address}/balance`, `/wallet/{address}/transactions` | Admin boundary; wallet reads. |
| GET | `/wallet/listen-events`, `/wallet/networks` | Admin boundary; listener/network status. |
| POST | `/wallet/switch-network` | Admin boundary; switches active RPC context. |
| POST | `/billing/funding-orders` | Admin boundary; create funding order. |
| GET | `/billing/funding-orders`, `/billing/funding-orders/{id}` | Admin boundary; funding order reads. |
| POST | `/billing/funding-orders/{id}/invoice`, `/billing/funding-orders/{id}/confirm-payment`, `/billing/funding-orders/{id}/cancel`, `/billing/funding-orders/{id}/mark-credited` | Admin boundary; funding workflow transitions. |
| GET | `/billing/credit-accounts/{address}`, `/billing/credit-accounts/{address}/lots`, `/billing/credit-accounts/{address}/movements` | Admin boundary; local credit projection. |
| POST | `/billing/admin/execute` | Admin boundary and signed EIP-712 administrative command. |
| POST | `/billing/admin/request-provider-payout` | Admin boundary; server-side payout request. |
| GET | `/billing/admin/transaction-status` | Admin boundary; durable transaction status. |
| GET | `/billing/admin/status`, `/billing/admin/balance`, `/billing/admin/transactions`, `/billing/admin/contract-info`, `/billing/admin/provider-labs`, `/billing/admin/provider-receivable-status`, `/billing/admin/billing-info`, `/billing/admin/top-spenders` | Admin boundary; dashboard reads. |
| GET/POST | `/billing/admin/notifications` | Admin boundary; notification settings. |
| POST | `/billing/admin/notifications/test`, `/billing/admin/notifications/send` | Admin boundary; test or send notification. |
| GET/POST | `/billing/provider-network` | Admin boundary; list or activate provider network membership. |
| POST | `/billing/provider-network/{id}/suspend`, `/billing/provider-network/{id}/terminate` | Admin boundary; lifecycle changes. |
| GET | `/billing/provider-receivables` | Admin boundary; filterable provider invoice list. |
| POST | `/billing/provider-receivables/{labId}/invoice` | Admin boundary; submit a uniquely referenced claim invoice. |
| POST | `/billing/provider-receivables/invoices/{invoiceId}/approve`, `/pay` | Admin boundary; approve then record an attested payment. |

## Compliance, labs and health

| Method | Path | Boundary / purpose |
| --- | --- | --- |
| GET | `/billing/compliance/mica-volume` | Admin boundary; current rolling volume. |
| GET | `/billing/compliance/exports/prepaid-balances`, `/consumed`, `/expired`, `/receivable-accruals`, `/completed-payouts`, `/provider-network` | Admin boundary; evidence exports. |
| GET | `/lab-admin/status`, `/lab-admin/labs`, `/lab-admin/guacamole/connections` | Admin boundary or allowed Lab Manager. |
| POST | `/lab-admin/assets`, `/lab-admin/labs`, `/lab-admin/fmu/provider-describe-token`, `/lab-admin/labs/{labId}/creator-binding`, `/lab-admin/labs/{labId}/list`, `/lab-admin/labs/{labId}/unlist` | Admin boundary or allowed Lab Manager; mutations require an idempotency key where documented. |
| PUT | `/lab-admin/labs/{labId}` | Admin boundary or allowed Lab Manager. |
| DELETE | `/lab-admin/assets`, `/lab-admin/labs/{labId}` | Admin boundary or allowed Lab Manager. |
| GET | `/lab-content/**` | Public read-only content, CORS for `GET`/`HEAD`/`OPTIONS`. |
| GET | `/health` | Detailed backend health and durable queue status. |
| GET | `/actuator/health/liveness`, `/actuator/health/readiness`, `/actuator/prometheus`, `/actuator/metrics`, `/actuator/info` | Process/orchestrator/monitoring endpoints. |

Use [Authentication](../services/authentication/AUTH.md),
[Wallet and billing](../services/wallet/WALLET_BILLING.md),
[Lab administration](../services/lab-administration/LAB_ADMINISTRATION.md) and
[Security](../security/SECURITY.md) before integrating a route.
