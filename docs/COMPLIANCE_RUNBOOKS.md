# Compliance Runbooks

> Operational runbooks for MiCA Art 4(3) compliance monitoring, provider lifecycle, and deferred-revenue accounting.
> These runbooks are part of Phase 0 / Phase 4 of the MiCA compliance programme.

---

## Runbook 1: MiCA 12-month Offer-Volume Monitoring

### Purpose
Ensure the rolling 12-month EUR offer volume stays below the EUR 1,000,000 threshold defined in MiCA Art 4(3)(a). If the threshold is crossed, the DGT / CNMV notification process must be triggered.

### Automated monitoring
The backend scheduler `MicaThresholdMonitorScheduler` runs daily at approx. 02:00 UTC and:
1. Queries `funding_orders` for confirmed volumes in the rolling 12-month window.
2. Stores a snapshot in `mica_volume_snapshots` via `MicaVolumePersistenceService`.
3. Emits a WARN log at ≥ 80 % of threshold (configurable: `billing.mica.warning-pct`).
4. Emits an ERROR log at ≥ 100 % of threshold.

### Manual verification (on-demand)
```
GET /billing/compliance/exports/mica-volume
# Returns: { "rollingEurVolume": ..., "periodStart": ..., "periodEnd": ... }
```

### Threshold breach procedure
1. Finance Director receives the ALERT from the ops monitoring channel.
2. Finance Director validates the volume figure against the export above.
3. If confirmed ≥ EUR 1,000,000:
   a. Suspend new funding orders immediately (set `billing.mica.threshold-eur=0` to block via manual config, or pause the FundingOrderService).
   b. Legal Counsel is notified within 24 hours.
   c. Legal Counsel prepares the CNMV notification pack using data from `PHASE_0_COMPLIANCE_FREEZE.md` §9.2.
   d. The notification is filed with CNMV within the regulatory deadline.
4. Do **not** accept new funding orders until regulatory status is confirmed.

### Configuration keys
| Key | Default | Purpose |
|---|---|---|
| `billing.mica.threshold-eur` | `1000000` | EUR threshold before ALERT |
| `billing.mica.warning-pct` | `80` | Percentage of threshold for WARN |
| `billing.mica-threshold.interval-ms` | `86400000` | Schedule interval (ms) |

---

## Runbook 2: Provider Contract Expiry and Suspension

### Purpose
Ensure no provider with an expired or terminated merchant agreement can remain active in the network.

### Automated monitoring
`ProviderContractExpiryScheduler` runs daily and queries `provider_network_registry` for ACTIVE rows where `expiry_date <= TODAY + warning_days`. It logs a WARNING for each expiring provider.

### Manual verification
```
GET /billing/provider-network?status=all
# Review rows where status=ACTIVE and expiryDate is approaching or past.
```

### Expiry procedure
1. Finance / Operations receives daily expiry warning from logs or monitoring channel.
2. Contact the provider (by email using the contact on file) at least 30 days before expiry.
3. If the provider renews their agreement:
   a. Obtain the new signed agreement. Record the new version string (e.g. `"v2.2"`).
   b. Update or reactivate the membership via:
      ```
      POST /billing/provider-network
      { "providerAddress": "0x...", "contractId": "...", "agreementVersion": "v2.2",
        "effectiveDate": "YYYY-MM-DD", "expiryDate": "YYYY-MM-DD", "activatedBy": "ops-admin@decentralabs.eu" }
      ```
4. If the provider does **not** renew:
   a. Suspend via:
      ```
      POST /billing/provider-network/{id}/suspend
      { "reason": "Contract expired — not renewed", "actionBy": "ops-admin@decentralabs.eu" }
      ```
   b. Notify the provider and any affected institutions.
   c. Disable the on-chain `providerNetworkStatus` via `setProviderNetworkStatus` admin call.

### Suspension vs. termination
- **Suspend** for temporary holds (investigation, contract gap, pending renewal).
- **Terminate** for permanent removals.
- Termination is irreversible in the current on-chain model; do not terminate until legally confirmed.

### Required audit fields
Every activation, suspension, and termination **must** include:
- `agreementVersion` — the version string of the signed agreement
- `actionBy` — the operator's address or email that performed the action

These are stored in `provider_network_registry.agreement_version` and `action_by`.

---

## Runbook 3: Expired Credits and Adjustment Entries

### Purpose
Process expired credit lots, record the deferred-revenue release, and support Finance with the accounting entries needed under prepaid/voucher accounting.

### Automated lot expiry
`CreditExpiryScheduler` runs hourly, queries `credit_lots` where `expires_at <= NOW()` and `expired = false`, and marks them `expired = true`. In a production deployment this also triggers an on-chain `expireCredits(account, lotIndex)` call via `ServiceCreditFacet`.

### Manual verification
```
GET /billing/compliance/exports/expired-balances
# Returns expired credit lots by account with EUR gross amount for accounting.
```

### Accounting entry procedure (per expired lot)
1. Pull the expired lot export for the accounting period.
2. For each expired lot:
   - **Debit**: Deferred Revenue (liability), EUR gross amount of the lot.
   - **Credit**: Other Income — Expired Credits (revenue), same amount.
3. Document the `fundingOrderId` and `lotIndex` in the journal entry as the audit reference.
4. Retain the on-chain `CreditLotExpired` event log as the primary evidence.

### Customer communication
- Customers should receive an expiry warning email at `billing.credit-expiry.warning-days` before expiry (default: 30 days).
- The email must not say "tokens burned" — correct wording: "Your service credits (Lot #X, EUR Y) will expire on [date] if unused."

### Adjustment entries
For post-capture adjustments (`ledgerAdjustCredits`):
1. Pull the compliance export: `GET /billing/compliance/exports/consumed-by-period`.
2. Each `CreditMovement` with `type = ADJUST` must be cross-referenced to the `adjustmentRef` stored in the movement record.
3. Finance records the adjustment as a deferred-revenue correction referencing the `adjustmentRef` and `fundingOrderId`.

---

## Runbook 4: DGT Consultation Evidence Generation

### Purpose
Prepare and assemble the evidence pack for a binding DGT (Agencia Tributaria) consultation (consulta vinculante) on the VAT treatment of prepaid service credits.

### Evidence pack checklist
| Item | Source | Status |
|---|---|---|
| Invoice template with approved wording | `PHASE_0_COMPLIANCE_FREEZE.md` §2.2 | ✅ Defined |
| EUR-to-credit conversion schedule | `PHASE_0_COMPLIANCE_FREEZE.md` §6 | ✅ Defined |
| Non-transferability technical evidence | `LabERC20NonTransferable.t.sol` test output | Run `forge test --match-contract LabERC20NonTransferable` |
| On-chain admin-only minting evidence | `CreditLedger.t.sol` test output + `ServiceCreditFacet` source | ✅ Available |
| Credit expiry policy | `PHASE_0_COMPLIANCE_FREEZE.md` §7.1 | ✅ Defined |
| Deferred-revenue accounting schedule | Finance export: `GET /billing/compliance/exports/prepaid-balance-by-lot` | Generate at filing date |
| Service description and network scope | `ARCHITECTURE_LIMITED_NETWORK_CREDIT_MODEL.md` | ✅ Available |
| Provider network scope evidence | `GET /billing/compliance/exports/provider-network-snapshot` | Generate at filing date |

### Generation procedure
1. Legal Counsel confirms the DGT consultation scope with Finance.
2. Run the following exports to collect current-state data:
   ```
   GET /billing/compliance/exports/prepaid-balance-by-lot
   GET /billing/compliance/exports/provider-network-snapshot
   GET /billing/compliance/exports/mica-volume
   ```
3. Run Foundry non-transferability tests and include output:
   ```
   cd Smart-Contracts
   forge test --match-contract LabERC20NonTransferable -v
   forge test --match-contract CreditLedger -v
   ```
4. Assemble:
   - Cover page: issuer legal name, LEI, date.
   - Section 1: Product description (use `ARCHITECTURE_LIMITED_NETWORK_CREDIT_MODEL.md`).
   - Section 2: Commercial model (use `PHASE_0_COMPLIANCE_FREEZE.md` §1–§3).
   - Section 3: Technical non-transferability (Foundry test output).
   - Section 4: Accounting model (use `PHASE_0_COMPLIANCE_FREEZE.md` §5–§7).
   - Section 5: Current volume and provider network snapshot (exports from step 2).
5. Legal Counsel submits via the AEAT Sede Electrónica using the entity's digital certificate.
6. Record the consultation reference number and filing date in the project legal register.
