# Operations and recovery

This is the public operational runbook for `blockchain-services`. It applies to
standalone deployments and to the backend used with Lab Gateway Full. Lab
Gateway Lite consumes the
reservation projection and gateway-side health signals described in the parent
Gateway documentation.

This guide is intentionally conservative: durable transaction and event rows
are evidence, not disposable cache entries. Do not delete, edit or replay them
directly in MySQL unless the change is covered by a reviewed maintenance
procedure and the database has been backed up.

## 1. Preconditions

Before enabling production traffic, verify that the operator has:

- access to the backend's configured admin boundary and access token;
- a trusted RPC endpoint for the configured chain and Diamond address;
- recent backups of MySQL, `/app/data`, the wallet encryption key and
  `LAB_CONTENT_BASE_PATH`;
- the deployed release version, contract deployment manifest and migration
  status.

Administrative endpoints are not public Marketplace endpoints. Keep them behind
the localhost/private-network policy and the configured admin token. See
[Security](../security/SECURITY.md) and [Deployment](../configuration/DEPLOYMENT.md)
before changing that boundary.

## 2. First-response health checks

Run the probes separately. A process can be live while the application is not
ready, and `/health` can report queue blockers without the process being down.

```bash
curl -fsS https://backend.example.edu/actuator/health/liveness
curl -fsS https://backend.example.edu/actuator/health/readiness
curl -sS https://backend.example.edu/health
```

For the local operator view, add the configured access-token header and use an
address allowed by `ADMIN_DASHBOARD_*`/`ADMIN_ALLOWED_CIDRS`:

```bash
curl -fsS \
  -H "X-Access-Token: ${ADMIN_ACCESS_TOKEN}" \
  "https://backend.example.edu/billing/admin/contract-events/dead-letter?limit=100"
```

Interpret the results as follows:

| Signal | Meaning | First action |
| --- | --- | --- |
| Liveness fails | The process or servlet is unavailable. | Inspect container/JVM logs and restart only after preserving evidence. |
| Readiness fails | The instance must not receive traffic. | Inspect RPC, database, migrations and SAML metadata health. |
| `/health` is `DEGRADED` | One or more durable queues or dependencies need attention. | Inspect `queue_health_errors` and the individual counters; do not treat `null` as zero. |
| `/health` is `DOWN` | The health handler could not complete its checks. | Preserve logs and response body, then investigate the failing dependency. |

The main queue counters are `nonce_backlog`, `access_deliveries_stuck`,
`session_started_unknown`, `session_started_failed`,
`institutional_transactions_stuck`, `contract_events_dead_letter` and
`contract_events_orphaned`. Prometheus/Actuator metrics should be monitored in
separately for provider receivable pagination and listener errors.

## 3. Durable transaction incidents

`SUBMITTED`, `REPLACEMENT_PENDING` and `STUCK_UNKNOWN` rows form a wallet/nonce
barrier. They prevent another operation from silently reusing a nonce.

When `institutional_transactions_stuck` or a nonce backlog is non-zero:

1. Stop manual duplicate submissions from the affected institutional wallet.
2. Record the chain ID, contract address, wallet address, operation key, nonce,
   transaction hash, gas values and last error from the operator evidence.
3. Query the trusted RPC for the transaction receipt and the current pending
   nonce. If a receipt exists, verify the sender, nonce, destination, status and
   block canonicality before declaring the operation mined or failed.
4. If the receipt is absent or the RPC is inconsistent, keep the row blocked as
   `STUCK_UNKNOWN` and escalate it. Do not submit a new transaction with the
   same nonce and do not clear the row by timeout.
5. After the RPC/database problem is resolved, use the reviewed reconciliation
   procedure for the deployed release and verify `/health` again.

The backend does not expose an HTTP endpoint for arbitrary transaction repair.
That absence is deliberate: a repair must be based on chain evidence and the
actual winning transaction hash.

## 4. Contract-event dead letters and reorgs

`GET /billing/admin/contract-events/dead-letter` is a read-only evidence view.
For every row, capture `event_name`, `transaction_hash`, `block_number`,
`block_hash`, `canonical_status`, `attempts`, `last_error` and timestamps.

- `DEAD_LETTER` means the configured retry budget was exhausted. Fix the
  dependency or ABI/configuration problem before attempting a reviewed replay.
- `ORPHANED` means a previously observed block was invalidated by a reorg. The
  listener rewinds the cursor and reconciles the replacement canonical range.
- A missing database count or a query error is not an empty queue; restore the
  database connection and repeat the check.

Do not delete journal rows, change their status, or run an ad-hoc event replay
against production. Preserve the row and release metadata for maintainer
review. The canonical event listener only advances its cursor after the
configured confirmation depth and canonical block-hash check.

## 5. Access, session and content queues

For `access_deliveries_stuck`, `session_started_unknown` or
`session_started_failed`:

- verify the reservation, access-code state and gateway-specific observer or
  redeemer credential;
- verify that the provider/gateway destination matches the on-chain
  `accessURI` and that the gateway is using the correct Full/Lite mode;
- inspect the corresponding Gateway and Guacamole/FMU logs;
- do not issue a second access code or bypass the two-phase commit/release flow
  to force a session.

For content deletion issues, preserve the tombstone and the lab-content volume.
The deletion outbox is designed to make cleanup retryable; removing the local
tombstone can make a later reconciliation unsafe.

## 6. Restore and rollout procedure

1. Put the instance out of service and take a consistent MySQL backup.
2. Restore MySQL, `/app/data` and `LAB_CONTENT_BASE_PATH` from the same recovery
   point whenever possible.
3. Restore `WALLET_CONFIG_ENCRYPTION_KEY` or `WALLET_CONFIG_KEY_FILE` and
   `INTENT_PAYLOAD_ENCRYPTION_KEY` together with the data they encrypt. Do not
   generate replacements for an existing database.
4. Deploy the release with Flyway enabled. Never skip migrations to make a
   readiness probe pass.
5. Check liveness, readiness and `/health` independently.
6. Verify the intended backend mode, contract manifest, Marketplace public key,
   SAML metadata state and one gateway-scoped credential before reopening
   traffic.
7. Review durable queue counters before and after the rollout and retain the
   responses with the deployment record.

See [API reference](../reference/API_REFERENCE.md) for route boundaries and
[Architecture](../architecture/ARCHITECTURE.md) for the durable processing
model. For a release checklist, use the [deployment guide](../configuration/DEPLOYMENT.md).
