package decentralabs.blockchain.controller.health;

import decentralabs.blockchain.service.auth.MarketplaceKeyService;
import decentralabs.blockchain.service.auth.SamlValidationService;
import decentralabs.blockchain.service.organization.InstitutionRegistrationService;
import decentralabs.blockchain.service.organization.InstitutionRole;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/health")
@RequiredArgsConstructor
@Slf4j
public class HealthController {

    private static final String DATABASE_UNAVAILABLE = "DATABASE_UNAVAILABLE";
    private static final String MIGRATION_MISSING = "MIGRATION_MISSING";
    private static final String QUERY_FAILED = "QUERY_FAILED";

    private final MarketplaceKeyService marketplaceKeyService;
    private final WalletService walletService;
    private final SamlValidationService samlValidationService;
    private final InstitutionalWalletService institutionalWalletService;
    private final InstitutionRegistrationService institutionRegistrationService;
    private final ObjectProvider<JdbcTemplate> jdbcTemplateProvider;

    @Value("${marketplace.public-key-url}")
    private String marketplacePublicKeyUrl;

    @Value("${private.key.path:}")
    private String privateKeyPath;

    @Value("${features.providers.enabled:true}")
    private boolean providersEnabled;

    @Value("${contract.event.listening.enabled:true}")
    private boolean eventListeningEnabled;

    @Value("${contract.address:}")
    private String contractAddress;

    @Value("${organization.invite.hmac-secret:}")
    private String organizationInviteHmacSecret;

    @Value("${health.queue-stuck-threshold-seconds:120}")
    private int queueStuckThresholdSeconds;

    @GetMapping
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> healthStatus = new HashMap<>();

        try {
            healthStatus.put("status", "UP");
            healthStatus.put("timestamp", Instant.now().toString());
            healthStatus.put("service", "blockchain-services");
            healthStatus.put("version", "1.0.0");

            boolean marketplaceKeyAvailable = checkMarketplaceKeyAvailability();
            healthStatus.put("marketplace_key_cached", marketplaceKeyAvailable);
            healthStatus.put("marketplace_key_url", marketplacePublicKeyUrl);

            healthStatus.put("jwt_validation", "ready");
            String rpcVersion = resolveRpcClientVersion();
            healthStatus.put("rpc_client_version", rpcVersion != null ? rpcVersion : "unavailable");
            healthStatus.put("rpc_up", rpcVersion != null);
            healthStatus.put("private_key_present", isPrivateKeyPresent());
            healthStatus.put("saml_validation_ready", samlValidationService.isConfigured());
            healthStatus.put("event_listener_enabled", eventListeningEnabled);
            boolean databaseUp = isDatabaseUp();
            healthStatus.put("database_up", databaseUp);
            HealthCount unavailable = HealthCount.failure(DATABASE_UNAVAILABLE);
            HealthCount nonceBacklog = databaseUp ? countNonceBacklog() : unavailable;
            HealthCount accessDeliveriesStuck = databaseUp ? countStuckAccessDeliveries() : unavailable;
            HealthCount sessionStartedUnknown = databaseUp ? countUnknownSessionStartedTransactions() : unavailable;
            HealthCount sessionStartedFailed = databaseUp ? countFailedSessionStartedTransactions() : unavailable;
            HealthCount institutionalTransactionsStuck = databaseUp ? countInstitutionalTransactionBlockers() : unavailable;
            Map<String, String> queueHealthErrors = new LinkedHashMap<>();
            putHealthCount(healthStatus, queueHealthErrors, "nonce_backlog", nonceBacklog);
            putHealthCount(healthStatus, queueHealthErrors, "access_deliveries_stuck", accessDeliveriesStuck);
            putHealthCount(healthStatus, queueHealthErrors, "session_started_unknown", sessionStartedUnknown);
            putHealthCount(healthStatus, queueHealthErrors, "session_started_failed", sessionStartedFailed);
            putHealthCount(healthStatus, queueHealthErrors, "institutional_transactions_stuck", institutionalTransactionsStuck);
            healthStatus.put("queue_health_errors", queueHealthErrors);
            healthStatus.put("wallet_configured", institutionalWalletService.isConfigured());
            healthStatus.put("treasury_configured", isTreasuryConfigured());
            boolean providerRegistered = institutionRegistrationService.isRegistered(InstitutionRole.PROVIDER);
            boolean consumerRegistered = institutionRegistrationService.isRegistered(InstitutionRole.CONSUMER);
            boolean institutionRegistered = providersEnabled ? providerRegistered : consumerRegistered;
            healthStatus.put("operating_mode", providersEnabled ? "provider-consumer" : "consumer-only");
            healthStatus.put("provider_registered", providerRegistered);
            healthStatus.put("consumer_registered", consumerRegistered);
            healthStatus.put("institution_registered", institutionRegistered);
            // Treat invite token capability as ready when a secret is configured
            // or when the institution has already completed registration.
            healthStatus.put("invite_token_configured", isInviteTokenConfigured() || institutionRegistered);
            healthStatus.put("endpoints", getEndpointStatus());

            return buildResponse(healthStatus);
        } catch (Exception e) {
            log.error("Health check failed", e);
            healthStatus.put("status", "DOWN");
            healthStatus.put("error", e.getMessage());
            healthStatus.put("timestamp", Instant.now().toString());
            healthStatus.put("service", "blockchain-services");

            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(healthStatus);
        }
    }

    private ResponseEntity<Map<String, Object>> buildResponse(Map<String, Object> status) {
        boolean rpcUp = Boolean.TRUE.equals(status.get("rpc_up"));
        boolean keyPresent = Boolean.TRUE.equals(status.get("private_key_present"));
        boolean marketplaceReady = Boolean.TRUE.equals(status.get("marketplace_key_cached"));
        boolean dbUp = Boolean.TRUE.equals(status.get("database_up"));
        boolean walletConfigured = Boolean.TRUE.equals(status.get("wallet_configured"));
        boolean treasuryConfigured = Boolean.TRUE.equals(status.get("treasury_configured"));
        boolean providerRegistered = Boolean.TRUE.equals(status.get("provider_registered"));
        boolean consumerRegistered = Boolean.TRUE.equals(status.get("consumer_registered"));
        boolean providerReady = providersEnabled ? providerRegistered : consumerRegistered;
        boolean authSigningReady = !providersEnabled || keyPresent;
        boolean durableQueuesReady = zeroCount(status.get("nonce_backlog"))
            && zeroCount(status.get("access_deliveries_stuck"))
            && zeroCount(status.get("session_started_unknown"))
            && zeroCount(status.get("session_started_failed"))
            && zeroCount(status.get("institutional_transactions_stuck"));

        if (!rpcUp || !authSigningReady || !marketplaceReady || !dbUp || !walletConfigured
                || !treasuryConfigured || !providerReady || !durableQueuesReady) {
            status.put("status", "DEGRADED");
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(status);
        }
        return ResponseEntity.ok(status);
    }

    private boolean checkMarketplaceKeyAvailability() {
        try {
            return marketplaceKeyService.ensureKey(false);
        } catch (Exception e) {
            log.warn("Marketplace key availability check failed: {}", e.getMessage());
            return false;
        }
    }

    private boolean isPrivateKeyPresent() {
        if (privateKeyPath == null || privateKeyPath.isBlank()) {
            return false;
        }
        try {
            return Files.exists(Path.of(privateKeyPath));
        } catch (Exception e) {
            log.warn("Unable to verify private key path {}: {}", privateKeyPath, e.getMessage());
            return false;
        }
    }

    private String resolveRpcClientVersion() {
        try {
            return walletService.getWeb3jInstance()
                .web3ClientVersion()
                .send()
                .getWeb3ClientVersion();
        } catch (Exception e) {
            log.warn("RPC connectivity check failed: {}", e.getMessage());
            return null;
        }
    }

    private Map<String, String> getEndpointStatus() {
        Map<String, String> endpoints = new HashMap<>();

        if (providersEnabled) {
            endpoints.put("authorize-and-issue", "available");
            endpoints.put("checkin-institutional", "available");
            endpoints.put("jwks", "available");
        } else {
            String disabled = "disabled (providers flag off)";
            endpoints.put("authorize-and-issue", disabled);
            endpoints.put("checkin-institutional", disabled);
            endpoints.put("jwks", disabled);
        }

        endpoints.put("wallet-create", "available (localhost)");
        endpoints.put("wallet-import", "available (localhost)");
        endpoints.put("wallet-balance", "available (localhost)");
        endpoints.put("wallet-transactions", "available (localhost)");
        endpoints.put("wallet-listen-events", "available (localhost)");
        endpoints.put("wallet-networks", "available (localhost)");
        endpoints.put("wallet-switch-network", "available (localhost)");

        endpoints.put("billing", "available (localhost)");
        endpoints.put("billing-admin", "available (localhost)");
        endpoints.put("treasury-reservations", "deprecated alias; use billing");
        endpoints.put("treasury-admin", "deprecated alias; use billing-admin");

        endpoints.put("health", "available");
        return endpoints;
    }

    private boolean isInviteTokenConfigured() {
        return organizationInviteHmacSecret != null && !organizationInviteHmacSecret.isBlank();
    }

    private boolean isDatabaseUp() {
        try {
            JdbcTemplate jdbcTemplate = jdbcTemplateProvider.getIfAvailable();
            if (jdbcTemplate == null) {
                log.warn("No JdbcTemplate available for database health check");
                return false;
            }
            Integer result = jdbcTemplate.queryForObject("SELECT 1", Integer.class);
            return result != null && result == 1;
        } catch (Exception e) {
            log.warn("Database connectivity check failed: {}", e.getMessage());
            return false;
        }
    }

    private HealthCount countNonceBacklog() {
        int threshold = boundedQueueThreshold();
        return countHealthRows(
            "SELECT COUNT(*) FROM institutional_checkin_outbox "
                + "WHERE status = 'STUCK_UNKNOWN' OR (nonce IS NOT NULL "
                + "AND status IN ('PENDING', 'RETRY', 'SUBMITTING', 'SUBMITTED') "
                + "AND updated_at < DATE_SUB(CURRENT_TIMESTAMP, INTERVAL " + threshold + " SECOND))",
            "11"
        );
    }

    private HealthCount countStuckAccessDeliveries() {
        int threshold = boundedQueueThreshold();
        return countHealthRows(
            "SELECT COUNT(*) FROM access_authorization_provisioning WHERE "
                + "(status IN ('PREPARED', 'WAITING_AUTHORIZATION', 'ACTIVATED', 'ROLLING_BACK') "
                + "AND expires_at < CURRENT_TIMESTAMP) OR (status = 'CODE_PERSISTED' "
                + "AND updated_at < DATE_SUB(CURRENT_TIMESTAMP, INTERVAL " + threshold + " SECOND))",
            "17"
        );
    }

    private HealthCount countUnknownSessionStartedTransactions() {
        return countHealthRows(
            "SELECT COUNT(*) FROM session_started_attestations WHERE onchain_status = 'STUCK_UNKNOWN'",
            "21"
        );
    }

    private HealthCount countFailedSessionStartedTransactions() {
        int threshold = boundedQueueThreshold();
        return countHealthRows(
            "SELECT COUNT(*) FROM session_started_attestations WHERE onchain_status IN "
                + "('FAILED', 'MANUAL_INTERVENTION', 'MINED_FAILED') OR "
                + "(onchain_status IN ('RETRY', 'SUBMITTING') AND updated_at < DATE_SUB(CURRENT_TIMESTAMP, INTERVAL "
                + threshold + " SECOND))",
            "21"
        );
    }

    private HealthCount countInstitutionalTransactionBlockers() {
        int threshold = boundedQueueThreshold();
        return countHealthRows(
            "SELECT COUNT(*) FROM institutional_transaction_outbox WHERE "
                + "status = 'STUCK_UNKNOWN' OR (status IN ('RESERVED', 'PREPARED', 'RETRYABLE', 'SUBMITTED', 'REPLACEMENT_PENDING') "
                + "AND updated_at < DATE_SUB(CURRENT_TIMESTAMP, INTERVAL "
                + threshold + " SECOND))",
            "28"
        );
    }

    private HealthCount countHealthRows(String sql, String requiredMigration) {
        JdbcTemplate jdbcTemplate = jdbcTemplateProvider.getIfAvailable();
        if (jdbcTemplate == null) {
            return HealthCount.failure(DATABASE_UNAVAILABLE);
        }
        try {
            Integer count = jdbcTemplate.queryForObject(sql, Integer.class);
            if (count == null) {
                log.warn("Durable queue health query returned no count");
                return HealthCount.failure(QUERY_FAILED);
            }
            return HealthCount.success(count);
        } catch (Exception e) {
            String error = isMissingSchemaObject(e) && isMigrationMissing(jdbcTemplate, requiredMigration)
                ? MIGRATION_MISSING
                : QUERY_FAILED;
            log.warn("Durable queue health check failed ({}): {}", error, e.getMessage());
            return HealthCount.failure(error);
        }
    }

    private boolean isMigrationMissing(JdbcTemplate jdbcTemplate, String requiredMigration) {
        try {
            Integer applied = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM flyway_schema_history WHERE version = ? AND success = TRUE",
                Integer.class,
                requiredMigration
            );
            return applied != null && applied == 0;
        } catch (Exception historyError) {
            if (isMissingSchemaObject(historyError)) {
                return true;
            }
            log.warn(
                "Unable to inspect Flyway migration {} while classifying queue health: {}",
                requiredMigration,
                historyError.getMessage()
            );
            return false;
        }
    }

    private void putHealthCount(
            Map<String, Object> status,
            Map<String, String> errors,
            String key,
            HealthCount result) {
        status.put(key, result.count());
        if (result.error() != null) {
            errors.put(key, result.error());
        }
    }

    private boolean isMissingSchemaObject(Throwable error) {
        Throwable current = error;
        while (current != null) {
            if (current instanceof SQLException sqlException) {
                String sqlState = sqlException.getSQLState();
                int vendorCode = sqlException.getErrorCode();
                if ("42S02".equals(sqlState)
                        || "42S22".equals(sqlState)
                        || "42P01".equals(sqlState)
                        || "42703".equals(sqlState)
                        || vendorCode == 1054
                        || vendorCode == 1146) {
                    return true;
                }
            }
            current = current.getCause();
        }
        return false;
    }

    private record HealthCount(Integer count, String error) {
        private static HealthCount success(int count) {
            return new HealthCount(count, null);
        }

        private static HealthCount failure(String error) {
            return new HealthCount(null, error);
        }
    }

    private int boundedQueueThreshold() {
        return Math.max(1, Math.min(86_400, queueStuckThresholdSeconds));
    }

    private boolean zeroCount(Object value) {
        return value instanceof Number number && number.intValue() == 0;
    }

    private boolean isTreasuryConfigured() {
        return contractAddress != null
            && !contractAddress.isBlank()
            && institutionalWalletService.isConfigured();
    }
}
