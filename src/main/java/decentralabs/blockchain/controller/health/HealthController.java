package decentralabs.blockchain.controller.health;

import decentralabs.blockchain.service.auth.MarketplaceKeyService;
import decentralabs.blockchain.service.auth.SamlValidationService;
import decentralabs.blockchain.service.organization.InstitutionRegistrationService;
import decentralabs.blockchain.service.organization.InstitutionRole;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.HashMap;
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
            int nonceBacklog = databaseUp ? countNonceBacklog() : -1;
            int accessDeliveriesStuck = databaseUp ? countStuckAccessDeliveries() : -1;
            int sessionStartedUnknown = databaseUp ? countUnknownSessionStartedTransactions() : -1;
            healthStatus.put("nonce_backlog", nonceBacklog);
            healthStatus.put("access_deliveries_stuck", accessDeliveriesStuck);
            healthStatus.put("session_started_unknown", sessionStartedUnknown);
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
            && zeroCount(status.get("session_started_unknown"));

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

    private int countNonceBacklog() {
        int threshold = boundedQueueThreshold();
        return countHealthRows(
            "SELECT COUNT(*) FROM institutional_checkin_outbox "
                + "WHERE status = 'STUCK_UNKNOWN' OR (nonce IS NOT NULL "
                + "AND status IN ('PENDING', 'RETRY', 'SUBMITTING', 'SUBMITTED') "
                + "AND updated_at < DATE_SUB(CURRENT_TIMESTAMP, INTERVAL " + threshold + " SECOND))"
        );
    }

    private int countStuckAccessDeliveries() {
        int threshold = boundedQueueThreshold();
        return countHealthRows(
            "SELECT COUNT(*) FROM access_authorization_provisioning WHERE "
                + "(status IN ('PREPARED', 'WAITING_AUTHORIZATION', 'ACTIVATED', 'ROLLING_BACK') "
                + "AND expires_at < CURRENT_TIMESTAMP) OR (status = 'CODE_PERSISTED' "
                + "AND updated_at < DATE_SUB(CURRENT_TIMESTAMP, INTERVAL " + threshold + " SECOND))"
        );
    }

    private int countUnknownSessionStartedTransactions() {
        return countHealthRows(
            "SELECT COUNT(*) FROM access_credential_audit WHERE onchain_status = 'STUCK_UNKNOWN'"
        );
    }

    private int countHealthRows(String sql) {
        try {
            JdbcTemplate jdbcTemplate = jdbcTemplateProvider.getIfAvailable();
            if (jdbcTemplate == null) return -1;
            Integer count = jdbcTemplate.queryForObject(sql, Integer.class);
            return count == null ? -1 : count;
        } catch (Exception e) {
            log.warn("Durable queue health check failed: {}", e.getMessage());
            return -1;
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
