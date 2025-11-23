package decentralabs.blockchain.controller.health;

import decentralabs.blockchain.service.auth.MarketplaceKeyService;
import decentralabs.blockchain.service.auth.SamlValidationService;
import decentralabs.blockchain.service.wallet.WalletService;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
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

    @Value("${marketplace.public-key-url}")
    private String marketplacePublicKeyUrl;

    @Value("${private.key.path:}")
    private String privateKeyPath;

    @Value("${features.providers.enabled:true}")
    private boolean providersEnabled;

    @Value("${contract.event.listening.enabled:true}")
    private boolean eventListeningEnabled;

    @GetMapping
    @CrossOrigin(origins = "*")
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

        if (!rpcUp || !keyPresent || !marketplaceReady) {
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
            endpoints.put("wallet-auth", "available");
            endpoints.put("wallet-auth2", "available");
            endpoints.put("saml-auth", "available");
            endpoints.put("saml-auth2", "available");
            endpoints.put("jwks", "available");
            endpoints.put("message", "available");
        } else {
            String disabled = "disabled (providers flag off)";
            endpoints.put("wallet-auth", disabled);
            endpoints.put("wallet-auth2", disabled);
            endpoints.put("saml-auth", disabled);
            endpoints.put("saml-auth2", disabled);
            endpoints.put("jwks", disabled);
            endpoints.put("message", disabled);
        }

        endpoints.put("wallet-create", "available (localhost)");
        endpoints.put("wallet-import", "available (localhost)");
        endpoints.put("wallet-balance", "available (localhost)");
        endpoints.put("wallet-transactions", "available (localhost)");
        endpoints.put("wallet-listen-events", "available (localhost)");
        endpoints.put("wallet-networks", "available (localhost)");
        endpoints.put("wallet-switch-network", "available (localhost)");

        endpoints.put("treasury-reservations", "available (localhost)");
        endpoints.put("treasury-admin", "available (localhost)");

        endpoints.put("health", "available");
        return endpoints;
    }
}
