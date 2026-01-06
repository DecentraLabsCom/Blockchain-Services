package decentralabs.blockchain.controller.provider;

import decentralabs.blockchain.dto.provider.ConsumerProvisioningTokenPayload;
import decentralabs.blockchain.dto.provider.ProviderConfigurationRequest;
import decentralabs.blockchain.dto.provider.ProviderConfigurationResponse;
import decentralabs.blockchain.dto.provider.ProvisioningTokenPayload;
import decentralabs.blockchain.dto.provider.ProvisioningTokenRequest;
import decentralabs.blockchain.service.organization.ConsumerRegistrationService;
import decentralabs.blockchain.service.organization.ProviderConfigurationPersistenceService;
import decentralabs.blockchain.service.organization.ProviderRegistrationService;
import decentralabs.blockchain.service.organization.ProvisioningTokenService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * Controller for provider configuration and registration UI
 */
@Controller
@RequestMapping("/institution-config")
@RequiredArgsConstructor
@Slf4j
public class ProviderConfigurationController {

    private static final List<String> TOKEN_LOCKED_FIELDS = List.of(
        "providerName",
        "providerEmail",
        "providerCountry",
        "providerOrganization"
    );

    private final ProviderRegistrationService registrationService;
    private final ConsumerRegistrationService consumerRegistrationService;
    private final ProviderConfigurationPersistenceService persistenceService;
    private final ProvisioningTokenService provisioningTokenService;

    @Value("${marketplace.base-url:}")
    private String marketplaceBaseUrl;

    @Value("${provider.name:}")
    private String providerName;

    @Value("${provider.email:}")
    private String providerEmail;

    @Value("${provider.country:}")
    private String providerCountry;

    @Value("${provider.organization:}")
    private String providerOrganization;

    @Value("${public.base-url:}")
    private String publicBaseUrl;

    // Note: GET /institution-config and /institution-config/ are handled by WebConfig
    // to serve static HTML without controller interference

    /**
     * Get current provider configuration status
     */
    @GetMapping("/status")
    @ResponseBody
    public ResponseEntity<ProviderConfigurationResponse> getConfigurationStatus() {
        ConfigSnapshot snapshot = loadSnapshot();
        boolean fromToken = "token".equalsIgnoreCase(snapshot.provisioningSource());

        ProviderConfigurationResponse response = ProviderConfigurationResponse.builder()
            .marketplaceBaseUrl(snapshot.marketplaceBaseUrl())
            .providerName(snapshot.providerName())
            .providerEmail(snapshot.providerEmail())
            .providerCountry(snapshot.providerCountry())
            .providerOrganization(snapshot.providerOrganization())
            .publicBaseUrl(snapshot.publicBaseUrl())
            .isConfigured(isFullyConfigured(snapshot))
            .isRegistered(isRegistered(snapshot))
            .fromProvisioningToken(fromToken)
            .lockedFields(fromToken ? TOKEN_LOCKED_FIELDS : List.of())
            .build();

        return ResponseEntity.ok(response);
    }

    /**
     * Save configuration and trigger provider registration
     */
    @PostMapping("/save-and-register")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> saveAndRegister(
        @Valid @RequestBody ProviderConfigurationRequest request
    ) {
        Map<String, Object> response = new HashMap<>();

        try {
            log.info("Saving provider configuration...");

            // Validate configuration
            validateConfiguration(request);
            if (isBlank(request.getProvisioningToken())) {
                throw new IllegalArgumentException("Provisioning token is required to register");
            }
            String provisioningToken = request.getProvisioningToken().trim();

            // Persist configuration to file
            persistenceService.saveConfiguration(request);

            log.info("Configuration saved successfully. Attempting registration...");

            // Trigger registration
            boolean registered = registrationService.registerProvider(
                request.getMarketplaceBaseUrl(),
                request.getProviderName(),
                request.getProviderEmail(),
                request.getProviderCountry(),
                request.getProviderOrganization(),
                request.getPublicBaseUrl(),
                provisioningToken
            );

            if (registered) {
                response.put("success", true);
                response.put("message", "Provider configuration saved and registration completed successfully");
                response.put("registered", true);
                return ResponseEntity.ok(response);
            } else {
                response.put("success", true);
                response.put("message", "Configuration saved but registration failed. Check logs for details.");
                response.put("registered", false);
                return ResponseEntity.status(HttpStatus.PARTIAL_CONTENT).body(response);
            }

        } catch (IllegalArgumentException e) {
            log.error("Invalid configuration: {}", e.getMessage());
            response.put("success", false);
            response.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(response);
        } catch (Exception e) {
            log.error("Failed to save configuration and register provider", e);
            response.put("success", false);
            response.put("error", "Failed to save configuration: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    /**
     * Retry registration with existing configuration
     */
    @PostMapping("/retry-registration")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> retryRegistration(
        @RequestBody(required = false) Map<String, String> request
    ) {
        Map<String, Object> response = new HashMap<>();

        try {
            ConfigSnapshot snapshot = loadSnapshot();
            String provisioningToken = request == null ? null : request.get("provisioningToken");

            if (!isFullyConfigured(snapshot)) {
                response.put("success", false);
                response.put("error", "Provider configuration is incomplete");
                return ResponseEntity.badRequest().body(response);
            }
            if (isBlank(provisioningToken)) {
                response.put("success", false);
                response.put("error", "Provisioning token is required to register");
                return ResponseEntity.badRequest().body(response);
            }
            String trimmedToken = provisioningToken.trim();

            boolean registered = registrationService.registerProvider(
                snapshot.marketplaceBaseUrl(),
                snapshot.providerName(),
                snapshot.providerEmail(),
                snapshot.providerCountry(),
                snapshot.providerOrganization(),
                snapshot.publicBaseUrl(),
                trimmedToken
            );

            response.put("success", registered);
            response.put("registered", registered);
            response.put("message", registered 
                ? "Provider registration completed successfully"
                : "Registration failed. Check logs for details.");

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Failed to retry provider registration", e);
            response.put("success", false);
            response.put("error", "Registration failed: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    /**
     * Apply provisioning token issued by Marketplace (SSO staff) and register provider
     */
    @PostMapping("/apply-provider-token")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> applyProvisioningToken(@Valid @RequestBody ProvisioningTokenRequest request) {
        Map<String, Object> response = new HashMap<>();
        try {
            ConfigSnapshot snapshot = loadSnapshot();
            String provisioningToken = request.getToken().trim();
            ProvisioningTokenPayload payload = provisioningTokenService.validateAndExtract(
                provisioningToken,
                snapshot.marketplaceBaseUrl(),
                snapshot.publicBaseUrl()
            );

            // Persist configuration from token (source=token)
            persistenceService.saveConfigurationFromToken(payload);

            boolean registered = registrationService.registerProvider(
                payload.getMarketplaceBaseUrl(),
                payload.getProviderName(),
                payload.getProviderEmail(),
                payload.getProviderCountry(),
                payload.getProviderOrganization(),
                payload.getPublicBaseUrl(),
                provisioningToken
            );

            response.put("success", true);
            response.put("registered", registered);
            response.put("lockedFields", TOKEN_LOCKED_FIELDS);
            response.put("config", Map.of(
                "marketplaceBaseUrl", payload.getMarketplaceBaseUrl(),
                "providerName", payload.getProviderName(),
                "providerEmail", payload.getProviderEmail(),
                "providerCountry", payload.getProviderCountry(),
                "providerOrganization", payload.getProviderOrganization(),
                "publicBaseUrl", payload.getPublicBaseUrl()
            ));

            return registered
                ? ResponseEntity.ok(response)
                : ResponseEntity.status(HttpStatus.PARTIAL_CONTENT).body(response);

        } catch (IllegalArgumentException e) {
            response.put("success", false);
            response.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(response);
        } catch (Exception e) {
            log.error("Failed to apply provisioning token", e);
            response.put("success", false);
            response.put("error", "Failed to apply provisioning token: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    /**
     * Apply consumer provisioning token issued by Marketplace (SSO staff) and register as consumer-only institution
     * Consumer-only institutions only need wallet/treasury for reservations, they don't publish labs or provide auth endpoint
     */
    @PostMapping("/apply-consumer-token")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> applyConsumerProvisioningToken(@Valid @RequestBody ProvisioningTokenRequest request) {
        Map<String, Object> response = new HashMap<>();
        try {
            ConfigSnapshot snapshot = loadSnapshot();
            String provisioningToken = request.getToken().trim();
            ConsumerProvisioningTokenPayload payload = provisioningTokenService.validateAndExtractConsumer(
                provisioningToken,
                snapshot.marketplaceBaseUrl(),
                snapshot.publicBaseUrl()
            );

            // Persist minimal consumer configuration from token (source=consumer-token)
            persistenceService.saveConfigurationFromConsumerToken(payload);

            boolean registered = consumerRegistrationService.registerConsumer(
                payload.getMarketplaceBaseUrl(),
                payload.getConsumerOrganization(),
                provisioningToken
            );

            response.put("success", true);
            response.put("registered", registered);
            response.put("consumerMode", true);
            response.put("config", Map.of(
                "marketplaceBaseUrl", payload.getMarketplaceBaseUrl(),
                "consumerName", payload.getConsumerName(),
                "consumerOrganization", payload.getConsumerOrganization()
            ));

            return registered
                ? ResponseEntity.ok(response)
                : ResponseEntity.status(HttpStatus.PARTIAL_CONTENT).body(response);

        } catch (IllegalArgumentException e) {
            response.put("success", false);
            response.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(response);
        } catch (Exception e) {
            log.error("Failed to apply consumer provisioning token", e);
            response.put("success", false);
            response.put("error", "Failed to apply consumer provisioning token: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    private boolean isFullyConfigured(ConfigSnapshot snapshot) {
        return !snapshot.marketplaceBaseUrl().isBlank()
            && !snapshot.providerName().isBlank()
            && !snapshot.providerEmail().isBlank()
            && !snapshot.providerCountry().isBlank()
            && !snapshot.providerOrganization().isBlank()
            && !snapshot.publicBaseUrl().isBlank();
    }

    private boolean isRegistered(ConfigSnapshot snapshot) {
        return !snapshot.marketplaceBaseUrl().isBlank() && !snapshot.providerName().isBlank();
    }

    private ConfigSnapshot loadSnapshot() {
        Properties props = persistenceService.loadConfigurationSafe();
        String resolvedMarketplace = firstNonBlank(props.getProperty("marketplace.base-url"), marketplaceBaseUrl);
        String resolvedProviderName = firstNonBlank(props.getProperty("provider.name"), providerName);
        String resolvedProviderEmail = firstNonBlank(props.getProperty("provider.email"), providerEmail);
        String resolvedProviderCountry = firstNonBlank(props.getProperty("provider.country"), providerCountry);
        String resolvedProviderOrg = firstNonBlank(props.getProperty("provider.organization"), providerOrganization);
        String resolvedPublicBaseUrl = firstNonBlank(props.getProperty("public.base-url"), publicBaseUrl);
        String source = props.getProperty("provisioning.source", "manual");

        return new ConfigSnapshot(
            resolvedMarketplace,
            resolvedProviderName,
            resolvedProviderEmail,
            resolvedProviderCountry,
            resolvedProviderOrg,
            resolvedPublicBaseUrl,
            source
        );
    }

    private String firstNonBlank(String primary, String fallback) {
        if (primary != null && !primary.isBlank()) {
            return primary.trim();
        }
        return fallback == null ? "" : fallback.trim();
    }

    private record ConfigSnapshot(
        String marketplaceBaseUrl,
        String providerName,
        String providerEmail,
        String providerCountry,
        String providerOrganization,
        String publicBaseUrl,
        String provisioningSource
    ) {}

    private void validateConfiguration(ProviderConfigurationRequest request) {
        if (request.getMarketplaceBaseUrl() == null || request.getMarketplaceBaseUrl().isBlank()) {
            throw new IllegalArgumentException("Marketplace base URL is required");
        }
        if (!request.getMarketplaceBaseUrl().startsWith("https://") && !request.getMarketplaceBaseUrl().startsWith("http://")) {
            throw new IllegalArgumentException("Marketplace base URL must start with http:// or https://");
        }
        if (request.getProviderName() == null || request.getProviderName().isBlank()) {
            throw new IllegalArgumentException("Provider name is required");
        }

        if (request.getProviderEmail() == null || request.getProviderEmail().isBlank()) {
            throw new IllegalArgumentException("Provider email is required");
        }
        if (!request.getProviderEmail().matches("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$")) {
            throw new IllegalArgumentException("Invalid email format");
        }

        if (request.getProviderCountry() == null || request.getProviderCountry().isBlank()) {
            throw new IllegalArgumentException("Provider country is required");
        }

        if (request.getProviderOrganization() == null || request.getProviderOrganization().isBlank()) {
            throw new IllegalArgumentException("Provider organization (schacHomeOrganization) is required");
        }

        if (request.getPublicBaseUrl() == null || request.getPublicBaseUrl().isBlank()) {
            throw new IllegalArgumentException("Public base URL is required");
        }
        if (!request.getPublicBaseUrl().startsWith("https://") && !request.getPublicBaseUrl().startsWith("http://")) {
            throw new IllegalArgumentException("Public base URL must start with http:// or https://");
        }
        if (request.getPublicBaseUrl().endsWith("/")) {
            throw new IllegalArgumentException("Public base URL must not end with trailing slash");
        }
    }

    private boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }
}
