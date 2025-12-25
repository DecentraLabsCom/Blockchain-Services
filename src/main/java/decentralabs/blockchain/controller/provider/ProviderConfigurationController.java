package decentralabs.blockchain.controller.provider;

import decentralabs.blockchain.dto.provider.ProviderConfigurationRequest;
import decentralabs.blockchain.dto.provider.ProviderConfigurationResponse;
import decentralabs.blockchain.dto.provider.ProvisioningTokenPayload;
import decentralabs.blockchain.dto.provider.ProvisioningTokenRequest;
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

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * Controller for provider configuration and registration UI
 */
@Controller
@RequestMapping("/provider-config")
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
    private final ProviderConfigurationPersistenceService persistenceService;
    private final ProvisioningTokenService provisioningTokenService;

    @Value("${marketplace.base-url:}")
    private String marketplaceBaseUrl;

    @Value("${marketplace.api-key:}")
    private String marketplaceApiKey;

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

    /**
     * Serve the provider configuration page
     */
    @GetMapping
    public String getConfigurationPage() {
        return "forward:/provider-config/index.html";
    }

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
            .hasApiKey(!snapshot.marketplaceApiKey().isBlank())
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

            // Persist configuration to file
            persistenceService.saveConfiguration(request);

            log.info("Configuration saved successfully. Attempting registration...");

            // Trigger registration
            boolean registered = registrationService.registerProvider(
                request.getMarketplaceBaseUrl(),
                request.getMarketplaceApiKey(),
                request.getProviderName(),
                request.getProviderEmail(),
                request.getProviderCountry(),
                request.getProviderOrganization(),
                request.getPublicBaseUrl()
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
    public ResponseEntity<Map<String, Object>> retryRegistration() {
        Map<String, Object> response = new HashMap<>();

        try {
            ConfigSnapshot snapshot = loadSnapshot();

            if (!isFullyConfigured(snapshot)) {
                response.put("success", false);
                response.put("error", "Provider configuration is incomplete");
                return ResponseEntity.badRequest().body(response);
            }

            boolean registered = registrationService.registerProvider(
                snapshot.marketplaceBaseUrl(),
                snapshot.marketplaceApiKey(),
                snapshot.providerName(),
                snapshot.providerEmail(),
                snapshot.providerCountry(),
                snapshot.providerOrganization(),
                snapshot.publicBaseUrl()
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
    @PostMapping("/apply-token")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> applyProvisioningToken(@Valid @RequestBody ProvisioningTokenRequest request) {
        Map<String, Object> response = new HashMap<>();
        try {
            ConfigSnapshot snapshot = loadSnapshot();
            ProvisioningTokenPayload payload = provisioningTokenService.validateAndExtract(request.getToken(), snapshot.marketplaceBaseUrl());

            // Persist configuration from token (source=token)
            persistenceService.saveConfigurationFromToken(payload);

            boolean registered = registrationService.registerProvider(
                payload.getMarketplaceBaseUrl(),
                payload.getApiKey(),
                payload.getProviderName(),
                payload.getProviderEmail(),
                payload.getProviderCountry(),
                payload.getProviderOrganization(),
                payload.getPublicBaseUrl()
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

    private boolean isFullyConfigured(ConfigSnapshot snapshot) {
        return !snapshot.marketplaceBaseUrl().isBlank()
            && !snapshot.marketplaceApiKey().isBlank()
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
        String resolvedApiKey = firstNonBlank(props.getProperty("marketplace.api-key"), marketplaceApiKey);
        String resolvedProviderName = firstNonBlank(props.getProperty("provider.name"), providerName);
        String resolvedProviderEmail = firstNonBlank(props.getProperty("provider.email"), providerEmail);
        String resolvedProviderCountry = firstNonBlank(props.getProperty("provider.country"), providerCountry);
        String resolvedProviderOrg = firstNonBlank(props.getProperty("provider.organization"), providerOrganization);
        String resolvedPublicBaseUrl = firstNonBlank(props.getProperty("public.base-url"), publicBaseUrl);
        String source = props.getProperty("provisioning.source", "manual");

        return new ConfigSnapshot(
            resolvedMarketplace,
            resolvedApiKey,
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
        String marketplaceApiKey,
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
        if (!request.getMarketplaceBaseUrl().startsWith("https://")) {
            throw new IllegalArgumentException("Marketplace base URL must start with https://");
        }

        if (request.getMarketplaceApiKey() == null || request.getMarketplaceApiKey().isBlank()) {
            throw new IllegalArgumentException("Marketplace API key is required");
        }
        if (request.getMarketplaceApiKey().length() < 32) {
            throw new IllegalArgumentException("API key must be at least 32 characters for security");
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
        if (!request.getPublicBaseUrl().startsWith("https://")) {
            throw new IllegalArgumentException("Public base URL must start with https://");
        }
        if (request.getPublicBaseUrl().endsWith("/")) {
            throw new IllegalArgumentException("Public base URL must not end with trailing slash");
        }
    }
}
