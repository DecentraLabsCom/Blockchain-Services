package decentralabs.blockchain.controller.provider;

import decentralabs.blockchain.dto.provider.ConsumerProvisioningTokenPayload;
import decentralabs.blockchain.dto.provider.ProviderConfigurationResponse;
import decentralabs.blockchain.dto.provider.ProvisioningTokenPayload;
import decentralabs.blockchain.dto.provider.ProvisioningTokenRequest;
import decentralabs.blockchain.dto.provider.PairingChallengeRequest;
import decentralabs.blockchain.service.organization.InstitutionRegistrationRequest;
import decentralabs.blockchain.service.organization.InstitutionRegistrationService;
import decentralabs.blockchain.service.organization.InstitutionRole;
import decentralabs.blockchain.service.organization.ProvisioningPairingPreparation;
import decentralabs.blockchain.service.organization.ProviderConfigurationPersistenceService;
import decentralabs.blockchain.service.organization.ProvisioningTokenService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpClientErrorException;

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
        "institutionId",
        "walletAddress",
        "canonicalBackendOrigin",
        "registrationType",
        "chainId",
        "registryContract",
        "jti",
        "nonce",
        "issuedAt",
        "expiresAt",
        "providerName",
        "providerEmail",
        "providerCountry",
        "providerOrganization"
    );

    private final InstitutionRegistrationService registrationService;
    private final ProviderConfigurationPersistenceService persistenceService;
    private final ProvisioningTokenService provisioningTokenService;

    @Value("${marketplace.base-url:}")
    private String marketplaceBaseUrl;

    @Value("${features.providers.enabled:false}")
    private boolean providersEnabled;

    @Value("${features.providers.registration.enabled:false}")
    private boolean providerRegistrationEnabled;

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
        boolean fromConsumerToken = "consumer-token".equalsIgnoreCase(snapshot.provisioningSource());
        boolean registered = snapshot.providerRegistered() || snapshot.consumerRegistered();
        String registrationRole = snapshot.providerRegistered()
            ? InstitutionRole.PROVIDER.name()
            : (snapshot.consumerRegistered() ? InstitutionRole.CONSUMER.name() : null);

        ProviderConfigurationResponse response = ProviderConfigurationResponse.builder()
            .marketplaceBaseUrl(snapshot.marketplaceBaseUrl())
            .consumerName(snapshot.consumerName())
            .providerName(snapshot.providerName())
            .providerEmail(snapshot.providerEmail())
            .providerCountry(snapshot.providerCountry())
            .providerOrganization(snapshot.providerOrganization())
            .publicBaseUrl(snapshot.publicBaseUrl())
            .isConfigured(isConfigured(snapshot))
            .isRegistered(registered)
            .providerRegistered(snapshot.providerRegistered())
            .consumerRegistered(snapshot.consumerRegistered())
            .providerRegistrationEnabled(providerRegistrationEnabled)
            .operatingMode(providersEnabled ? "provider-consumer" : "consumer-only")
            .registrationRole(registrationRole)
            .fromProvisioningToken(fromToken || fromConsumerToken)
            .lockedFields(fromToken ? TOKEN_LOCKED_FIELDS : List.of())
            .build();

        return ResponseEntity.ok(response);
    }

    /**
     * Retired editable-form flow. Institutional identity must come from pairing
     * and signed claims, never from browser-supplied configuration fields.
     */
    @PostMapping("/save-and-register")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> saveAndRegister() {
        Map<String, Object> response = new HashMap<>();
        response.put("success", false);
        response.put("error", "Editable provisioning forms are retired. Create and approve an institutional pairing first.");
        response.put("code", "PAIRING_REQUIRED");
        return ResponseEntity.status(HttpStatus.GONE).body(response);
    }

    /**
     * Retry registration with existing configuration
     */
    @PostMapping("/retry-registration")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> retryRegistration() {
        Map<String, Object> response = new HashMap<>();
        response.put("success", false);
        response.put("error", "Provisioning tokens are single-use. Issue a new token for an explicit recovery attempt.");
        return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
    }

    /**
     * Exchange a Marketplace challenge for a signed offer using only this
     * backend's configured institutional wallet and public origin.
     */
    @PostMapping("/apply-pairing-challenge")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> applyPairingChallenge(
        @Valid @RequestBody PairingChallengeRequest request
    ) {
        Map<String, Object> response = new HashMap<>();
        try {
            ProvisioningPairingPreparation preparation = registrationService.preparePairing(request.getChallenge());
            if (InstitutionRole.PROVIDER.name().equals(preparation.registrationType())) {
                ensureProviderRegistrationEnabled();
            }
            response.put("success", true);
            response.put("pairingId", preparation.pairingId());
            response.put("status", preparation.status());
            response.put("institutionId", preparation.institutionId());
            response.put("registrationType", preparation.registrationType());
            response.put("walletAddress", preparation.walletAddress());
            response.put("canonicalBackendOrigin", preparation.canonicalBackendOrigin());
            response.put("expiresAt", preparation.expiresAt());
            return ResponseEntity.ok(response);
        } catch (HttpClientErrorException e) {
            response.put("success", false);
            response.put("error", "Marketplace rejected the pairing challenge");
            return ResponseEntity.status(e.getStatusCode()).body(response);
        } catch (IllegalArgumentException | IllegalStateException e) {
            response.put("success", false);
            response.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(response);
        } catch (Exception e) {
            log.error("Failed to offer institutional backend pairing", e);
            response.put("success", false);
            response.put("error", "Failed to pair institutional backend");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    /** Complete registration after the SSO user has approved the read-only offer. */
    @PostMapping("/complete-pairing")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> completePairing(
        @Valid @RequestBody PairingChallengeRequest request
    ) {
        Map<String, Object> response = new HashMap<>();
        try {
            String token = registrationService.retrieveProvisioningToken(request.getChallenge());
            ConfigSnapshot snapshot = loadSnapshot();
            String registrationType = readRegistrationType(token);
            boolean registered;
            if (InstitutionRole.PROVIDER.name().equals(registrationType)) {
                ProvisioningTokenPayload payload = provisioningTokenService.validateAndExtract(
                    token, snapshot.marketplaceBaseUrl(), snapshot.publicBaseUrl()
                );
                registered = registrationService.register(buildProviderRegistrationRequest(token, payload));
                if (registered) registrationService.markAsRegistered(InstitutionRole.PROVIDER);
            } else {
                ConsumerProvisioningTokenPayload payload = provisioningTokenService.validateAndExtractConsumer(
                    token, snapshot.marketplaceBaseUrl(), snapshot.publicBaseUrl()
                );
                registered = registrationService.register(buildConsumerRegistrationRequest(token, payload));
                if (registered) registrationService.markAsRegistered(InstitutionRole.CONSUMER);
            }
            response.put("success", true);
            response.put("registered", registered);
            response.put("registrationType", registrationType);
            return registered
                ? ResponseEntity.ok(response)
                : ResponseEntity.status(HttpStatus.PARTIAL_CONTENT).body(response);
        } catch (HttpClientErrorException e) {
            response.put("success", false);
            response.put("error", "Pairing has not been approved yet");
            return ResponseEntity.status(e.getStatusCode()).body(response);
        } catch (IllegalArgumentException e) {
            response.put("success", false);
            response.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(response);
        } catch (Exception e) {
            log.error("Failed to complete institutional backend pairing", e);
            response.put("success", false);
            response.put("error", "Failed to complete institutional pairing");
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
            ensureProviderRegistrationEnabled();
            ConfigSnapshot snapshot = loadSnapshot();
            if (request.getToken() == null || request.getToken().isBlank()) {
                throw new IllegalArgumentException("Provisioning token is required");
            }
            String provisioningToken = request.getToken().trim();
            ProvisioningTokenPayload payload = provisioningTokenService.validateAndExtract(
                provisioningToken,
                snapshot.marketplaceBaseUrl(),
                snapshot.publicBaseUrl()
            );

            // Persist configuration from token (source=token)
            persistenceService.saveConfigurationFromToken(payload);

            InstitutionRegistrationRequest registrationRequest = InstitutionRegistrationRequest.builder()
                .role(InstitutionRole.PROVIDER)
                .marketplaceUrl(payload.getMarketplaceBaseUrl())
                .provisioningToken(provisioningToken)
                .provisioningClaims(payload.securityClaims())
                .organization(payload.getInstitutionId())
                .name(payload.getProviderName())
                .email(payload.getProviderEmail())
                .country(payload.getProviderCountry())
                .publicBaseUrl(payload.getCanonicalBackendOrigin())
                .build();

            boolean registered = registrationService.register(registrationRequest);

            if (registered) {
                // Mark as registered in config file
                registrationService.markAsRegistered(InstitutionRole.PROVIDER);
            }

            response.put("success", true);
            response.put("registered", registered);
            response.put("lockedFields", TOKEN_LOCKED_FIELDS);
            response.put("config", Map.of(
                "marketplaceBaseUrl", payload.getMarketplaceBaseUrl(),
                "providerName", payload.getProviderName(),
                "providerEmail", payload.getProviderEmail(),
                "providerCountry", payload.getProviderCountry(),
                "providerOrganization", payload.getInstitutionId(),
                "publicBaseUrl", payload.getCanonicalBackendOrigin(),
                "walletAddress", payload.getWalletAddress()
            ));

            return registered
                ? ResponseEntity.ok(response)
                : ResponseEntity.status(HttpStatus.PARTIAL_CONTENT).body(response);

        } catch (IllegalStateException e) {
            response.put("success", false);
            response.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
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
     * Consumer-only institutions only need wallet/billing flows for reservations, they don't publish labs or provide auth endpoint
     */
    @PostMapping("/apply-consumer-token")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> applyConsumerProvisioningToken(@Valid @RequestBody ProvisioningTokenRequest request) {
        Map<String, Object> response = new HashMap<>();
        try {
            ConfigSnapshot snapshot = loadSnapshot();
            if (request.getToken() == null || request.getToken().isBlank()) {
                throw new IllegalArgumentException("Provisioning token is required");
            }
            String provisioningToken = request.getToken().trim();
            ConsumerProvisioningTokenPayload payload = provisioningTokenService.validateAndExtractConsumer(
                provisioningToken,
                snapshot.marketplaceBaseUrl(),
                snapshot.publicBaseUrl()
            );

            // Persist minimal consumer configuration from token (source=consumer-token)
            persistenceService.saveConfigurationFromConsumerToken(payload);

            InstitutionRegistrationRequest registrationRequest = InstitutionRegistrationRequest.builder()
                .role(InstitutionRole.CONSUMER)
                .marketplaceUrl(payload.getMarketplaceBaseUrl())
                .provisioningToken(provisioningToken)
                .provisioningClaims(payload.securityClaims())
                .organization(payload.getInstitutionId())
                .publicBaseUrl(payload.getCanonicalBackendOrigin())
                .build();

            boolean registered = registrationService.register(registrationRequest);

            // Mark as registered in config file if successful
            if (registered) {
                registrationService.markAsRegistered(InstitutionRole.CONSUMER);
            }

            response.put("success", true);
            response.put("registered", registered);
            response.put("consumerMode", true);
            response.put("registrationRole", InstitutionRole.CONSUMER.name());
            response.put("config", Map.of(
                "marketplaceBaseUrl", payload.getMarketplaceBaseUrl(),
                "consumerName", payload.getConsumerName(),
                "consumerOrganization", payload.getInstitutionId(),
                "walletAddress", payload.getWalletAddress()
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

    private boolean isConfigured(ConfigSnapshot snapshot) {
        if ("consumer-token".equalsIgnoreCase(snapshot.provisioningSource())) {
            return !snapshot.marketplaceBaseUrl().isBlank()
                && !snapshot.consumerName().isBlank()
                && !snapshot.providerOrganization().isBlank();
        }

        return !snapshot.marketplaceBaseUrl().isBlank()
            && !snapshot.providerName().isBlank()
            && !snapshot.providerEmail().isBlank()
            && !snapshot.providerCountry().isBlank()
            && !snapshot.providerOrganization().isBlank()
            && !snapshot.publicBaseUrl().isBlank();
    }

    private String readRegistrationType(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) throw new IllegalArgumentException("Malformed provisioning token");
        try {
            byte[] decoded = java.util.Base64.getUrlDecoder().decode(parts[1]);
            com.fasterxml.jackson.databind.JsonNode payload = new com.fasterxml.jackson.databind.ObjectMapper()
                .readTree(decoded);
            String type = payload.path("registrationType").asText("");
            if (!InstitutionRole.PROVIDER.name().equalsIgnoreCase(type)
                && !InstitutionRole.CONSUMER.name().equalsIgnoreCase(type)) {
                throw new IllegalArgumentException("Invalid provisioning registration type");
            }
            return type.toUpperCase();
        } catch (java.io.IOException | IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid provisioning token", e);
        }
    }

    private InstitutionRegistrationRequest buildProviderRegistrationRequest(
        String token,
        ProvisioningTokenPayload payload
    ) {
        return InstitutionRegistrationRequest.builder()
            .role(InstitutionRole.PROVIDER)
            .marketplaceUrl(payload.getMarketplaceBaseUrl())
            .provisioningToken(token)
            .provisioningClaims(payload.securityClaims())
            .organization(payload.getInstitutionId())
            .name(payload.getProviderName())
            .email(payload.getProviderEmail())
            .country(payload.getProviderCountry())
            .publicBaseUrl(payload.getCanonicalBackendOrigin())
            .build();
    }

    private InstitutionRegistrationRequest buildConsumerRegistrationRequest(
        String token,
        ConsumerProvisioningTokenPayload payload
    ) {
        return InstitutionRegistrationRequest.builder()
            .role(InstitutionRole.CONSUMER)
            .marketplaceUrl(payload.getMarketplaceBaseUrl())
            .provisioningToken(token)
            .provisioningClaims(payload.securityClaims())
            .organization(payload.getInstitutionId())
            .publicBaseUrl(payload.getCanonicalBackendOrigin())
            .build();
    }

    private ConfigSnapshot loadSnapshot() {
        Properties props = persistenceService.loadConfigurationSafe();
        String resolvedMarketplace = firstNonBlank(props.getProperty("marketplace.base-url"), marketplaceBaseUrl);
        String resolvedConsumerName = firstNonBlank(props.getProperty("consumer.name"), "");
        String resolvedProviderName = firstNonBlank(props.getProperty("provider.name"), providerName);
        String resolvedProviderEmail = firstNonBlank(props.getProperty("provider.email"), providerEmail);
        String resolvedProviderCountry = firstNonBlank(props.getProperty("provider.country"), providerCountry);
        String resolvedProviderOrg = firstNonBlank(props.getProperty("provider.organization"), providerOrganization);
        String resolvedPublicBaseUrl = firstNonBlank(props.getProperty("public.base-url"), publicBaseUrl);
        String source = props.getProperty("provisioning.source", "manual");
        boolean providerRegistered = "true".equalsIgnoreCase(props.getProperty("provider.registered", "false"));
        boolean consumerRegistered = "true".equalsIgnoreCase(props.getProperty("consumer.registered", "false"));

        return new ConfigSnapshot(
            resolvedMarketplace,
            resolvedConsumerName,
            resolvedProviderName,
            resolvedProviderEmail,
            resolvedProviderCountry,
            resolvedProviderOrg,
            resolvedPublicBaseUrl,
            source,
            providerRegistered,
            consumerRegistered
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
        String consumerName,
        String providerName,
        String providerEmail,
        String providerCountry,
        String providerOrganization,
        String publicBaseUrl,
        String provisioningSource,
        boolean providerRegistered,
        boolean consumerRegistered
    ) {}

    private void ensureProviderRegistrationEnabled() {
        if (!providerRegistrationEnabled) {
            throw new IllegalStateException(
                "Provider registration is disabled in this deployment. Use the consumer provisioning flow from /wallet-dashboard instead."
            );
        }
    }

}
