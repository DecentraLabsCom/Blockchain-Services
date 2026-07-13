package decentralabs.blockchain.service.organization;

import decentralabs.blockchain.service.billing.InstitutionalAdminService;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

/**
 * Unified service for institution registration with the DecentraLabs Marketplace.
 * Handles both PROVIDER and CONSUMER registration flows.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class InstitutionRegistrationService {

    private final InstitutionalAdminService institutionalAdminService;
    private final InstitutionalWalletService institutionalWalletService;
    private final ProviderConfigurationPersistenceService configPersistenceService;
    private final RestTemplate restTemplate;

    /**
     * Register institution with marketplace based on role
     * 
     * @param request Registration request with role and required fields
     * @return true if registration successful, false otherwise
     */
    public boolean register(InstitutionRegistrationRequest request) {
        log.info("Registering institution as {} with marketplace", request.getRole());
        
        switch (request.getRole()) {
            case PROVIDER:
                return registerAsProvider(request);
            case CONSUMER:
                return registerAsConsumer(request);
            default:
                log.error("Unknown institution role: {}", request.getRole());
                return false;
        }
    }

    /**
     * Check if institution is registered for given role
     * 
     * @param role Role to check (PROVIDER or CONSUMER)
     * @return true if registered, false otherwise
     */
    public boolean isRegistered(InstitutionRole role) {
        try {
            Properties props = configPersistenceService.loadConfigurationSafe();
            String flag = role.getRegisteredFlag();
            return "true".equalsIgnoreCase(props.getProperty(flag, "false"));
        } catch (Exception e) {
            log.warn("Unable to check {} registration status: {}", role, e.getMessage());
            return false;
        }
    }

    /**
     * Mark institution as registered in configuration file
     * 
     * @param role Role to mark as registered
     * @throws IOException if unable to write to configuration file
     */
    public void markAsRegistered(InstitutionRole role) throws IOException {
        log.info("Marking institution as registered for role: {}", role);
        configPersistenceService.markAsRegistered(role);
    }

    /**
     * Get registration status from configuration for given role
     * 
     * @param role Role to check
     * @return true if configuration flag is set to true
     */
    public boolean getRegistrationStatus(InstitutionRole role) {
        try {
            Properties props = configPersistenceService.loadConfigurationSafe();
            String flag = role.getRegisteredFlag();
            return "true".equalsIgnoreCase(props.getProperty(flag, "false"));
        } catch (Exception e) {
            log.warn("Unable to check {} registration status: {}", role, e.getMessage());
            return false;
        }
    }

    /**
     * Register as provider institution
     */
    private boolean registerAsProvider(InstitutionRegistrationRequest request) {
        validateProviderRequest(request);
        
        String walletAddress = institutionalWalletService.getInstitutionalWalletAddress();
        if (walletAddress == null || walletAddress.isBlank()) {
            log.error("Provider registration failed: institutional wallet address not available");
            return false;
        }
        if (!walletAddress.equalsIgnoreCase(request.getWalletAddress())) {
            log.error("Provider registration failed: token wallet does not match institutional wallet");
            return false;
        }

        String authURI = request.getPublicBaseUrl().trim();
        if (authURI.endsWith("/")) {
            authURI = authURI.substring(0, authURI.length() - 1);
        }

        if (!authURI.startsWith("https://") && !authURI.startsWith("http://")) {
            log.error("Provider registration failed: public.base-url must start with http:// or https://");
            return false;
        }

        String backendUrl = normalizeBackendUrl(authURI);

        try {
            Credentials credentials = institutionalWalletService.getInstitutionalCredentials();
            if (!credentials.getAddress().equalsIgnoreCase(walletAddress)) {
                throw new IllegalStateException("Institutional credentials do not match configured wallet");
            }
            String walletSignature = signProviderRegistrationChallenge(request, walletAddress, authURI, credentials);
            log.info("Attempting to register as provider with marketplace...");
            log.info("Provider details: name={}, wallet={}, organization={}, authURI={}", 
                request.getName(), walletAddress, request.getOrganization(), authURI);

            doRegisterProvider(
                request.getMarketplaceUrl(),
                request.getProvisioningToken(),
                walletAddress,
                request.getName(),
                request.getEmail(),
                request.getCountry(),
                request.getOrganization(),
                authURI,
                backendUrl,
                walletSignature
            );

            log.info("Provider registration completed successfully");
            alignSpendingPeriodWithRegistration(InstitutionRole.PROVIDER);
            markAsRegistered(InstitutionRole.PROVIDER);
            return true;
        } catch (Exception e) {
            log.error("Provider registration failed: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * Register as consumer-only institution
     */
    private boolean registerAsConsumer(InstitutionRegistrationRequest request) {
        validateConsumerRequest(request);
        
        String walletAddress = institutionalWalletService.getInstitutionalWalletAddress();
        if (walletAddress == null || walletAddress.isBlank()) {
            log.error("Consumer registration failed: institutional wallet address not available");
            return false;
        }

        try {
            log.info("Attempting to register as consumer-only institution...");
            log.info("Consumer details: wallet={}, organization={}", walletAddress, request.getOrganization());

            String backendUrl = normalizeBackendUrl(request.getPublicBaseUrl());
            doRegisterConsumer(
                request.getMarketplaceUrl(),
                request.getProvisioningToken(),
                walletAddress,
                request.getOrganization(),
                backendUrl
            );

            log.info("Consumer registration completed successfully");
            alignSpendingPeriodWithRegistration(InstitutionRole.CONSUMER);
            markAsRegistered(InstitutionRole.CONSUMER);
            return true;
        } catch (Exception e) {
            log.error("Consumer registration failed: {}", e.getMessage(), e);
            return false;
        }
    }

    private void alignSpendingPeriodWithRegistration(InstitutionRole role) {
        try {
            institutionalAdminService.resetSpendingPeriodAfterRegistration();
            log.info("Aligned institutional spending period anchor with {} registration", role);
        } catch (Exception e) {
            log.warn("{} registration succeeded but spending period anchor reset failed: {}", role, e.getMessage());
        }
    }

    /**
     * Internal method to perform provider registration with marketplace
     */
    private void doRegisterProvider(
        String marketplaceUrl,
        String provisioningToken,
        String walletAddress,
        String name,
        String email,
        String country,
        String organization,
        String authURI,
        String backendUrl,
        String walletSignature
    ) {
        String url = buildMarketplaceUrl(marketplaceUrl, "/api/institutions/registerProvider");

        // Build request body
        Map<String, String> requestBody = new HashMap<>();
        requestBody.put("name", name.trim());
        requestBody.put("walletAddress", walletAddress);
        requestBody.put("email", email.trim());
        requestBody.put("country", country.trim());
        requestBody.put("authURI", authURI);
        requestBody.put("organization", organization.trim());
        requestBody.put("walletSignature", walletSignature);
        if (backendUrl != null && !backendUrl.isBlank()) {
            requestBody.put("backendUrl", backendUrl);
        }

        sendRegistrationRequest(url, provisioningToken, requestBody, "Provider");
    }

    /**
     * Internal method to perform consumer registration with marketplace
     */
    private void doRegisterConsumer(
        String marketplaceUrl,
        String provisioningToken,
        String walletAddress,
        String organization,
        String backendUrl
    ) {
        String url = buildMarketplaceUrl(marketplaceUrl, "/api/institutions/registerConsumer");

        // Build request body
        Map<String, String> requestBody = new HashMap<>();
        requestBody.put("walletAddress", walletAddress);
        requestBody.put("organization", organization.trim());
        if (backendUrl != null && !backendUrl.isBlank()) {
            requestBody.put("backendUrl", backendUrl);
        }

        sendRegistrationRequest(url, provisioningToken, requestBody, "Consumer");
    }

    /**
     * Send registration request to marketplace
     */
    private void sendRegistrationRequest(String url, String provisioningToken, Map<String, String> requestBody, String roleLabel) {
        if (provisioningToken == null || provisioningToken.isBlank()) {
            throw new IllegalArgumentException("Provisioning token is required");
        }
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException("Marketplace URL is required");
        }
        // Build headers with provisioning token
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        String trimmedToken = Objects.requireNonNull(provisioningToken.trim(), "provisioningToken");
        headers.setBearerAuth(trimmedToken);

        HttpEntity<Map<String, String>> request = new HttpEntity<>(requestBody, headers);

        try {
            ResponseEntity<String> response = restTemplate.postForEntity(
                url,
                request,
                String.class
            );

            if (response.getStatusCode() == HttpStatus.CREATED || response.getStatusCode() == HttpStatus.OK) {
                log.info("{} registration successful: {}", roleLabel, response.getBody());
            } else {
                log.warn("{} registration returned unexpected status: {} - {}", 
                    roleLabel, response.getStatusCode(), response.getBody());
            }
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                log.error("{} registration failed: Unauthorized (invalid provisioning token)", roleLabel);
                throw new RuntimeException("Invalid provisioning token");
            } else {
                log.error("{} registration failed with status {}: {}", 
                    roleLabel, e.getStatusCode(), e.getResponseBodyAsString());
                throw e;
            }
        } catch (Exception e) {
            log.error("{} registration request failed: {}", roleLabel, e.getMessage());
            throw new RuntimeException("Failed to communicate with marketplace", e);
        }
    }

    /**
     * Build marketplace URL with endpoint
     */
    private String buildMarketplaceUrl(String marketplaceUrl, String endpoint) {
        if (marketplaceUrl == null || marketplaceUrl.isBlank()) {
            throw new IllegalArgumentException("Marketplace URL is required");
        }
        String url = marketplaceUrl.trim();
        if (url.endsWith("/")) {
            url = url.substring(0, url.length() - 1);
        }
        return url + endpoint;
    }

    /**
     * Normalize backend URL
     */
    private String normalizeBackendUrl(String baseUrl) {
        if (baseUrl == null) {
            return null;
        }

        String trimmed = baseUrl.trim();
        if (trimmed.isEmpty()) {
            return null;
        }

        if (trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }

        return trimmed + "/api";
    }

    private String signProviderRegistrationChallenge(
        InstitutionRegistrationRequest request,
        String walletAddress,
        String publicBaseUrl,
        Credentials credentials
    ) {
        String challenge = String.join("\n",
            "DecentraLabs Provider Registration v1",
            "jti=" + request.getProvisioningJti(),
            "registrationNonce=" + request.getRegistrationNonce(),
            "walletAddress=" + walletAddress.toLowerCase(Locale.ROOT),
            "providerOrganization=" + request.getOrganization().trim().toLowerCase(Locale.ROOT),
            "publicBaseUrl=" + publicBaseUrl,
            "chainId=" + request.getChainId(),
            "verifyingContract=" + request.getVerifyingContract().toLowerCase(Locale.ROOT)
        );
        Sign.SignatureData signature = Sign.signPrefixedMessage(
            challenge.getBytes(StandardCharsets.UTF_8), credentials.getEcKeyPair()
        );
        byte[] encoded = new byte[65];
        System.arraycopy(signature.getR(), 0, encoded, 0, 32);
        System.arraycopy(signature.getS(), 0, encoded, 32, 32);
        System.arraycopy(signature.getV(), 0, encoded, 64, 1);
        return Numeric.toHexString(encoded);
    }

    /**
     * Validate required fields for provider registration
     */
    private void validateProviderRequest(InstitutionRegistrationRequest request) {
        if (request.getName() == null || request.getName().isBlank()) {
            throw new IllegalArgumentException("Provider name is required");
        }
        if (request.getEmail() == null || request.getEmail().isBlank()) {
            throw new IllegalArgumentException("Provider email is required");
        }
        if (request.getCountry() == null || request.getCountry().isBlank()) {
            throw new IllegalArgumentException("Provider country is required");
        }
        if (request.getPublicBaseUrl() == null || request.getPublicBaseUrl().isBlank()) {
            throw new IllegalArgumentException("Provider public base URL is required");
        }
        if (request.getWalletAddress() == null || !request.getWalletAddress().matches("^0x[a-fA-F0-9]{40}$")) {
            throw new IllegalArgumentException("Provider token wallet address is required");
        }
        if (request.getProvisioningJti() == null || request.getProvisioningJti().isBlank()) {
            throw new IllegalArgumentException("Provider token jti is required");
        }
        if (request.getRegistrationNonce() == null || request.getRegistrationNonce().isBlank()) {
            throw new IllegalArgumentException("Provider registration nonce is required");
        }
        if (request.getChainId() == null || request.getChainId() <= 0) {
            throw new IllegalArgumentException("Provider token chain ID is required");
        }
        if (request.getVerifyingContract() == null
            || !request.getVerifyingContract().matches("^0x[a-fA-F0-9]{40}$")) {
            throw new IllegalArgumentException("Provider token verifying contract is required");
        }
        validateCommonFields(request);
    }

    /**
     * Validate required fields for consumer registration
     */
    private void validateConsumerRequest(InstitutionRegistrationRequest request) {
        validateCommonFields(request);
    }

    /**
     * Validate fields required for both roles
     */
    private void validateCommonFields(InstitutionRegistrationRequest request) {
        if (request.getMarketplaceUrl() == null || request.getMarketplaceUrl().isBlank()) {
            throw new IllegalArgumentException("Marketplace URL is required");
        }
        if (request.getOrganization() == null || request.getOrganization().isBlank()) {
            throw new IllegalArgumentException("Organization is required");
        }
        if (request.getProvisioningToken() == null || request.getProvisioningToken().isBlank()) {
            throw new IllegalArgumentException("Provisioning token is required");
        }
    }
}
