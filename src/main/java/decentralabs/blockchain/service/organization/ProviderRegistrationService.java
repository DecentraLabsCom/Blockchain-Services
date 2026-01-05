package decentralabs.blockchain.service.organization;

import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

/**
 * Service to automatically register blockchain-services as a provider on startup
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ProviderRegistrationService {

    private final InstitutionalWalletService institutionalWalletService;
    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

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

    /**
     * Register provider with marketplace using provided configuration
     * Called manually from ProviderConfigurationController after user submits form
     * 
     * @return true if registration successful, false otherwise
     */
    public boolean registerProvider(
        String marketplaceUrl,
        String name,
        String email,
        String country,
        String organization,
        String baseUrl,
        String provisioningToken
    ) {
        String walletAddress = institutionalWalletService.getInstitutionalWalletAddress();
        if (walletAddress == null || walletAddress.isBlank()) {
            log.error("Provider registration failed: institutional wallet address not available");
            return false;
        }
        if (provisioningToken == null || provisioningToken.isBlank()) {
            log.error("Provider registration failed: provisioning token is required");
            return false;
        }

        String authURI = baseUrl.trim();
        if (authURI.endsWith("/")) {
            authURI = authURI.substring(0, authURI.length() - 1);
        }

        if (!authURI.startsWith("https://") && !authURI.startsWith("http://")) {
            log.error("Provider registration failed: public.base-url must start with http:// or https://");
            return false;
        }

        String backendUrl = normalizeBackendUrl(authURI);

        try {
            log.info("Attempting to register as provider with marketplace...");
            log.info("Provider details: name={}, wallet={}, organization={}, authURI={}", 
                name, walletAddress, organization, authURI);

            doRegisterProvider(marketplaceUrl, provisioningToken, walletAddress, name, email, country, organization, authURI, backendUrl);

            log.info("Provider registration completed successfully");
            return true;
        } catch (Exception e) {
            log.error("Provider registration failed: {}", e.getMessage(), e);
            return false;
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
        String backendUrl
    ) {
        String url = marketplaceUrl.trim();
        if (url.endsWith("/")) {
            url = url.substring(0, url.length() - 1);
        }
        url += "/api/institutions/registerProvider";

        // Build request body
        Map<String, String> requestBody = new HashMap<>();
        requestBody.put("name", name.trim());
        requestBody.put("walletAddress", walletAddress);
        requestBody.put("email", email.trim());
        requestBody.put("country", country.trim());
        requestBody.put("authURI", authURI);
        requestBody.put("organization", organization.trim());
        if (backendUrl != null && !backendUrl.isBlank()) {
            requestBody.put("backendUrl", backendUrl);
        }

        // Build headers with provisioning token
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(provisioningToken.trim());

        HttpEntity<Map<String, String>> request = new HttpEntity<>(requestBody, headers);

        try {
            ResponseEntity<String> response = restTemplate.exchange(
                url,
                HttpMethod.POST,
                request,
                String.class
            );

            if (response.getStatusCode() == HttpStatus.CREATED || response.getStatusCode() == HttpStatus.OK) {
                log.info("Provider registration successful: {}", response.getBody());
            } else {
                log.warn("Provider registration returned unexpected status: {} - {}", 
                    response.getStatusCode(), response.getBody());
            }
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode() == HttpStatus.CONFLICT || e.getStatusCode() == HttpStatus.OK) {
                log.info("Provider already registered (expected on subsequent startups)");
            } else if (e.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                log.error("Provider registration failed: Unauthorized (invalid provisioning token)");
                throw new RuntimeException("Invalid provisioning token");
            } else {
                log.error("Provider registration failed with status {}: {}", 
                    e.getStatusCode(), e.getResponseBodyAsString());
                throw e;
            }
        } catch (Exception e) {
            log.error("Provider registration request failed: {}", e.getMessage());
            throw new RuntimeException("Failed to communicate with marketplace", e);
        }
    }

    /**
     * Check if provider is registered
     */
    public boolean isProviderRegistered() {
        // This could query the contract or marketplace API
        // For now, we'll just return true if configuration is complete
        return marketplaceBaseUrl != null && !marketplaceBaseUrl.isBlank()
            && providerName != null && !providerName.isBlank();
    }

    private String normalizeBackendUrl(String authURI) {
        if (authURI == null) {
            return null;
        }

        String trimmed = authURI.trim();
        if (trimmed.isEmpty()) {
            return null;
        }

        while (trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }

        if (trimmed.endsWith("/auth")) {
            trimmed = trimmed.substring(0, trimmed.length() - 5);
        }

        if (!trimmed.startsWith("https://") && !trimmed.startsWith("http://")) {
            return null;
        }

        return trimmed;
    }
}
