package decentralabs.blockchain.service.organization;

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
 * Service to register blockchain-services as CONSUMER-ONLY institution
 * (only reserves labs, does not publish)
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ConsumerRegistrationService {

    private final InstitutionalWalletService institutionalWalletService;
    private final ProviderConfigurationPersistenceService configPersistenceService;
    private final RestTemplate restTemplate = new RestTemplate();

    @Value("${public.base-url:}")
    private String publicBaseUrl;

    /**
     * Register as consumer-only institution (grants INSTITUTION_ROLE only)
     * 
     * @param marketplaceUrl Marketplace base URL
     * @param organization schacHomeOrganization domain
     * @param provisioningToken Provisioning token for authentication
     * @return true if registration successful, false otherwise
     */
    public boolean registerConsumer(
        String marketplaceUrl,
        String organization,
        String provisioningToken
    ) {
        String walletAddress = institutionalWalletService.getInstitutionalWalletAddress();
        if (walletAddress == null || walletAddress.isBlank()) {
            log.error("Consumer registration failed: institutional wallet address not available");
            return false;
        }
        if (provisioningToken == null || provisioningToken.isBlank()) {
            log.error("Consumer registration failed: provisioning token is required");
            return false;
        }

        try {
            log.info("Attempting to register as consumer-only institution...");
            log.info("Consumer details: wallet={}, organization={}", walletAddress, organization);

            String backendUrl = normalizeBackendUrl(publicBaseUrl);
            doRegisterConsumer(marketplaceUrl, provisioningToken, walletAddress, organization, backendUrl);

            log.info("Consumer registration completed successfully");
            return true;
        } catch (Exception e) {
            log.error("Consumer registration failed: {}", e.getMessage(), e);
            return false;
        }
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
        String url = marketplaceUrl.trim();
        if (url.endsWith("/")) {
            url = url.substring(0, url.length() - 1);
        }
        url += "/api/institutions/registerConsumer";

        // Build request body
        Map<String, String> requestBody = new HashMap<>();
        requestBody.put("walletAddress", walletAddress);
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
                log.info("Consumer registration successful: {}", response.getBody());
            } else {
                log.warn("Consumer registration returned unexpected status: {} - {}", 
                    response.getStatusCode(), response.getBody());
            }
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode() == HttpStatus.CONFLICT || e.getStatusCode() == HttpStatus.OK) {
                log.info("Consumer already registered (expected on subsequent startups)");
            } else if (e.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                log.error("Consumer registration failed: Unauthorized (invalid provisioning token)");
                throw new RuntimeException("Invalid provisioning token");
            } else {
                log.error("Consumer registration failed with status {}: {}", 
                    e.getStatusCode(), e.getResponseBodyAsString());
                throw e;
            }
        } catch (Exception e) {
            log.error("Consumer registration request failed: {}", e.getMessage());
            throw new RuntimeException("Failed to communicate with marketplace", e);
        }
    }

    /**
     * Check if consumer is registered
     * Reads from configuration file to check if consumer.registered=true
     */
    public boolean isConsumerRegistered() {
        try {
            var props = configPersistenceService.loadConfigurationSafe();
            return "true".equalsIgnoreCase(props.getProperty("consumer.registered", "false"));
        } catch (Exception e) {
            log.warn("Unable to check consumer registration status: {}", e.getMessage());
            return false;
        }
    }

    private String normalizeBackendUrl(String baseUrl) {
        if (baseUrl == null) {
            return null;
        }

        String trimmed = baseUrl.trim();
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
