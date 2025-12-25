package decentralabs.blockchain.service.organization;

import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
    private final RestTemplate restTemplate = new RestTemplate();

    /**
     * Register as consumer-only institution (grants INSTITUTION_ROLE only)
     * 
     * @param marketplaceUrl Marketplace base URL
     * @param apiKey Shared API key for authentication
     * @param organization schacHomeOrganization domain
     * @return true if registration successful, false otherwise
     */
    public boolean registerConsumer(
        String marketplaceUrl,
        String apiKey,
        String organization
    ) {
        String walletAddress = institutionalWalletService.getInstitutionalWalletAddress();
        if (walletAddress == null || walletAddress.isBlank()) {
            log.error("Consumer registration failed: institutional wallet address not available");
            return false;
        }

        try {
            log.info("Attempting to register as consumer-only institution...");
            log.info("Consumer details: wallet={}, organization={}", walletAddress, organization);

            doRegisterConsumer(marketplaceUrl, apiKey, walletAddress, organization);

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
        String apiKey,
        String walletAddress,
        String organization
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

        // Build headers with API key
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("x-api-key", apiKey);

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
                log.error("Consumer registration failed: Invalid API key");
                throw new RuntimeException("Invalid marketplace API key");
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
     */
    public boolean isConsumerRegistered() {
        // Could query the contract or marketplace API
        // For now, return false to allow manual check
        return false;
    }
}
