package decentralabs.blockchain.service.auth;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

/**
 * Service for managing marketplace public keys
 */
@Service
@Slf4j
public class MarketplaceKeyService {

    @Value("${marketplace.public-key-url}")
    private String marketplacePublicKeyUrl;

    @Value("${marketplace.key.cache-ms:3600000}")
    private long keyCacheDurationMs;

    private final RestTemplate restTemplate = new RestTemplate();

    private volatile PublicKey cachedMarketplacePublicKey = null;
    private volatile long lastKeyFetchTime = 0;

    /**
     * Gets the marketplace public key, using cache if available
     *
     * @param forceRefresh Force fetching a new key from the server
     * @return Public key for marketplace JWT verification
     * @throws Exception if key fetch or parsing fails
     */
    public PublicKey getPublicKey(boolean forceRefresh) throws Exception {
        long currentTime = System.currentTimeMillis();

        if (forceRefresh || cachedMarketplacePublicKey == null
            || (currentTime - lastKeyFetchTime) > keyCacheDurationMs) {

            String publicKeyPEM = fetchPublicKeyFromUrl();
            cachedMarketplacePublicKey = parsePublicKey(publicKeyPEM);
            lastKeyFetchTime = currentTime;
            log.info("Marketplace public key refreshed successfully");
        }

        return cachedMarketplacePublicKey;
    }

    private String fetchPublicKeyFromUrl() throws Exception {
        try {
            ResponseEntity<String> response =
                restTemplate.getForEntity(marketplacePublicKeyUrl, String.class);

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                return response.getBody();
            }
            throw new Exception("Failed to fetch public key. Status: " + response.getStatusCode());
        } catch (Exception e) {
            log.error("Error fetching marketplace public key from {}: {}",
                marketplacePublicKeyUrl, e.getMessage(), e);
            throw new Exception("Could not fetch marketplace public key: " + e.getMessage(), e);
        }
    }

    private PublicKey parsePublicKey(String publicKeyPEM) throws Exception {
        String publicKeyContent = publicKeyPEM
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(publicKeyContent);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    public boolean isKeyAvailable() {
        return cachedMarketplacePublicKey != null;
    }
}

