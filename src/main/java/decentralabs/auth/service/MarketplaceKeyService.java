package decentralabs.auth.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Service for managing marketplace public keys
 */
@Service
public class MarketplaceKeyService {
    
    @Value("${marketplace.public-key-url}")
    private String marketplacePublicKeyUrl;
    
    private PublicKey cachedMarketplacePublicKey = null;
    private long lastKeyFetchTime = 0;
    private static final long KEY_CACHE_DURATION = 3600000; // 1 hour in milliseconds
    
    /**
     * Gets the marketplace public key, using cache if available
     * 
     * @param forceRefresh Force fetching a new key from the server
     * @return Public key for marketplace JWT verification
     * @throws Exception if key fetch or parsing fails
     */
    public PublicKey getPublicKey(boolean forceRefresh) throws Exception {
        long currentTime = System.currentTimeMillis();
        
        // Check if we need to fetch a new key
        if (forceRefresh || cachedMarketplacePublicKey == null || 
            (currentTime - lastKeyFetchTime) > KEY_CACHE_DURATION) {
            
            String publicKeyPEM = fetchPublicKeyFromUrl();
            cachedMarketplacePublicKey = parsePublicKey(publicKeyPEM);
            lastKeyFetchTime = currentTime;
        }
        
        return cachedMarketplacePublicKey;
    }
    
    /**
     * Fetches the public key from the marketplace URL
     */
    private String fetchPublicKeyFromUrl() throws Exception {
        try {
            RestTemplate restTemplate = new RestTemplate();
            ResponseEntity<String> response = restTemplate.getForEntity(marketplacePublicKeyUrl, String.class);
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                return response.getBody();
            } else {
                throw new Exception("Failed to fetch public key from marketplace. Status: " + response.getStatusCode());
            }
        } catch (Exception e) {
            System.err.println("Error fetching marketplace public key: " + e.getMessage());
            throw new Exception("Could not fetch marketplace public key: " + e.getMessage(), e);
        }
    }
    
    /**
     * Parses a PEM-formatted public key string into a PublicKey object
     */
    private PublicKey parsePublicKey(String publicKeyPEM) throws Exception {
        // Remove PEM header/footer and whitespace
        String publicKeyContent = publicKeyPEM
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        
        // Decode Base64
        byte[] keyBytes = Base64.getDecoder().decode(publicKeyContent);
        
        // Generate PublicKey object
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }
    
    /**
     * Checks if a marketplace key is currently available
     */
    public boolean isKeyAvailable() {
        return cachedMarketplacePublicKey != null;
    }
}
