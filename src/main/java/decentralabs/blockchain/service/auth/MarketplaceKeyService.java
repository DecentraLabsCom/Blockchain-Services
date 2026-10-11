package decentralabs.blockchain.service.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

/**
 * Loads and caches the Marketplace JWT verification key set.
 *
 * The Marketplace publishes the active key first and keeps the previous key
 * during a rotation. A token's protected-header kid selects the correct key;
 * an unknown kid causes one immediate refresh so a deployment never has to
 * wait for the normal cache TTL.
 */
@Service
@Slf4j
public class MarketplaceKeyService {

    private static final String RSA_ALGORITHM = "RSA";
    private static final String JWT_ALGORITHM = "RS256";

    @Value("${marketplace.public-key-url:}")
    private String marketplacePublicKeyUrl;

    @Value("${marketplace.key.cache-ms:3600000}")
    private long keyCacheDurationMs;

    @Value("${marketplace.key.retry-ms:60000}")
    private long keyRetryMs;

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

    private volatile Map<String, PublicKey> cachedMarketplacePublicKeys = Collections.emptyMap();
    private volatile long lastKeyFetchTime = 0;
    private volatile long lastFailureTime = 0;

    /** Gets the first Marketplace key, preserving the legacy API. */
    public PublicKey getPublicKey(boolean forceRefresh) throws Exception {
        return getPublicKey(null, forceRefresh);
    }

    /**
     * Gets a Marketplace public key by its JWKS kid. An unknown kid triggers
     * one immediate refresh so key rotation is not gated by the cache TTL.
     */
    public PublicKey getPublicKey(String kid, boolean forceRefresh) throws Exception {
        Map<String, PublicKey> keys = getPublicKeys(forceRefresh);
        if (kid == null || kid.isBlank()) {
            return firstKey(keys);
        }

        PublicKey key = keys.get(kid);
        if (key != null) {
            return key;
        }

        keys = getPublicKeys(true);
        key = keys.get(kid);
        if (key == null) {
            throw new Exception("No Marketplace public key found for kid: " + kid);
        }
        return key;
    }

    /** Selects the verification key using the JWT protected-header kid. */
    public PublicKey getPublicKeyForToken(String token, boolean forceRefresh) throws Exception {
        return getPublicKey(extractKeyId(token), forceRefresh);
    }

    /** Returns the cached JWKS, refreshing it when forced or expired. */
    public synchronized Map<String, PublicKey> getPublicKeys(boolean forceRefresh) throws Exception {
        long now = System.currentTimeMillis();
        boolean expired = cachedMarketplacePublicKeys.isEmpty()
            || now - lastKeyFetchTime > keyCacheDurationMs;

        if (forceRefresh || expired) {
            String keySetResponse = fetchPublicKeyFromUrl();
            Map<String, PublicKey> loadedKeys = parseKeySet(keySetResponse);
            cachedMarketplacePublicKeys = loadedKeys;
            lastKeyFetchTime = now;
            lastFailureTime = 0;
            log.info("Marketplace verification key set refreshed successfully ({} keys)", loadedKeys.size());
        }

        return cachedMarketplacePublicKeys;
    }

    /**
     * Extracts kid without trusting any claims. JJWT still verifies the
     * signature after the key has been selected.
     */
    public String extractKeyId(String token) throws Exception {
        if (token == null || token.isBlank()) {
            throw new Exception("Marketplace JWT is empty");
        }

        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) {
            throw new Exception("Marketplace JWT has an invalid compact structure");
        }

        JsonNode header = objectMapper.readTree(Base64.getUrlDecoder().decode(parts[0]));
        if (header == null || !JWT_ALGORITHM.equals(header.path("alg").asText())) {
            throw new Exception("Marketplace JWT uses an unsupported signing algorithm");
        }
        JsonNode kid = header.get("kid");
        return kid == null || kid.isNull() || kid.asText().isBlank() ? null : kid.asText();
    }

    /** Ensures a key set is present, retrying after a failed fetch if needed. */
    public boolean ensureKey(boolean forceRefresh) {
        long now = System.currentTimeMillis();
        boolean shouldRetry = cachedMarketplacePublicKeys.isEmpty()
            || now - lastKeyFetchTime > keyCacheDurationMs
            || (lastFailureTime > 0 && now - lastFailureTime > keyRetryMs);
        if (forceRefresh || shouldRetry) {
            try {
                getPublicKeys(forceRefresh);
                return true;
            } catch (Exception e) {
                lastFailureTime = now;
                log.debug("Marketplace public key availability check failed", e);
                return false;
            }
        }
        return true;
    }

    private PublicKey firstKey(Map<String, PublicKey> keys) throws Exception {
        if (keys.isEmpty()) {
            throw new Exception("Marketplace public key set is empty");
        }
        return keys.values().iterator().next();
    }

    private String fetchPublicKeyFromUrl() throws Exception {
        String publicKeyUrl = marketplacePublicKeyUrl;
        try {
            if (publicKeyUrl == null || publicKeyUrl.isBlank()) {
                throw new Exception("Marketplace public key URL is not configured");
            }
            ResponseEntity<String> response = restTemplate.getForEntity(publicKeyUrl, String.class);

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                return response.getBody();
            }
            throw new Exception("Failed to fetch public key. Status: " + response.getStatusCode());
        } catch (Exception e) {
            log.error("Error fetching marketplace public key set from {}: {}",
                publicKeyUrl, e.getMessage(), e);
            throw new Exception("Could not fetch marketplace public key: " + e.getMessage(), e);
        }
    }

    private Map<String, PublicKey> parseKeySet(String response) throws Exception {
        if (response == null || response.isBlank()) {
            throw new Exception("Marketplace public key response is empty");
        }

        String trimmed = response.trim();
        if (!trimmed.startsWith("{")) {
            PublicKey publicKey = parsePublicKey(trimmed);
            return singletonKeySet(publicKey);
        }

        JsonNode root = objectMapper.readTree(trimmed);
        JsonNode keys = root == null ? null : root.get("keys");
        if (keys == null || !keys.isArray()) {
            throw new Exception("Marketplace JWKS response does not contain a keys array");
        }

        Map<String, PublicKey> parsed = new LinkedHashMap<>();
        for (JsonNode jwk : keys) {
            if (jwk == null || !"RSA".equals(jwk.path("kty").asText())
                || (jwk.has("alg") && !JWT_ALGORITHM.equals(jwk.path("alg").asText()))
                || (jwk.has("use") && !"sig".equals(jwk.path("use").asText()))) {
                continue;
            }
            String modulus = jwk.path("n").asText(null);
            String exponent = jwk.path("e").asText(null);
            if (modulus == null || exponent == null) {
                continue;
            }

            PublicKey publicKey = parseJwk(modulus, exponent);
            String kid = jwk.path("kid").asText(null);
            if (kid == null || kid.isBlank()) {
                kid = keyId(publicKey);
            }
            parsed.putIfAbsent(kid, publicKey);
        }

        if (parsed.isEmpty()) {
            throw new Exception("Marketplace JWKS response contains no supported RSA signing keys");
        }
        return Collections.unmodifiableMap(parsed);
    }

    private Map<String, PublicKey> singletonKeySet(PublicKey publicKey) {
        return Collections.singletonMap(keyId(publicKey), publicKey);
    }

    private PublicKey parseJwk(String modulus, String exponent) throws Exception {
        byte[] modulusBytes = Base64.getUrlDecoder().decode(modulus);
        byte[] exponentBytes = Base64.getUrlDecoder().decode(exponent);
        RSAPublicKeySpec spec = new RSAPublicKeySpec(
            new BigInteger(1, modulusBytes),
            new BigInteger(1, exponentBytes));
        return KeyFactory.getInstance(RSA_ALGORITHM).generatePublic(spec);
    }

    private PublicKey parsePublicKey(String publicKeyPEM) throws Exception {
        if (!publicKeyPEM.contains("-----BEGIN PUBLIC KEY-----")
            || !publicKeyPEM.contains("-----END PUBLIC KEY-----")) {
            throw new Exception("Invalid Marketplace public key PEM format");
        }

        String publicKeyContent = publicKeyPEM
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(publicKeyContent);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance(RSA_ALGORITHM).generatePublic(spec);
    }

    private String keyId(PublicKey publicKey) {
        if (!(publicKey instanceof RSAPublicKey rsaPublicKey)) {
            throw new IllegalArgumentException("Marketplace verification key must be RSA");
        }

        String modulus = base64UrlUnsigned(rsaPublicKey.getModulus());
        String exponent = base64UrlUnsigned(rsaPublicKey.getPublicExponent());
        String canonicalJwk = "{\"e\":\"" + exponent
            + "\",\"kty\":\"RSA\",\"n\":\"" + modulus + "\"}";
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(canonicalJwk.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to calculate Marketplace key id", e);
        }
    }

    private String base64UrlUnsigned(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            byte[] unsigned = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, unsigned, 0, unsigned.length);
            bytes = unsigned;
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public boolean isKeyAvailable() {
        return !cachedMarketplacePublicKeys.isEmpty();
    }
}
