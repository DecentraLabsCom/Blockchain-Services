package decentralabs.blockchain.service.organization;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.dto.provider.ConsumerProvisioningTokenPayload;
import decentralabs.blockchain.dto.provider.ProvisioningTokenPayload;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import jakarta.annotation.Nonnull;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.math.BigInteger;
import java.net.URI;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Validates provisioning tokens (RS256) issued by Marketplace and extracts provider config
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ProvisioningTokenService {

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

    // Simple in-memory replay guard keyed by jti with expiration time
    private final Map<String, Instant> usedJti = new ConcurrentHashMap<>();

    /**
     * Validates provider provisioning token and extracts provider configuration
     */
    public ProvisioningTokenPayload validateAndExtract(String token, String configuredMarketplaceBaseUrl, String configuredPublicBaseUrl) {
        try {
            // Decode payload without verifying to get candidate marketplace base URL
            JsonNode headerNode = decodePart(token, 0);
            JsonNode payloadNode = decodePart(token, 1);

            String tokenMarketplaceBaseUrl = payloadNode.path("marketplaceBaseUrl").asText("");
            String marketplaceBaseUrl = resolveMarketplaceBaseUrl(configuredMarketplaceBaseUrl, tokenMarketplaceBaseUrl);
            String expectedAudience = resolveExpectedAudience(configuredPublicBaseUrl, payloadNode);

            String jwksUrl = marketplaceBaseUrl + "/api/institutions/provisionToken/jwks";
            JsonNode jwkSet = fetchJwkSet(jwksUrl);

            String kid = headerNode.path("kid").asText(null);
            PublicKey publicKey = selectRsaPublicKey(jwkSet, kid);

            JwtParser parser = Jwts.parser()
                .verifyWith(publicKey)
                .requireIssuer(marketplaceBaseUrl)
                .requireAudience(expectedAudience)
                .clockSkewSeconds(600)
                .build();

            Claims claims = parser.parseSignedClaims(token).getPayload();

            enforceReplayProtection(claims.getId(), claims.getExpiration().toInstant());

            ProvisioningTokenPayload payload = ProvisioningTokenPayload.builder()
                .marketplaceBaseUrl(validateHttps(marketplaceBaseUrl, "marketplace base URL"))
                .providerName(requireNonBlank(claims.get("providerName", String.class), "provider name"))
                .providerEmail(validateEmail(claims.get("providerEmail", String.class)))
                .providerCountry(requireNonBlank(claims.get("providerCountry", String.class), "provider country"))
                .providerOrganization(requireNonBlank(claims.get("providerOrganization", String.class), "provider organization"))
                .publicBaseUrl(validateHttps(claims.get("publicBaseUrl", String.class), "public base URL"))
                .jti(claims.getId())
                .build();

            // Ensure claim marketplace matches the trusted base
            String claimBase = claims.get("marketplaceBaseUrl", String.class);
            if (claimBase != null && !normalizeUrl(claimBase).equals(normalizeUrl(marketplaceBaseUrl))) {
                throw new IllegalArgumentException("Marketplace base URL mismatch");
            }

            return payload;
        } catch (IllegalArgumentException ex) {
            throw ex;
        } catch (Exception ex) {
            log.error("Failed to validate provisioning token: {}", ex.getMessage());
            throw new IllegalArgumentException("Invalid provisioning token");
        }
    }

    /**
     * Validates consumer provisioning token (consumer-only institutions, no labs)
     */
    public ConsumerProvisioningTokenPayload validateAndExtractConsumer(String token, String configuredMarketplaceBaseUrl, String configuredPublicBaseUrl) {
        try {
            // Decode payload without verifying to get candidate marketplace base URL
            JsonNode headerNode = decodePart(token, 0);
            JsonNode payloadNode = decodePart(token, 1);

            String type = payloadNode.path("type").asText("");
            if (!"consumer".equals(type)) {
                throw new IllegalArgumentException("Token is not a consumer provisioning token");
            }

            String tokenMarketplaceBaseUrl = payloadNode.path("marketplaceBaseUrl").asText("");
            String marketplaceBaseUrl = resolveMarketplaceBaseUrl(configuredMarketplaceBaseUrl, tokenMarketplaceBaseUrl);
            String expectedAudience = resolveExpectedAudience(configuredPublicBaseUrl, payloadNode);

            String jwksUrl = marketplaceBaseUrl + "/api/institutions/provisionConsumer/jwks";
            JsonNode jwkSet = fetchJwkSet(jwksUrl);

            String kid = headerNode.path("kid").asText(null);
            PublicKey publicKey = selectRsaPublicKey(jwkSet, kid);

            JwtParser parser = Jwts.parser()
                .verifyWith(publicKey)
                .requireIssuer(marketplaceBaseUrl)
                .requireAudience(expectedAudience)
                .clockSkewSeconds(600)
                .build();

            Claims claims = parser.parseSignedClaims(token).getPayload();

            enforceReplayProtection(claims.getId(), claims.getExpiration().toInstant());

            ConsumerProvisioningTokenPayload payload = ConsumerProvisioningTokenPayload.builder()
                .type("consumer")
                .marketplaceBaseUrl(validateHttps(marketplaceBaseUrl, "marketplace base URL"))
                .consumerName(requireNonBlank(claims.get("consumerName", String.class), "consumer name"))
                .consumerOrganization(requireNonBlank(claims.get("consumerOrganization", String.class), "consumer organization"))
                .jti(claims.getId())
                .build();

            // Ensure claim marketplace matches the trusted base
            String claimBase = claims.get("marketplaceBaseUrl", String.class);
            if (claimBase != null && !normalizeUrl(claimBase).equals(normalizeUrl(marketplaceBaseUrl))) {
                throw new IllegalArgumentException("Marketplace base URL mismatch");
            }

            return payload;
        } catch (IllegalArgumentException ex) {
            throw ex;
        } catch (Exception ex) {
            log.error("Failed to validate consumer provisioning token: {}", ex.getMessage());
            throw new IllegalArgumentException("Invalid consumer provisioning token");
        }
    }

    private JsonNode decodePart(String token, int index) throws Exception {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Malformed JWT");
        }
        String json = new String(Base64.getUrlDecoder().decode(parts[index]));
        return objectMapper.readTree(json);
    }

    private String resolveMarketplaceBaseUrl(String configured, String fromToken) {
        if (configured != null && !configured.isBlank()) {
            return normalizeUrl(configured);
        }
        if (fromToken == null || fromToken.isBlank()) {
            throw new IllegalArgumentException("Marketplace base URL is required (configure marketplace.base-url or include it in token)");
        }
        return normalizeUrl(fromToken);
    }

    private String resolveExpectedAudience(String configuredPublicBaseUrl, JsonNode payloadNode) {
        if (configuredPublicBaseUrl != null && !configuredPublicBaseUrl.isBlank()) {
            return normalizeUrl(configuredPublicBaseUrl);
        }

        JsonNode audNode = payloadNode.get("aud");
        if (audNode == null || audNode.isNull()) {
            throw new IllegalArgumentException("Token audience is required");
        }

        if (audNode.isTextual()) {
            return validateHttps(audNode.asText(), "token audience");
        }

        if (audNode.isArray()) {
            for (JsonNode value : audNode) {
                if (value != null && value.isTextual() && !value.asText().isBlank()) {
                    return validateHttps(value.asText(), "token audience");
                }
            }
        }

        throw new IllegalArgumentException("Token audience is required");
    }

    private String normalizeUrl(String url) {
        String trimmed = url.trim();
        if (trimmed.endsWith("/")) {
            return trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }

    private JsonNode fetchJwkSet(String jwksUrl) throws Exception {
        String normalized = requireNonBlank(jwksUrl, "jwksUrl");
        URI jwksUri = Objects.requireNonNull(URI.create(normalized), "jwksUri");
        ResponseEntity<String> response = restTemplate.getForEntity(jwksUri, String.class);
        if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null) {
            throw new IllegalArgumentException("Unable to fetch JWK set");
        }
        JsonNode root = objectMapper.readTree(response.getBody());
        if (!root.has("keys") || !root.get("keys").isArray()) {
            throw new IllegalArgumentException("Invalid JWK set format");
        }
        return root.get("keys");
    }

    private PublicKey selectRsaPublicKey(JsonNode keys, String kid) throws Exception {
        JsonNode selected = null;
        for (JsonNode key : keys) {
            boolean algOk = "RS256".equals(key.path("alg").asText("RS256"));
            boolean useOk = "sig".equals(key.path("use").asText("sig"));
            boolean kidOk = kid == null || Objects.equals(kid, key.path("kid").asText(null));
            if (algOk && useOk && kidOk) {
                selected = key;
                if (kidOk) break;
            }
        }
        if (selected == null) {
            throw new IllegalArgumentException("No suitable RSA key found in JWK set");
        }

        String n = selected.get("n").asText();
        String e = selected.get("e").asText();

        BigInteger modulus = new BigInteger(1, Decoders.BASE64URL.decode(n));
        BigInteger exponent = new BigInteger(1, Decoders.BASE64URL.decode(e));
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(keySpec);
    }

    private void enforceReplayProtection(String jti, Instant expiresAt) {
        if (jti == null || jti.isBlank()) {
            throw new IllegalArgumentException("Token missing jti");
        }
        Instant now = Instant.now();
        usedJti.entrySet().removeIf(entry -> entry.getValue().isBefore(now));
        Instant existing = usedJti.get(jti);
        if (existing != null && existing.isAfter(now)) {
            throw new IllegalArgumentException("Provisioning token already used");
        }
        usedJti.put(jti, Optional.ofNullable(expiresAt).orElse(now.plusSeconds(600)));
    }

    private String validateHttps(String url, String label) {
        String value = requireNonBlank(url, label);
        String normalized = normalizeUrl(value);
        if (!normalized.startsWith("https://") && !normalized.startsWith("http://")) {
            throw new IllegalArgumentException(label + " must start with http:// or https://");
        }
        return normalized;
    }

    private String validateEmail(String email) {
        String value = requireNonBlank(email, "provider email");
        if (!value.matches("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$")) {
            throw new IllegalArgumentException("Invalid provider email");
        }
        return value;
    }

    private @Nonnull String requireNonBlank(String value, String label) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Missing " + label);
        }
        return Objects.requireNonNull(value.trim(), "trimmed value");
    }
}
