package decentralabs.blockchain.service.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.http.ResponseEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import decentralabs.blockchain.util.PucHashUtil;

/**
 * Independently validates external OIDC ID tokens before an institutional
 * session is issued. Only the configured Entra provider is enabled today;
 * the provider-neutral boundary allows CILogon and other OIDC providers to
 * use the same validation contract later.
 */
@Service
public class ExternalOidcTokenValidationService {

    private static final String ENTRA_PROVIDER = "entra-id";
    private static final String SUPPORTED_ALGORITHM = "RS256";

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;
    private final boolean enabled;
    private final Set<String> issuers;
    private final Set<String> audiences;
    private final Set<String> allowedTenants;
    private final String jwksUrl;
    private final long clockSkewSeconds;
    private final Map<String, CachedKeys> keyCache = new ConcurrentHashMap<>();

    @Autowired
    public ExternalOidcTokenValidationService(
        RestTemplate restTemplate,
        ObjectMapper objectMapper,
        @Value("${identity.oidc.entra.enabled:false}") boolean enabled,
        @Value("${identity.oidc.entra.issuers:}") String issuers,
        @Value("${identity.oidc.entra.audiences:}") String audiences,
        @Value("${identity.oidc.entra.jwks-url:}") String jwksUrl,
        @Value("${identity.oidc.entra.allowed-tenants:}") String allowedTenants,
        @Value("${identity.oidc.entra.clock-skew-seconds:60}") long clockSkewSeconds
    ) {
        this(
            restTemplate,
            objectMapper,
            enabled,
            splitCsv(issuers),
            splitCsv(audiences),
            jwksUrl,
            splitCsv(allowedTenants),
            clockSkewSeconds
        );
    }

    ExternalOidcTokenValidationService(
        RestTemplate restTemplate,
        ObjectMapper objectMapper,
        boolean enabled,
        Collection<String> issuers,
        Collection<String> audiences,
        String jwksUrl,
        Collection<String> allowedTenants,
        long clockSkewSeconds
    ) {
        this.restTemplate = restTemplate;
        this.objectMapper = objectMapper;
        this.enabled = enabled;
        this.issuers = normalizedSet(issuers);
        this.audiences = normalizedSet(audiences);
        this.jwksUrl = jwksUrl == null ? "" : jwksUrl.trim();
        this.allowedTenants = normalizedSet(allowedTenants);
        this.clockSkewSeconds = Math.max(0, Math.min(clockSkewSeconds, 300));
    }

    public ValidatedToken validate(
        String provider,
        String token,
        String expectedIssuer,
        String expectedSubject,
        String expectedEvidenceHash,
        String expectedNonce
    ) {
        if (!ENTRA_PROVIDER.equals(provider)) {
            throw new IllegalArgumentException("Unsupported external OIDC provider");
        }
        if (!enabled || issuers.isEmpty() || audiences.isEmpty() || allowedTenants.isEmpty() || jwksUrl.isBlank()) {
            throw new IllegalArgumentException("External OIDC validation is not configured");
        }
        if (token == null || token.isBlank() || token.length() > 16384) {
            throw new IllegalArgumentException("External OIDC token is invalid");
        }
        if (!PucHashUtil.hashPuc(token).equalsIgnoreCase(requireText(expectedEvidenceHash, "evidence hash"))) {
            throw new IllegalArgumentException("External OIDC evidence hash mismatch");
        }

        JsonNode header = readHeader(token);
        if (!SUPPORTED_ALGORITHM.equals(header.path("alg").asText())
            || header.path("kid").asText().isBlank()) {
            throw new IllegalArgumentException("External OIDC token uses an unsupported header");
        }
        String keyId = header.path("kid").asText();
        Jws<Claims> signed;
        try {
            signed = parseSignedClaims(token, resolveKey(keyId, false));
        } catch (Exception firstSignatureFailure) {
            try {
                signed = parseSignedClaims(token, resolveKey(keyId, true));
            } catch (Exception refreshFailure) {
                throw new IllegalArgumentException("External OIDC token validation failed", refreshFailure);
            }
        }

        Claims claims = signed.getPayload();
        validateClaims(claims, expectedIssuer, expectedSubject, expectedNonce);
        String tenantId = requireText(claims.get("tid", String.class), "tenant");
        String objectId = requireText(claims.get("oid", String.class), "object id");
        return new ValidatedToken(claims.getIssuer(), objectId, tenantId,
            Collections.unmodifiableMap(new LinkedHashMap<>(claims)));
    }

    private Jws<Claims> parseSignedClaims(String token, PublicKey key) {
        return Jwts.parser()
            .verifyWith(key)
            .clockSkewSeconds(clockSkewSeconds)
            .build()
            .parseSignedClaims(token);
    }

    private void validateClaims(Claims claims, String expectedIssuer, String expectedSubject, String expectedNonce) {
        String issuer = requireText(claims.getIssuer(), "issuer");
        requireText(claims.getSubject(), "subject");
        if (claims.getIssuedAt() == null || claims.getExpiration() == null) {
            throw new IllegalArgumentException("External OIDC token lifetime claims are required");
        }
        if (!issuers.contains(issuer) || !issuer.equals(expectedIssuer)) {
            throw new IllegalArgumentException("External OIDC issuer is not trusted");
        }
        if (!audienceContains(claims.get("aud"))) {
            throw new IllegalArgumentException("External OIDC audience is not trusted");
        }
        if (!requireText(expectedNonce, "nonce").equals(claims.get("nonce", String.class))) {
            throw new IllegalArgumentException("External OIDC nonce mismatch");
        }
        String objectId = requireText(claims.get("oid", String.class), "object id");
        if (!objectId.equals(requireText(expectedSubject, "subject"))) {
            throw new IllegalArgumentException("External OIDC object id mismatch");
        }
        String tenantId = requireText(claims.get("tid", String.class), "tenant");
        String tenantIssuer = "https://login.microsoftonline.com/" + tenantId + "/v2.0";
        if (!tenantIssuer.equals(issuer)) {
            throw new IllegalArgumentException("External OIDC issuer and tenant mismatch");
        }
        if (!allowedTenants.isEmpty() && !allowedTenants.contains(tenantId)) {
            throw new IllegalArgumentException("External OIDC tenant is not allowed");
        }
    }

    private boolean audienceContains(Object value) {
        if (value instanceof Collection<?> values) {
            return values.stream().map(String::valueOf).anyMatch(audiences::contains);
        }
        return value != null && audiences.contains(String.valueOf(value));
    }

    private PublicKey resolveKey(String kid, boolean forceRefresh) throws Exception {
        CachedKeys cached = keyCache.get(jwksUrl);
        if (!forceRefresh && cached != null && cached.expiresAt() > System.currentTimeMillis()) {
            PublicKey key = cached.keys().get(kid);
            if (key != null) return key;
        }
        Map<String, PublicKey> loaded = loadKeys();
        keyCache.put(jwksUrl, new CachedKeys(loaded, System.currentTimeMillis() + 300_000));
        PublicKey key = loaded.get(kid);
        if (key == null) throw new IllegalArgumentException("External OIDC signing key is unknown");
        return key;
    }

    private Map<String, PublicKey> loadKeys() throws Exception {
        URI uri = URI.create(jwksUrl);
        if (!"https".equalsIgnoreCase(uri.getScheme())) throw new IllegalArgumentException("OIDC JWKS URL must use HTTPS");
        ResponseEntity<String> response = restTemplate.getForEntity(uri, String.class);
        if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null) {
            throw new IllegalArgumentException("OIDC JWKS endpoint returned an invalid response");
        }
        JsonNode keys = objectMapper.readTree(response.getBody()).path("keys");
        if (!keys.isArray()) throw new IllegalArgumentException("OIDC JWKS response is invalid");
        Map<String, PublicKey> parsed = new LinkedHashMap<>();
        for (JsonNode jwk : keys) {
            if (!"RSA".equals(jwk.path("kty").asText())
                || (jwk.has("use") && !"sig".equals(jwk.path("use").asText()))
                || (jwk.has("alg") && !SUPPORTED_ALGORITHM.equals(jwk.path("alg").asText()))) continue;
            String kid = jwk.path("kid").asText(null);
            String modulus = jwk.path("n").asText(null);
            String exponent = jwk.path("e").asText(null);
            if (kid == null || kid.isBlank() || modulus == null || exponent == null) continue;
            parsed.put(kid, parseRsaKey(modulus, exponent));
        }
        if (parsed.isEmpty()) throw new IllegalArgumentException("OIDC JWKS response has no supported keys");
        return Collections.unmodifiableMap(parsed);
    }

    private PublicKey parseRsaKey(String modulus, String exponent) throws Exception {
        return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(
            new BigInteger(1, Base64.getUrlDecoder().decode(modulus)),
            new BigInteger(1, Base64.getUrlDecoder().decode(exponent))
        ));
    }

    private JsonNode readHeader(String token) {
        try {
            String[] parts = token.split("\\.", -1);
            if (parts.length != 3) throw new IllegalArgumentException("External OIDC token structure is invalid");
            return objectMapper.readTree(Base64.getUrlDecoder().decode(parts[0]));
        } catch (IllegalArgumentException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new IllegalArgumentException("External OIDC token header is invalid", ex);
        }
    }

    private String requireText(String value, String name) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("Missing " + name);
        return value.trim();
    }

    private Set<String> normalizedSet(Collection<String> values) {
        if (values == null) return Set.of();
        return values.stream().filter(value -> value != null && !value.isBlank()).map(value -> value.trim()).collect(java.util.stream.Collectors.toUnmodifiableSet());
    }

    private record CachedKeys(Map<String, PublicKey> keys, long expiresAt) { }

    public record ValidatedToken(String issuer, String subject, String tenantId, Map<String, Object> claims) { }

    private static Set<String> splitCsv(String value) {
        if (value == null || value.isBlank()) return Set.of();
        return java.util.Arrays.stream(value.split(","))
            .map(item -> item.trim()).filter(item -> !item.isBlank()).collect(java.util.stream.Collectors.toUnmodifiableSet());
    }
}
