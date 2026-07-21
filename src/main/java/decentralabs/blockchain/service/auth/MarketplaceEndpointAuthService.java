package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.service.BackendUrlResolver;
import decentralabs.blockchain.service.organization.ProviderConfigurationPersistenceService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import java.net.URI;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.stream.Stream;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
@Slf4j
public class MarketplaceEndpointAuthService {

    private final MarketplaceKeyService marketplaceKeyService;
    private final BackendUrlResolver backendUrlResolver;
    private final ProviderConfigurationPersistenceService providerConfigurationPersistenceService;

    @Value("${auth.marketplace-endpoints.enabled:true}")
    private boolean enabled;

    @Value("${auth.marketplace-endpoints.issuer:marketplace}")
    private String issuer;

    @Value("${auth.marketplace-endpoints.audience:}")
    private String audience;

    @Value("${auth.marketplace-endpoints.institution-id:}")
    private String institutionId;

    @Value("${auth.marketplace-endpoints.service-subject:marketplace}")
    private String serviceSubject;

    @Value("${auth.marketplace-endpoints.max-ttl-seconds:60}")
    private long maxTtlSeconds;

    @Value("${auth.marketplace-endpoints.clock-skew-seconds:60}")
    private long clockSkewSeconds;

    public Map<String, Object> enforceAuthorization(String authorizationHeader, String requiredScope) {
        if (!enabled) {
            return Collections.emptyMap();
        }

        String token = extractBearerToken(authorizationHeader);
        return enforceToken(token, requiredScope);
    }

    public Map<String, Object> enforceToken(String token, String requiredScope) {
        if (!enabled) {
            return Collections.emptyMap();
        }
        if (token == null || token.isBlank()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "missing_marketplace_token");
        }

        Claims claims = validateToken(token);
        if (requiredScope != null && !requiredScope.isBlank() && !scopeContainsRequiredScope(claims, requiredScope)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "missing_marketplace_scope");
        }
        return claims;
    }

    public Map<String, Object> enforceServiceAuthorization(String authorizationHeader, String requiredScope) {
        if (!enabled) {
            return Collections.emptyMap();
        }

        String token = extractBearerToken(authorizationHeader);
        if (token == null || token.isBlank()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "missing_marketplace_token");
        }

        Claims claims = validateToken(token);
        validateServiceClaims(claims);
        if (requiredScope != null && !requiredScope.isBlank() && !scopeContainsRequiredScope(claims, requiredScope)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "missing_marketplace_scope");
        }
        return claims;
    }

    private Claims validateToken(String token) {
        try {
            return parseTokenWithKey(token, marketplaceKeyService.getPublicKey(false), resolveAudience());
        } catch (ResponseStatusException ex) {
            throw ex;
        } catch (Exception firstFailure) {
            try {
                return parseTokenWithKey(token, marketplaceKeyService.getPublicKey(true), resolveAudience());
            } catch (Exception refreshFailure) {
                log.warn("Marketplace endpoint JWT validation failed after key refresh: {}",
                    refreshFailure.getMessage());
                log.debug("Initial marketplace endpoint JWT validation failure: {}", firstFailure.getMessage());
            }
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid_marketplace_token");
        }
    }

    private Claims parseTokenWithKey(String token, PublicKey marketplacePublicKey, String expectedAudience) {
        JwtParser parser = Jwts.parser()
            .verifyWith(marketplacePublicKey)
            .requireIssuer(issuer)
            .requireAudience(expectedAudience)
            .clockSkewSeconds(clockSkewSeconds)
            .build();
        Jws<Claims> jws = parser.parseSignedClaims(token);
        return jws.getPayload();
    }

    private String resolveAudience() {
        String configured = audience != null && !audience.isBlank()
            ? audience.trim()
            : backendUrlResolver.resolveBaseDomain();
        try {
            URI uri = URI.create(configured);
            if (uri.getHost() == null || uri.getUserInfo() != null
                || uri.getQuery() != null || uri.getFragment() != null
                || (uri.getPath() != null && !uri.getPath().isBlank() && !"/".equals(uri.getPath()))
                || (!"http".equalsIgnoreCase(uri.getScheme()) && !"https".equalsIgnoreCase(uri.getScheme()))) {
                throw new IllegalArgumentException("Audience must be an exact HTTP(S) origin");
            }
            String authority = uri.getHost().toLowerCase(Locale.ROOT);
            if (uri.getPort() > 0) authority += ":" + uri.getPort();
            return uri.getScheme().toLowerCase(Locale.ROOT) + "://" + authority;
        } catch (Exception ex) {
            throw new IllegalArgumentException("Invalid marketplace JWT audience", ex);
        }
    }

    private void validateServiceClaims(Claims claims) {
        if (claims == null || !serviceSubject.equals(claims.getSubject())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid_marketplace_token");
        }
        if (claims.getId() == null || claims.getId().isBlank()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid_marketplace_token");
        }

        String expectedInstitution = resolveExpectedInstitution();
        String tokenInstitution = claims.get("institutionId", String.class);
        if (expectedInstitution.isBlank()
            || tokenInstitution == null
            || !expectedInstitution.equalsIgnoreCase(tokenInstitution.trim())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid_marketplace_token");
        }

        if (claims.getIssuedAt() == null || claims.getExpiration() == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid_marketplace_token");
        }
        long issuedAt = claims.getIssuedAt().toInstant().getEpochSecond();
        long expiresAt = claims.getExpiration().toInstant().getEpochSecond();
        if (expiresAt <= issuedAt || expiresAt - issuedAt > maxTtlSeconds
            || issuedAt > Instant.now().plusSeconds(clockSkewSeconds).getEpochSecond()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid_marketplace_token");
        }
    }

    /**
     * Resolve the backend identity without requiring operators to duplicate the
     * institution identifier in a second environment variable. An explicit
     * auth override remains authoritative; the persisted provisioning
     * configuration is the safe fallback because it was written from the
     * Marketplace-issued provisioning claims.
     */
    private String resolveExpectedInstitution() {
        String configured = institutionId == null ? "" : institutionId.trim();
        if (!configured.isBlank()) {
            return configured;
        }

        Properties persisted = providerConfigurationPersistenceService.loadConfigurationSafe();
        String persistedOrganization = persisted.getProperty("provider.organization", "");
        return persistedOrganization == null ? "" : persistedOrganization.trim();
    }

    private String extractBearerToken(String authorizationHeader) {
        if (authorizationHeader == null || authorizationHeader.isBlank()) {
            return null;
        }
        String trimmed = authorizationHeader.trim();
        if (trimmed.length() < 7) {
            return null;
        }
        String prefix = trimmed.substring(0, 7).toLowerCase();
        if (!"bearer ".equals(prefix)) {
            return null;
        }
        String token = trimmed.substring(7).trim();
        return token.isEmpty() ? null : token;
    }

    private boolean scopeContainsRequiredScope(Claims claims, String requiredScope) {
        if (claims == null || requiredScope == null || requiredScope.isBlank()) {
            return true;
        }
        Object scopeClaim = claims.getOrDefault("scope", claims.get("scopes"));
        if (scopeClaim instanceof String scopeText) {
            return Stream.of(scopeText.split("[\\s,]+"))
                .filter(token -> !token.isBlank())
                .anyMatch(token -> token.equals(requiredScope));
        }
        if (scopeClaim instanceof Collection<?> collection) {
            return collection.stream()
                .filter(Objects::nonNull)
                .map(token -> token.toString())
                .filter(token -> !token.isBlank())
                .anyMatch(token -> token.equals(requiredScope));
        }
        return false;
    }
}
