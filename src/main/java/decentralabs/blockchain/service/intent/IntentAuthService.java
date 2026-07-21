package decentralabs.blockchain.service.intent;

import decentralabs.blockchain.service.BackendUrlResolver;
import decentralabs.blockchain.service.auth.MarketplaceKeyService;
import decentralabs.blockchain.service.organization.ProviderConfigurationPersistenceService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import java.net.URI;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Collection;
import java.util.Locale;
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
public class IntentAuthService {

    private final MarketplaceKeyService marketplaceKeyService;
    private final BackendUrlResolver backendUrlResolver;
    private final ProviderConfigurationPersistenceService providerConfigurationPersistenceService;

    @Value("${intents.auth.enabled:true}")
    private boolean enabled;

    @Value("${intents.auth.issuer:marketplace}")
    private String issuer;

    @Value("${intents.auth.audience:}")
    private String audience;

    @Value("${intents.auth.institution-id:}")
    private String institutionId;

    @Value("${intents.auth.service-subject:marketplace}")
    private String serviceSubject;

    @Value("${intents.auth.max-ttl-seconds:60}")
    private long maxTtlSeconds;

    @Value("${intents.auth.submit-scope:intents:submit}")
    private String submitScope;

    @Value("${intents.auth.authorize-scope:intents:authorize}")
    private String authorizeScope;

    @Value("${intents.auth.registration-mined-scope:intents:registration-mined}")
    private String registrationMinedScope;

    @Value("${intents.auth.status-scope:intents:status}")
    private String statusScope;

    @Value("${intents.auth.clock-skew-seconds:60}")
    private long clockSkewSeconds;

    public void enforceSubmitAuthorization(String authorizationHeader) {
        enforceAuthorization(authorizationHeader, submitScope);
    }

    public void enforceAuthorizeAuthorization(String authorizationHeader) {
        enforceAuthorization(authorizationHeader, authorizeScope);
    }

    public void enforceRegistrationMinedAuthorization(String authorizationHeader) {
        enforceAuthorization(authorizationHeader, registrationMinedScope);
    }

    public void enforceStatusAuthorization(String authorizationHeader) {
        enforceAuthorization(authorizationHeader, statusScope);
    }

    private void enforceAuthorization(String authorizationHeader, String requiredScope) {
        if (!enabled) {
            return;
        }

        String token = extractBearerToken(authorizationHeader);
        if (token == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "missing_intents_token");
        }

        Claims claims = validateToken(token);
        if (requiredScope != null && !requiredScope.isBlank() && !scopeContainsRequiredScope(claims, requiredScope)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "missing_intents_scope");
        }
    }

    private Claims validateToken(String token) {
        try {
            PublicKey marketplacePublicKey = marketplaceKeyService.getPublicKey(false);
            JwtParser parser = Jwts.parser()
                .verifyWith(marketplacePublicKey)
                .requireIssuer(issuer)
                .requireAudience(resolveAudience())
                .clockSkewSeconds(clockSkewSeconds)
                .build();
            Jws<Claims> jws = parser.parseSignedClaims(token);
            Claims claims = jws.getPayload();
            validateServiceClaims(claims);
            return claims;
        } catch (ResponseStatusException ex) {
            throw ex;
        } catch (Exception ex) {
            log.warn("Intent authorization JWT validation failed: {}", ex.getMessage());
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid_intents_token");
        }
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
            throw new IllegalArgumentException("Invalid intents JWT audience", ex);
        }
    }

    private void validateServiceClaims(Claims claims) {
        if (claims == null || !serviceSubject.equals(claims.getSubject())) {
            throw new IllegalArgumentException("Invalid service token subject");
        }
        if (claims.getId() == null || claims.getId().isBlank()) {
            throw new IllegalArgumentException("Service token jti is required");
        }

        String expectedInstitution = resolveExpectedInstitution();
        String tokenInstitution = claims.get("institutionId", String.class);
        if (expectedInstitution.isBlank()
            || tokenInstitution == null
            || !expectedInstitution.equalsIgnoreCase(tokenInstitution.trim())) {
            throw new IllegalArgumentException("Service token institutionId mismatch");
        }

        if (claims.getIssuedAt() == null || claims.getExpiration() == null) {
            throw new IllegalArgumentException("Service token lifetime claims are required");
        }
        long issuedAt = claims.getIssuedAt().toInstant().getEpochSecond();
        long expiresAt = claims.getExpiration().toInstant().getEpochSecond();
        if (expiresAt <= issuedAt || expiresAt - issuedAt > maxTtlSeconds) {
            throw new IllegalArgumentException("Service token lifetime is too long");
        }
        if (issuedAt > Instant.now().plusSeconds(clockSkewSeconds).getEpochSecond()) {
            throw new IllegalArgumentException("Service token issuedAt is in the future");
        }
    }

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
