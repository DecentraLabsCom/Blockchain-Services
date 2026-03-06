package decentralabs.blockchain.service.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import java.security.PublicKey;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
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

    @Value("${auth.marketplace-endpoints.enabled:true}")
    private boolean enabled;

    @Value("${auth.marketplace-endpoints.issuer:marketplace}")
    private String issuer;

    @Value("${auth.marketplace-endpoints.audience:blockchain-services}")
    private String audience;

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

    private Claims validateToken(String token) {
        try {
            PublicKey marketplacePublicKey = marketplaceKeyService.getPublicKey(false);
            JwtParser parser = Jwts.parser()
                .verifyWith(marketplacePublicKey)
                .requireIssuer(issuer)
                .requireAudience(audience)
                .clockSkewSeconds(clockSkewSeconds)
                .build();
            Jws<Claims> jws = parser.parseSignedClaims(token);
            return jws.getPayload();
        } catch (ResponseStatusException ex) {
            throw ex;
        } catch (Exception ex) {
            log.warn("Marketplace endpoint JWT validation failed: {}", ex.getMessage());
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid_marketplace_token");
        }
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
                .map(Object::toString)
                .filter(token -> !token.isBlank())
                .anyMatch(token -> token.equals(requiredScope));
        }
        return false;
    }
}
