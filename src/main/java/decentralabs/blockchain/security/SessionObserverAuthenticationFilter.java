package decentralabs.blockchain.security;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.Nonnull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/** Authenticates short-lived, least-privilege JWTs issued per gateway. */
@Component
public class SessionObserverAuthenticationFilter extends OncePerRequestFilter {
    private static final String PATH = "/access-audit/internal/session-observed";
    private static final String AUDIENCE = "session-observation";
    private static final String SCOPE = "session-observation:submit";

    private final ObjectMapper objectMapper;

    @Value("${security.session-observer.credentials-json:{}}")
    private String credentialsJson;

    public SessionObserverAuthenticationFilter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    protected boolean shouldNotFilter(@Nonnull HttpServletRequest request) {
        return !"POST".equalsIgnoreCase(request.getMethod()) || !PATH.equals(request.getRequestURI());
    }

    @Override
    protected void doFilterInternal(
        @Nonnull HttpServletRequest request,
        @Nonnull HttpServletResponse response,
        @Nonnull FilterChain filterChain
    ) throws ServletException, IOException {
        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            String token = authorization.substring("Bearer ".length()).trim();
            String gatewayId = unverifiedIssuer(token);
            String encodedSecret = credentials().get(gatewayId);
            if (encodedSecret == null || encodedSecret.isBlank()) {
                throw new IllegalArgumentException("Unknown session observer gateway");
            }
            SecretKey key = Keys.hmacShaKeyFor(Base64.getUrlDecoder().decode(encodedSecret));
            Claims claims = Jwts.parser()
                .verifyWith(key)
                .requireIssuer(gatewayId)
                .requireSubject(gatewayId)
                .build()
                .parseSignedClaims(token)
                .getPayload();
            if (!claims.getAudience().contains(AUDIENCE)
                || !SCOPE.equals(claims.get("scope", String.class))
                || claims.getExpiration() == null
                || !claims.getExpiration().toInstant().isAfter(Instant.now())) {
                throw new IllegalArgumentException("Invalid session observer claims");
            }
            SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(
                    gatewayId,
                    null,
                    List.of(new SimpleGrantedAuthority("ROLE_SESSION_OBSERVER"))
                )
            );
            filterChain.doFilter(request, response);
        } catch (Exception ex) {
            SecurityContextHolder.clearContext();
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
        }
    }

    private Map<String, String> credentials() throws IOException {
        if (credentialsJson == null || credentialsJson.isBlank()) {
            return Map.of();
        }
        return objectMapper.readValue(credentialsJson, new TypeReference<>() { });
    }

    private String unverifiedIssuer(String token) throws IOException {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Malformed observer JWT");
        }
        byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
        Map<String, Object> claims = objectMapper.readValue(
            new String(payload, StandardCharsets.UTF_8), new TypeReference<>() { }
        );
        Object issuer = claims.get("iss");
        if (!(issuer instanceof String value) || value.isBlank()) {
            throw new IllegalArgumentException("Missing observer issuer");
        }
        return value;
    }
}
