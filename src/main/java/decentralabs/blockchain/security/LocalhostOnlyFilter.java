package decentralabs.blockchain.security;

import decentralabs.blockchain.util.LogSanitizer;
import java.io.IOException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import jakarta.annotation.Nonnull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Ensures that wallet and billing endpoints are only accessible from localhost.
 */
@Component
@Order(0)
@Slf4j
public class LocalhostOnlyFilter extends OncePerRequestFilter {
    private final AdminNetworkAccessPolicy adminNetworkAccessPolicy;

    @Value("${security.access-token:}")
    private String accessToken;

    @Value("${security.access-token-header:X-Access-Token}")
    private String accessTokenHeader;

    @Value("${security.access-token-cookie:access_token}")
    private String accessTokenCookie;

    public LocalhostOnlyFilter(AdminNetworkAccessPolicy adminNetworkAccessPolicy) {
        this.adminNetworkAccessPolicy = adminNetworkAccessPolicy;
    }

    @Override
    protected void doFilterInternal(
        @Nonnull HttpServletRequest request,
        @Nonnull HttpServletResponse response,
        @Nonnull FilterChain filterChain
    ) throws ServletException, IOException {

        String path = LogSanitizer.sanitize(request.getServletPath());
        String clientIp = LogSanitizer.sanitize(
            request.getRemoteAddr() != null ? request.getRemoteAddr() : ""
        );
        
        log.debug("LocalhostOnlyFilter: path={}, clientIp={}", path, clientIp);
        
        if (requiresLocalhost(request) && !adminNetworkAccessPolicy.isRequestAllowed(request, () -> hasValidAccessToken(request))) {
            log.warn("Blocked non-localhost request: path={}, clientIp={}", path, clientIp);
            response.sendError(HttpServletResponse.SC_FORBIDDEN,
                "Endpoint is available from localhost only");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private boolean requiresLocalhost(HttpServletRequest request) {
        String path = request.getRequestURI();
        // Protect wallet/billing APIs, admin notifications, and the wallet dashboard UI.
        return path.startsWith("/wallet")
            || path.startsWith("/billing")
            || path.startsWith("/billing/admin/notifications")
            || path.startsWith("/wallet-dashboard")
            || path.startsWith("/institution-config")
            || path.startsWith("/onboarding/token");
    }

    private boolean hasValidAccessToken(HttpServletRequest request) {
        if (accessToken == null || accessToken.isBlank()) {
            return false;
        }

        String queryToken = request.getParameter("token");
        if (queryToken != null && !queryToken.isBlank()) {
            return accessToken.equals(queryToken.trim());
        }

        String headerToken = request.getHeader(accessTokenHeader);
        if (headerToken != null && !headerToken.isBlank()) {
            return accessToken.equals(headerToken.trim());
        }

        String authorization = request.getHeader("Authorization");
        if (authorization != null) {
            String lower = authorization.toLowerCase();
            if (lower.startsWith("bearer ")) {
                String bearer = authorization.substring("bearer ".length()).trim();
                return accessToken.equals(bearer);
            }
        }

        if (accessTokenCookie != null && request.getCookies() != null) {
            for (var cookie : request.getCookies()) {
                if (accessTokenCookie.equals(cookie.getName())) {
                    return accessToken.equals(cookie.getValue());
                }
            }
        }
        return false;
    }
}
