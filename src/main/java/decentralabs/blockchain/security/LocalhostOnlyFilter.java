package decentralabs.blockchain.security;

import decentralabs.blockchain.util.LogSanitizer;
import java.io.IOException;
import java.net.InetAddress;
import java.util.List;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Ensures that wallet and treasury endpoints are only accessible from localhost.
 */
@Component
@Order(0)
@Slf4j
public class LocalhostOnlyFilter extends OncePerRequestFilter {

    @Value("${security.allow-private-networks:false}")
    private boolean allowPrivateNetworks;

    @Value("${security.access-token:}")
    private String accessToken;

    @Value("${security.access-token-header:X-Access-Token}")
    private String accessTokenHeader;

    @Value("${security.access-token-cookie:access_token}")
    private String accessTokenCookie;

    @Value("${security.access-token.required:true}")
    private boolean accessTokenRequired;

    @Value("${lab.manager.token:}")
    private String labManagerToken;

    @Value("${lab.manager.token-header:X-Lab-Manager-Token}")
    private String labManagerTokenHeader;

    private static final List<String> LOCALHOST_ADDRESSES = List.of(
        "127.0.0.1",
        "0:0:0:0:0:0:0:1",
        "::1",
        "::ffff:127.0.0.1"
    );

    @Override
    protected void doFilterInternal(
        @NonNull HttpServletRequest request,
        @NonNull HttpServletResponse response,
        @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        String path = LogSanitizer.sanitize(request.getServletPath());
        String clientIp = LogSanitizer.sanitize(
            request.getRemoteAddr() != null ? request.getRemoteAddr() : ""
        );
        
        log.debug("LocalhostOnlyFilter: path={}, clientIp={}", path, clientIp);
        
        if (requiresLocalhost(request) && !isLocalhost(request)) {
            log.warn("Blocked non-localhost request: path={}, clientIp={}", path, clientIp);
            response.sendError(HttpServletResponse.SC_FORBIDDEN,
                "Endpoint is available from localhost only");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private boolean requiresLocalhost(HttpServletRequest request) {
        String path = request.getRequestURI();
        // Protect wallet/treasury APIs, admin notifications, and the wallet dashboard UI.
        return path.startsWith("/wallet")
            || path.startsWith("/treasury")
            || path.startsWith("/treasury/admin/notifications")
            || path.startsWith("/wallet-dashboard")
            || path.startsWith("/institution-config")
            || path.startsWith("/onboarding/token");
    }

    private boolean isLocalhost(HttpServletRequest request) {
        String clientIp = request.getRemoteAddr();
        if (clientIp == null) {
            return false;
        }

        String normalized = clientIp.trim();
        if (LOCALHOST_ADDRESSES.contains(normalized)) {
            return true;
        }

        // Check if request comes from a trusted proxy (private network) forwarding localhost.
        // This allows nginx to set X-Real-IP/X-Forwarded-For to 127.0.0.1 for internal paths.
        if (isPrivateAddress(normalized)) {
            String forwardedIp = getFirstForwardedIp(request);
            if (forwardedIp != null && LOCALHOST_ADDRESSES.contains(forwardedIp.trim())) {
                log.debug("Trusting forwarded localhost from private proxy: remoteAddr={}, forwarded={}", 
                    normalized, forwardedIp);
                return true;
            }
        }

        // In standalone docker, requests often arrive from a bridge IP (172.x/10.x).
        // Only allow those when explicitly enabled and secured with an access token.
        if (allowPrivateNetworks && (isPrivateAddress(normalized) || isForwardedPrivateAddress(request))) {
            if (!accessTokenRequired) {
                return true;
            }
            if (accessToken == null || accessToken.isBlank()) {
                log.warn("Private network access is enabled but no access token is configured.");
                return false;
            }
            if (hasValidAccessToken(request)) {
                return true;
            }
            log.warn("Missing or invalid access token for private network access.");
            return false;
        }

        return false;
    }

    private String getFirstForwardedIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            String[] parts = forwarded.split(",");
            if (parts.length > 0 && parts[0] != null && !parts[0].isBlank()) {
                return parts[0].trim();
            }
        }
        String realIp = request.getHeader("X-Real-IP");
        if (realIp != null && !realIp.isBlank()) {
            return realIp.trim();
        }
        return null;
    }

    private boolean hasValidAccessToken(HttpServletRequest request) {
        // Check lab manager token first
        if (labManagerToken != null && !labManagerToken.isBlank()) {
            // Check lab manager header
            String labManagerHeaderToken = request.getHeader(labManagerTokenHeader);
            if (labManagerHeaderToken != null && !labManagerHeaderToken.isBlank()) {
                if (labManagerToken.equals(labManagerHeaderToken.trim())) {
                    return true;
                }
            }
        }
        
        // Check access token
        if (accessToken == null || accessToken.isBlank()) {
            return false;
        }
        
        // Check query parameter first (for URLs like /wallet-dashboard/?token=xxx)
        String queryToken = request.getParameter("token");
        if (queryToken != null && !queryToken.isBlank()) {
            return accessToken.equals(queryToken.trim());
        }
        
        // Check header
        String headerToken = request.getHeader(accessTokenHeader);
        if (headerToken != null && !headerToken.isBlank()) {
            return accessToken.equals(headerToken.trim());
        }
        
        // Check Authorization Bearer
        String authorization = request.getHeader("Authorization");
        if (authorization != null) {
            String lower = authorization.toLowerCase();
            if (lower.startsWith("bearer ")) {
                String bearer = authorization.substring("bearer ".length()).trim();
                return accessToken.equals(bearer);
            }
        }
        
        // Check cookie
        if (accessTokenCookie != null && request.getCookies() != null) {
            for (var cookie : request.getCookies()) {
                if (accessTokenCookie.equals(cookie.getName())) {
                    return accessToken.equals(cookie.getValue());
                }
            }
        }
        return false;
    }

    private boolean isPrivateAddress(String ip) {
        try {
            InetAddress addr = InetAddress.getByName(ip);
            return addr.isSiteLocalAddress();
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isForwardedPrivateAddress(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded == null || forwarded.isBlank()) {
            forwarded = request.getHeader("X-Real-IP");
        }
        if (forwarded == null || forwarded.isBlank()) {
            return false;
        }
        for (String token : forwarded.split(",")) {
            if (token == null) {
                continue;
            }
            String candidate = token.trim();
            if (candidate.isEmpty()) {
                continue;
            }
            if (isPrivateAddress(candidate)) {
                return true;
            }
        }
        return false;
    }
}
