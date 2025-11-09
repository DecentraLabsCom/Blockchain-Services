package decentralabs.blockchain.security;

import java.io.IOException;
import java.util.List;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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

    private static final List<String> LOCALHOST_ADDRESSES = List.of(
        "127.0.0.1",
        "0:0:0:0:0:0:0:1",
        "::1",
        "::ffff:127.0.0.1"
    );

    private static final List<String> RESTRICTED_PREFIXES = List.of(
        "/wallet",
        "/treasury"
    );

    @Override
    protected void doFilterInternal(
        @NonNull HttpServletRequest request,
        @NonNull HttpServletResponse response,
        @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        String path = request.getServletPath();
        String clientIp = request.getRemoteAddr();
        
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
        String path = request.getServletPath();
        // Allow /admin/ static resources (dashboard HTML/CSS/JS) for all users from localhost
        // But protect /treasury and /wallet API endpoints
        return RESTRICTED_PREFIXES.stream().anyMatch(path::startsWith);
    }

    private boolean isLocalhost(HttpServletRequest request) {
        String clientIp = request.getRemoteAddr();
        if (clientIp == null) {
            return false;
        }
        clientIp = clientIp.trim();
        
        // Allow standard localhost addresses
        if (LOCALHOST_ADDRESSES.contains(clientIp)) {
            return true;
        }
        
        // Allow Docker internal network addresses (172.x.x.x, 10.x.x.x)
        // These are typical Docker bridge network IPs
        if (clientIp.startsWith("172.") || clientIp.startsWith("10.")) {
            return true;
        }
        
        return false;
    }
}
