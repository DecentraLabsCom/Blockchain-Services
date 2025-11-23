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
        String path = request.getServletPath();
        // Protect wallet/treasury APIs, admin notifications, and the wallet dashboard UI.
        return path.startsWith("/wallet")
            || path.startsWith("/treasury")
            || path.startsWith("/treasury/admin/notifications")
            || path.startsWith("/wallet-dashboard");
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

        // In standalone docker, requests often arrive from a bridge IP (172.x/10.x).
        // Only allow those when explicitly enabled.
        if (allowPrivateNetworks && isPrivateAddress(normalized)) {
            return true;
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
}
