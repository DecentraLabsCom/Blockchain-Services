package decentralabs.blockchain.security;

import java.io.IOException;
import java.util.List;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Ensures that wallet and treasury endpoints are only accessible from localhost.
 */
@Component
@Order(0)
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

        if (requiresLocalhost(request) && !isLocalhost(request)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN,
                "Endpoint is available from localhost only");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private boolean requiresLocalhost(HttpServletRequest request) {
        String path = request.getServletPath();
        return RESTRICTED_PREFIXES.stream().anyMatch(path::startsWith);
    }

    private boolean isLocalhost(HttpServletRequest request) {
        String clientIp = request.getRemoteAddr();
        if (clientIp == null) {
            return false;
        }
        clientIp = clientIp.trim();
        return LOCALHOST_ADDRESSES.contains(clientIp);
    }
}
