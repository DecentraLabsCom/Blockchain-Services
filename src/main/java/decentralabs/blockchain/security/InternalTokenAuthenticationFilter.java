package decentralabs.blockchain.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Populates ROLE_INTERNAL when a valid internal token is provided.
 * Used to secure administrative treasury endpoints in standalone mode.
 */
@Component
public class InternalTokenAuthenticationFilter extends OncePerRequestFilter {

    @Value("${security.internal-token:}")
    private String internalToken;

    @Value("${security.internal-token-header:X-Internal-Token}")
    private String internalTokenHeader;

    @Value("${security.internal-token-cookie:internal_token}")
    private String internalTokenCookie;

    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
        String path = request.getRequestURI();
        return path == null || !path.startsWith("/treasury/admin");
    }

    @Override
    protected void doFilterInternal(
        @NonNull HttpServletRequest request,
        @NonNull HttpServletResponse response,
        @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        if (internalToken == null || internalToken.isBlank()) {
            filterChain.doFilter(request, response);
            return;
        }

        String provided = request.getHeader(internalTokenHeader);
        if (provided == null || provided.isBlank()) {
            provided = readTokenFromCookies(request.getCookies());
        }

        if (provided != null && !provided.isBlank()) {
            if (!internalToken.equals(provided.trim())) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
                return;
            }
            Authentication existing = SecurityContextHolder.getContext().getAuthentication();
            if (existing == null) {
                Authentication auth = new UsernamePasswordAuthenticationToken(
                    "internal",
                    null,
                    List.of(new SimpleGrantedAuthority("ROLE_INTERNAL"))
                );
                SecurityContextHolder.getContext().setAuthentication(auth);
            }
        }

        filterChain.doFilter(request, response);
    }

    private String readTokenFromCookies(Cookie[] cookies) {
        if (cookies == null || internalTokenCookie == null || internalTokenCookie.isBlank()) {
            return null;
        }
        for (Cookie cookie : cookies) {
            if (internalTokenCookie.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }
}
