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
 * Populates ROLE_INTERNAL when a valid access token is provided.
 * Used to secure administrative treasury endpoints in standalone mode.
 */
@Component
public class AccessTokenAuthenticationFilter extends OncePerRequestFilter {

    @Value("${security.access-token:}")
    private String accessToken;

    @Value("${security.access-token-header:X-Access-Token}")
    private String accessTokenHeader;

    @Value("${security.access-token-cookie:access_token}")
    private String accessTokenCookie;

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
        if (accessToken == null || accessToken.isBlank()) {
            filterChain.doFilter(request, response);
            return;
        }

        String provided = request.getHeader(accessTokenHeader);
        if (provided == null || provided.isBlank()) {
            provided = readTokenFromCookies(request.getCookies());
        }

        if (provided != null && !provided.isBlank()) {
            if (!accessToken.equals(provided.trim())) {
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
        if (cookies == null || accessTokenCookie == null || accessTokenCookie.isBlank()) {
            return null;
        }
        for (Cookie cookie : cookies) {
            if (accessTokenCookie.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }
}
