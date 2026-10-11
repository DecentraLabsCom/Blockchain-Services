package decentralabs.blockchain.security;

import decentralabs.blockchain.service.BackendUrlResolver;
import decentralabs.blockchain.util.GatewayIdentity;
import decentralabs.blockchain.util.LogSanitizer;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Optional;
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
    private static final String SESSION_OBSERVED_PATH = "/access-audit/internal/session-observed";

    public static final String LOCAL_BILLING_READ_ALLOWED_ATTRIBUTE =
        LocalhostOnlyFilter.class.getName() + ".localBillingReadAllowed";

    private final AdminNetworkAccessPolicy adminNetworkAccessPolicy;
    private final LabAdminGatewayCredentialService labAdminGatewayCredentialService;
    private final BackendUrlResolver backendUrlResolver;

    @Value("${security.access-token:}")
    private String accessToken;

    @Value("${security.access-token-header:X-Access-Token}")
    private String accessTokenHeader;

    @Value("${security.access-token-cookie:access_token}")
    private String accessTokenCookie;

    @Value("${gateway.lab-manager.token:}")
    private String labManagerToken;

    @Value("${gateway.lab-manager.token-header:X-Lab-Manager-Token}")
    private String labManagerTokenHeader;

    @Value("${auth.marketplace-endpoints.enabled:true}")
    private boolean marketplaceBillingReadsEnabled;

    public LocalhostOnlyFilter(AdminNetworkAccessPolicy adminNetworkAccessPolicy) {
        this(adminNetworkAccessPolicy, null, null);
    }

    @org.springframework.beans.factory.annotation.Autowired
    public LocalhostOnlyFilter(
        AdminNetworkAccessPolicy adminNetworkAccessPolicy,
        LabAdminGatewayCredentialService labAdminGatewayCredentialService,
        BackendUrlResolver backendUrlResolver
    ) {
        this.adminNetworkAccessPolicy = adminNetworkAccessPolicy;
        this.labAdminGatewayCredentialService = labAdminGatewayCredentialService;
        this.backendUrlResolver = backendUrlResolver;
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
        
        // Both values are sanitized before logging; CodeQL does not model this
        // project-local sanitizer.
        // codeql[java/log-injection]
        log.debug("LocalhostOnlyFilter: path={}, clientIp={}", path, clientIp);

        if (isMarketplaceBillingReadRequest(request)) {
            // FundingController performs the cryptographic JWT and scope
            // validation. This filter only prevents the localhost policy from
            // blocking that authenticated server-to-server read before it can
            // reach the controller.
            filterChain.doFilter(request, response);
            return;
        }

        boolean localRouteAllowed = !requiresLocalhost(request)
            || adminNetworkAccessPolicy.isRequestAllowed(request, () -> hasValidRouteToken(request));
        if (!localRouteAllowed) {
            log.warn("Blocked non-localhost request: path={}, clientIp={}", path, clientIp);
            response.sendError(HttpServletResponse.SC_FORBIDDEN,
                "Endpoint is available from localhost only");
            return;
        }

        if (isLabAdminPath(request) && !establishLabAdminScope(request)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Gateway scope is invalid or not authorized");
            return;
        }

        if (isBillingReadRequest(request)) {
            // This attribute is server-set only after the network policy has
            // allowed the local route. Remote requests must be authorized by
            // FundingController with the Marketplace service JWT.
            request.setAttribute(LOCAL_BILLING_READ_ALLOWED_ATTRIBUTE, Boolean.TRUE);
        }

        filterChain.doFilter(request, response);
    }

    private boolean isMarketplaceBillingReadRequest(HttpServletRequest request) {
        if (!marketplaceBillingReadsEnabled || !isBillingReadRequest(request)) {
            return false;
        }

        String authorization = request.getHeader("Authorization");
        return authorization != null && authorization.trim().regionMatches(true, 0, "Bearer ", 0, 7)
            && authorization.trim().length() > 7;
    }

    private boolean isBillingReadRequest(HttpServletRequest request) {
        if (!("GET".equalsIgnoreCase(request.getMethod()) || "HEAD".equalsIgnoreCase(request.getMethod()))) {
            return false;
        }

        String path = request.getRequestURI();
        return path != null
            && (path.startsWith("/billing/credit-accounts/")
                || path.equals("/billing/funding-orders")
                || path.startsWith("/billing/funding-orders/"));
    }

    private boolean requiresLocalhost(HttpServletRequest request) {
        String path = request.getRequestURI();
        if (path.equals("/wallet/health") || path.equals("/billing/health")) {
            return false;
        }
        // The FMU runner calls this endpoint from the Docker network. Keep the
        // network gate out of the way for this one callback so that the
        // SessionObserverAuthenticationFilter and Spring Security can enforce
        // the required short-lived SESSION_OBSERVER credential.
        if ("POST".equalsIgnoreCase(request.getMethod()) && SESSION_OBSERVED_PATH.equals(path)) {
            return false;
        }
        // Protect wallet/billing APIs, admin notifications, and the wallet dashboard UI.
        return path.startsWith("/wallet")
            || path.startsWith("/billing")
            || path.startsWith("/billing/admin/notifications")
            || path.startsWith("/wallet-dashboard")
            || path.startsWith("/wallet-admin")
            || path.startsWith("/institution-config")
            || path.startsWith("/lab-admin")
            || path.startsWith("/access-audit/internal")
            || path.startsWith("/onboarding/token");
    }

    private boolean hasValidAccessToken(HttpServletRequest request) {
        if (accessToken == null || accessToken.isBlank()) {
            return false;
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

    private boolean hasValidRouteToken(HttpServletRequest request) {
        if (hasValidAccessToken(request)) {
            return true;
        }

        if (isLabAdminPath(request) && hasValidLabManagerToken(request) && adminNetworkAccessPolicy.isLabManagerRequestAllowed(request)) {
            return true;
        }

        return false;
    }

    private boolean isLabAdminPath(HttpServletRequest request) {
        return request.getRequestURI().startsWith("/lab-admin");
    }

    private boolean hasValidLabManagerToken(HttpServletRequest request) {
        String suppliedToken = labManagerTokenFromRequest(request);
        if (suppliedToken == null) {
            return false;
        }

        Optional<String> mappedGateway = labAdminGatewayCredentialService == null
            ? Optional.empty()
            : labAdminGatewayCredentialService.gatewayIdForToken(suppliedToken);
        if (mappedGateway.isPresent()) {
            String requestedGateway = GatewayIdentity.normalizeGatewayId(request.getHeader("X-Gateway-ID"));
            return mappedGateway.get().equals(requestedGateway);
        }
        return constantTimeEquals(labManagerToken, suppliedToken);
    }

    private boolean establishLabAdminScope(HttpServletRequest request) {
        if (hasValidAccessToken(request)) {
            request.setAttribute(LabAdminGatewayScope.REQUEST_ATTRIBUTE, LabAdminGatewayScope.forInstitution());
            return true;
        }

        String suppliedToken = labManagerTokenFromRequest(request);
        Optional<String> mappedGateway = labAdminGatewayCredentialService == null || suppliedToken == null
            ? Optional.empty()
            : labAdminGatewayCredentialService.gatewayIdForToken(suppliedToken);
        if (mappedGateway.isPresent()) {
            String requestedGateway = GatewayIdentity.normalizeGatewayId(request.getHeader("X-Gateway-ID"));
            if (!mappedGateway.get().equals(requestedGateway)) {
                return false;
            }
            request.setAttribute(
                LabAdminGatewayScope.REQUEST_ATTRIBUTE,
                LabAdminGatewayScope.forGateway(mappedGateway.get())
            );
            return true;
        }

        String localGateway = localGatewayId();
        if (localGateway == null) {
            // The one-argument constructor is retained for isolated filter tests.
            request.setAttribute(LabAdminGatewayScope.REQUEST_ATTRIBUTE, LabAdminGatewayScope.forInstitution());
            return true;
        }
        String requestedGateway = GatewayIdentity.normalizeGatewayId(request.getHeader("X-Gateway-ID"));
        if (requestedGateway != null && !localGateway.equals(requestedGateway)) {
            return false;
        }
        request.setAttribute(
            LabAdminGatewayScope.REQUEST_ATTRIBUTE,
            LabAdminGatewayScope.forGateway(localGateway)
        );
        return true;
    }

    private String localGatewayId() {
        return backendUrlResolver == null
            ? null
            : GatewayIdentity.fromAccessUri(backendUrlResolver.resolveBaseDomain());
    }

    private String labManagerTokenFromRequest(HttpServletRequest request) {
        String supplied = request.getHeader(labManagerTokenHeader);
        return supplied == null || supplied.isBlank() ? null : supplied.trim();
    }

    private boolean constantTimeEquals(String expected, String actual) {
        if (expected == null || expected.isBlank() || actual == null) {
            return false;
        }
        return MessageDigest.isEqual(
            expected.trim().getBytes(StandardCharsets.UTF_8),
            actual.trim().getBytes(StandardCharsets.UTF_8)
        );
    }
}
