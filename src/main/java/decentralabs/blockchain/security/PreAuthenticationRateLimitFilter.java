package decentralabs.blockchain.security;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import jakarta.annotation.Nonnull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Cheap rate limit for FMU ticket endpoints that runs before authentication.
 *
 * <p>The gateway bucket is applied by {@link PublicEndpointRateLimitFilter}
 * after the observer or booking identity has been authenticated. This bucket
 * exists to bound invalid-token work before any signature verification.</p>
 */
@Component
@Slf4j
public class PreAuthenticationRateLimitFilter extends OncePerRequestFilter {
    private static final int MAX_BUCKETS = 50000;

    private final AdminNetworkAccessPolicy adminNetworkAccessPolicy;

    @Value("${rate.limit.fmu.session-ticket.ip.requests.per.minute:600}")
    private int fmuSessionTicketIpRequestsPerMinute;

    @Value("${rate.limit.fmu.session-ticket.ip.requests.burst:60}")
    private int fmuSessionTicketIpRequestsBurst;

    @Value("${rate.limit.enabled:true}")
    private boolean rateLimitEnabled;

    private final Map<String, Bucket> fmuSessionTicketIpBuckets = new ConcurrentHashMap<>();

    public PreAuthenticationRateLimitFilter(AdminNetworkAccessPolicy adminNetworkAccessPolicy) {
        this.adminNetworkAccessPolicy = adminNetworkAccessPolicy;
    }

    @Override
    protected void doFilterInternal(
        @Nonnull HttpServletRequest request,
        @Nonnull HttpServletResponse response,
        @Nonnull FilterChain filterChain
    ) throws ServletException, IOException {
        if (!rateLimitEnabled || !isFmuSessionTicketEndpoint(request.getRequestURI())) {
            filterChain.doFilter(request, response);
            return;
        }

        String clientIp = getClientIp(request);
        if (!checkRateLimit(clientIp)) {
            log.warn("Pre-auth rate limit exceeded for FMU session-ticket endpoint");
            sendRateLimitResponse(response);
            return;
        }

        filterChain.doFilter(request, response);
    }

    private boolean isFmuSessionTicketEndpoint(String path) {
        return path != null && path.startsWith("/auth/fmu/session-ticket/");
    }

    private boolean checkRateLimit(String clientIp) {
        cleanupBucketsIfNeeded();
        Bucket bucket = fmuSessionTicketIpBuckets.computeIfAbsent(clientIp, key -> createBucket());
        return bucket.tryConsume(1);
    }

    private Bucket createBucket() {
        return Bucket.builder()
            .addLimit(Bandwidth.builder()
                .capacity(fmuSessionTicketIpRequestsBurst)
                .refillGreedy(fmuSessionTicketIpRequestsPerMinute, Duration.ofMinutes(1))
                .build())
            .build();
    }

    private String getClientIp(HttpServletRequest request) {
        String resolved = adminNetworkAccessPolicy.resolveClientIp(request);
        return resolved == null || resolved.isBlank() ? request.getRemoteAddr() : resolved;
    }

    private void sendRateLimitResponse(HttpServletResponse response) throws IOException {
        response.setStatus(429);
        response.setContentType("application/json");
        response.setHeader("Retry-After", "60");
        response.getWriter().write("{\"error\":\"Too many requests. Please try again later.\"}");
    }

    private void cleanupBucketsIfNeeded() {
        if (fmuSessionTicketIpBuckets.size() > MAX_BUCKETS) {
            log.info("Evicting pre-auth rate limit buckets, current size: {}", fmuSessionTicketIpBuckets.size());
            int toRemove = fmuSessionTicketIpBuckets.size() / 4;
            var iterator = fmuSessionTicketIpBuckets.entrySet().iterator();
            for (int i = 0; i < toRemove && iterator.hasNext(); i++) {
                iterator.next();
                iterator.remove();
            }
        }
    }
}
