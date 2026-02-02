package decentralabs.blockchain.security;

import decentralabs.blockchain.util.LogSanitizer;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
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

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Rate limiting filter for public authentication endpoints.
 * Protects against brute force and DoS attacks on:
 * - /auth/message
 * - /auth/wallet-auth
 * - /auth/wallet-auth2
 * - /auth/saml-auth
 * - /auth/saml-auth2
 * - /auth/jwks
 * - /.well-known/*
 * 
 * Uses a token bucket algorithm per IP address.
 */
@Component
@Order(1) // After LocalhostOnlyFilter
@Slf4j
public class PublicEndpointRateLimitFilter extends OncePerRequestFilter {

    @Value("${rate.limit.auth.requests.per.minute:30}")
    private int authRequestsPerMinute;

    @Value("${rate.limit.auth.requests.burst:10}")
    private int authRequestsBurst;

    @Value("${rate.limit.jwks.requests.per.minute:120}")
    private int jwksRequestsPerMinute;

    @Value("${rate.limit.enabled:true}")
    private boolean rateLimitEnabled;

    private final Map<String, Bucket> authBuckets = new ConcurrentHashMap<>();
    private final Map<String, Bucket> jwksBuckets = new ConcurrentHashMap<>();

    // Maximum buckets to prevent memory exhaustion
    private static final int MAX_BUCKETS = 50000;

    @Override
    protected void doFilterInternal(
            @Nonnull HttpServletRequest request,
            @Nonnull HttpServletResponse response,
            @Nonnull FilterChain filterChain
    ) throws ServletException, IOException {

        if (!rateLimitEnabled) {
            filterChain.doFilter(request, response);
            return;
        }

        String path = request.getRequestURI();
        String clientIp = getClientIp(request);

        // Check if this is a rate-limited endpoint
        if (isAuthEndpoint(path)) {
            if (!checkAuthRateLimit(clientIp)) {
                log.warn("Rate limit exceeded for auth endpoint: path={}, ip={}", LogSanitizer.sanitize(path), maskIp(clientIp));
                sendRateLimitResponse(response);
                return;
            }
        } else if (isJwksEndpoint(path)) {
            if (!checkJwksRateLimit(clientIp)) {
                log.warn("Rate limit exceeded for JWKS endpoint: ip={}", maskIp(clientIp));
                sendRateLimitResponse(response);
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private boolean isAuthEndpoint(String path) {
        return path.startsWith("/auth/wallet-auth")
                || path.startsWith("/auth/saml-auth")
                || path.equals("/auth/message");
    }

    private boolean isJwksEndpoint(String path) {
        return path.equals("/auth/jwks")
                || path.startsWith("/.well-known/");
    }

    private boolean checkAuthRateLimit(String clientIp) {
        cleanupBucketsIfNeeded(authBuckets);
        Bucket bucket = authBuckets.computeIfAbsent(clientIp, k -> createAuthBucket());
        return bucket.tryConsume(1);
    }

    private boolean checkJwksRateLimit(String clientIp) {
        cleanupBucketsIfNeeded(jwksBuckets);
        Bucket bucket = jwksBuckets.computeIfAbsent(clientIp, k -> createJwksBucket());
        return bucket.tryConsume(1);
    }

    private Bucket createAuthBucket() {
        return Bucket.builder()
                .addLimit(Bandwidth.builder()
                        .capacity(authRequestsBurst)
                        .refillGreedy(authRequestsPerMinute, Duration.ofMinutes(1))
                        .build())
                .build();
    }

    private Bucket createJwksBucket() {
        return Bucket.builder()
                .addLimit(Bandwidth.builder()
                        .capacity(jwksRequestsPerMinute)
                        .refillGreedy(jwksRequestsPerMinute, Duration.ofMinutes(1))
                        .build())
                .build();
    }

    private void sendRateLimitResponse(HttpServletResponse response) throws IOException {
        response.setStatus(429);
        response.setContentType("application/json");
        response.setHeader("Retry-After", "60");
        response.getWriter().write("{\"error\":\"Too many requests. Please try again later.\"}");
    }

    private String getClientIp(HttpServletRequest request) {
        // Check X-Forwarded-For header (set by reverse proxy)
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            // Take the first IP in the chain (original client)
            String[] ips = xForwardedFor.split(",");
            return ips[0].trim();
        }
        
        // Check X-Real-IP header
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp.trim();
        }
        
        return request.getRemoteAddr();
    }

    private String maskIp(String ip) {
        if (ip == null) return "unknown";
        // Mask last octet for privacy in logs
        int lastDot = ip.lastIndexOf('.');
        if (lastDot > 0) {
            return ip.substring(0, lastDot) + ".***";
        }
        // IPv6 or other format - just mask end
        if (ip.length() > 8) {
            return ip.substring(0, ip.length() - 4) + "****";
        }
        return ip;
    }

    private void cleanupBucketsIfNeeded(Map<String, Bucket> buckets) {
        if (buckets.size() > MAX_BUCKETS) {
            log.info("Cleaning up rate limit buckets, current size: {}", buckets.size());
            buckets.clear();
        }
    }
}
