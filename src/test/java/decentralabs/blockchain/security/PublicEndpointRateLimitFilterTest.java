package decentralabs.blockchain.security;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

/**
 * Unit tests for PublicEndpointRateLimitFilter.
 * Tests rate limiting behavior per IP for public auth endpoints.
 */
class PublicEndpointRateLimitFilterTest {

    private MockMvc mockMvc;
    private PublicEndpointRateLimitFilter filter;

    @BeforeEach
    void setUp() {
        filter = new PublicEndpointRateLimitFilter();
        // Configure low limits for testing
        ReflectionTestUtils.setField(filter, "authRequestsPerMinute", 5);
        ReflectionTestUtils.setField(filter, "authRequestsBurst", 3);
        ReflectionTestUtils.setField(filter, "jwksRequestsPerMinute", 10);
        ReflectionTestUtils.setField(filter, "rateLimitEnabled", true);
        
        mockMvc = MockMvcBuilders
            .standaloneSetup(new RateLimitTestController())
            .addFilters(filter)
            .build();
    }

    @Test
    @DisplayName("Auth endpoint allows requests within rate limit")
    void authEndpoint_allowsRequestsWithinLimit() throws Exception {
        // First request should succeed
        mockMvc.perform(get("/auth/message")
                .with(req -> { req.setRemoteAddr("192.168.1.100"); return req; }))
            .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Auth endpoint blocks requests exceeding burst limit")
    void authEndpoint_blocksAfterBurstExceeded() throws Exception {
        String clientIp = "10.0.0.50";
        
        // Make requests up to burst limit (3)
        for (int i = 0; i < 3; i++) {
            mockMvc.perform(get("/auth/message")
                    .with(req -> { req.setRemoteAddr(clientIp); return req; }))
                .andExpect(status().isOk());
        }
        
        // 4th request should be rate limited
        mockMvc.perform(get("/auth/message")
                .with(req -> { req.setRemoteAddr(clientIp); return req; }))
            .andExpect(status().isTooManyRequests())
            .andExpect(header().string("Retry-After", "60"))
            .andExpect(jsonPath("$.error").exists());
    }

    @Test
    @DisplayName("Rate limiting is per-IP - different IPs have separate limits")
    void rateLimiting_isPerIp() throws Exception {
        String clientIp1 = "192.168.1.10";
        String clientIp2 = "192.168.1.20";
        
        // Exhaust limit for IP1
        for (int i = 0; i < 3; i++) {
            mockMvc.perform(get("/auth/message")
                    .with(req -> { req.setRemoteAddr(clientIp1); return req; }))
                .andExpect(status().isOk());
        }
        
        // IP1 is now rate limited
        mockMvc.perform(get("/auth/message")
                .with(req -> { req.setRemoteAddr(clientIp1); return req; }))
            .andExpect(status().isTooManyRequests());
        
        // IP2 should still be allowed (independent bucket)
        mockMvc.perform(get("/auth/message")
                .with(req -> { req.setRemoteAddr(clientIp2); return req; }))
            .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Rate limiting respects X-Forwarded-For header")
    void rateLimiting_respectsXForwardedFor() throws Exception {
        String realClientIp = "203.0.113.50";
        String proxyIp = "10.0.0.1";
        
        // Make requests with X-Forwarded-For
        for (int i = 0; i < 3; i++) {
            mockMvc.perform(get("/auth/message")
                    .header("X-Forwarded-For", realClientIp + ", " + proxyIp)
                    .with(req -> { req.setRemoteAddr(proxyIp); return req; }))
                .andExpect(status().isOk());
        }
        
        // Should be rate limited based on real client IP, not proxy
        mockMvc.perform(get("/auth/message")
                .header("X-Forwarded-For", realClientIp + ", " + proxyIp)
                .with(req -> { req.setRemoteAddr(proxyIp); return req; }))
            .andExpect(status().isTooManyRequests());
        
        // Different client through same proxy should work
        mockMvc.perform(get("/auth/message")
                .header("X-Forwarded-For", "203.0.113.100, " + proxyIp)
                .with(req -> { req.setRemoteAddr(proxyIp); return req; }))
            .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Rate limiting respects X-Real-IP header")
    void rateLimiting_respectsXRealIp() throws Exception {
        String realClientIp = "198.51.100.25";
        
        for (int i = 0; i < 3; i++) {
            mockMvc.perform(get("/auth/message")
                    .header("X-Real-IP", realClientIp)
                    .with(req -> { req.setRemoteAddr("10.0.0.1"); return req; }))
                .andExpect(status().isOk());
        }
        
        // Should be rate limited based on X-Real-IP
        mockMvc.perform(get("/auth/message")
                .header("X-Real-IP", realClientIp)
                .with(req -> { req.setRemoteAddr("10.0.0.1"); return req; }))
            .andExpect(status().isTooManyRequests());
    }

    @Test
    @DisplayName("JWKS endpoint has separate higher limit")
    void jwksEndpoint_hasSeparateLimit() throws Exception {
        String clientIp = "172.16.0.100";
        
        // Exhaust auth limit (3 requests)
        for (int i = 0; i < 3; i++) {
            mockMvc.perform(get("/auth/message")
                    .with(req -> { req.setRemoteAddr(clientIp); return req; }))
                .andExpect(status().isOk());
        }
        
        // Auth is rate limited
        mockMvc.perform(get("/auth/message")
                .with(req -> { req.setRemoteAddr(clientIp); return req; }))
            .andExpect(status().isTooManyRequests());
        
        // But JWKS should still work (separate bucket)
        mockMvc.perform(get("/auth/jwks")
                .with(req -> { req.setRemoteAddr(clientIp); return req; }))
            .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Well-known endpoints use JWKS rate limit")
    void wellKnownEndpoint_usesJwksLimit() throws Exception {
        String clientIp = "192.168.100.1";
        
        // JWKS limit is 10 for this test
        for (int i = 0; i < 10; i++) {
            mockMvc.perform(get("/.well-known/openid-configuration")
                    .with(req -> { req.setRemoteAddr(clientIp); return req; }))
                .andExpect(status().isOk());
        }
        
        // 11th should be rate limited
        mockMvc.perform(get("/.well-known/openid-configuration")
                .with(req -> { req.setRemoteAddr(clientIp); return req; }))
            .andExpect(status().isTooManyRequests());
    }

    @Test
    @DisplayName("Wallet-auth endpoints are rate limited")
    void walletAuthEndpoints_areRateLimited() throws Exception {
        String clientIp = "10.10.10.10";
        
        for (int i = 0; i < 3; i++) {
            mockMvc.perform(post("/auth/wallet-auth")
                    .with(req -> { req.setRemoteAddr(clientIp); return req; }))
                .andExpect(status().isOk());
        }
        
        mockMvc.perform(post("/auth/wallet-auth")
                .with(req -> { req.setRemoteAddr(clientIp); return req; }))
            .andExpect(status().isTooManyRequests());
    }

    @Test
    @DisplayName("Rate limiting can be disabled via config")
    void rateLimiting_canBeDisabled() throws Exception {
        ReflectionTestUtils.setField(filter, "rateLimitEnabled", false);
        
        String clientIp = "192.168.5.5";
        
        // Should allow unlimited requests when disabled
        for (int i = 0; i < 20; i++) {
            mockMvc.perform(get("/auth/message")
                    .with(req -> { req.setRemoteAddr(clientIp); return req; }))
                .andExpect(status().isOk());
        }
    }

    @Test
    @DisplayName("Non-rate-limited endpoints are not affected")
    void nonRateLimitedEndpoints_notAffected() throws Exception {
        String clientIp = "192.168.1.1";
        
        // Regular endpoint should not be rate limited
        for (int i = 0; i < 20; i++) {
            mockMvc.perform(get("/health")
                    .with(req -> { req.setRemoteAddr(clientIp); return req; }))
                .andExpect(status().isOk());
        }
    }
}
