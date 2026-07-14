package decentralabs.blockchain.security;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import decentralabs.blockchain.service.auth.JwtService;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PublicEndpointRateLimitFilterTest {

    private MockMvc mockMvc;
    private PublicEndpointRateLimitFilter filter;
    private JwtService jwtService;

    @BeforeEach
    void setUp() {
        AdminNetworkAccessPolicy policy = new AdminNetworkAccessPolicy();
        ReflectionTestUtils.setField(policy, "adminDashboardLocalOnly", true);
        ReflectionTestUtils.setField(policy, "adminDashboardAllowPrivate", false);
        ReflectionTestUtils.setField(policy, "allowPrivateNetworks", false);
        ReflectionTestUtils.setField(policy, "accessTokenRequired", true);
        ReflectionTestUtils.setField(policy, "configuredCidrs", "");
        ReflectionTestUtils.setField(policy, "trustedProxyCidrs", "127.0.0.1/8,::1/128,172.16.0.0/12");

        jwtService = mock(JwtService.class);
        when(jwtService.validateToken("booking-a")).thenReturn(true);
        when(jwtService.extractAllClaims("booking-a"))
            .thenReturn(Map.of("targetGatewayId", "gateway-a"));
        when(jwtService.validateToken("booking-b")).thenReturn(true);
        when(jwtService.extractAllClaims("booking-b"))
            .thenReturn(Map.of("targetGatewayId", "gateway-b"));

        filter = new PublicEndpointRateLimitFilter(policy, jwtService);
        ReflectionTestUtils.setField(filter, "authRequestsPerMinute", 5);
        ReflectionTestUtils.setField(filter, "authRequestsBurst", 3);
        ReflectionTestUtils.setField(filter, "fmuSessionTicketRequestsPerMinute", 5);
        ReflectionTestUtils.setField(filter, "fmuSessionTicketRequestsBurst", 3);
        ReflectionTestUtils.setField(filter, "jwksRequestsPerMinute", 10);
        ReflectionTestUtils.setField(filter, "rateLimitEnabled", true);

        mockMvc = MockMvcBuilders.standaloneSetup(new RateLimitTestController())
            .addFilters(filter)
            .build();
        SecurityContextHolder.clearContext();
    }

    @Test
    void authorizeAndIssue_allowsRequestsWithinRateLimit() throws Exception {
        mockMvc.perform(post("/auth/authorize-and-issue")
                .with(req -> { req.setRemoteAddr("192.168.1.100"); return req; }))
            .andExpect(status().isOk());
    }

    @Test
    void authorizeAndIssue_blocksRequestsExceedingBurstLimit() throws Exception {
        String clientIp = "10.0.0.50";
        for (int i = 0; i < 3; i++) {
            mockMvc.perform(post("/auth/authorize-and-issue")
                    .with(req -> { req.setRemoteAddr(clientIp); return req; }))
                .andExpect(status().isOk());
        }

        mockMvc.perform(post("/auth/authorize-and-issue")
                .with(req -> { req.setRemoteAddr(clientIp); return req; }))
            .andExpect(status().isTooManyRequests())
            .andExpect(header().string("Retry-After", "60"))
            .andExpect(jsonPath("$.error").exists());
    }

    @Test
    void rateLimiting_isPerIp() throws Exception {
        for (int i = 0; i < 3; i++) {
            mockMvc.perform(post("/auth/authorize-and-issue")
                    .with(req -> { req.setRemoteAddr("192.168.1.10"); return req; }))
                .andExpect(status().isOk());
        }
        mockMvc.perform(post("/auth/authorize-and-issue")
                .with(req -> { req.setRemoteAddr("192.168.1.10"); return req; }))
            .andExpect(status().isTooManyRequests());
        mockMvc.perform(post("/auth/authorize-and-issue")
                .with(req -> { req.setRemoteAddr("192.168.1.20"); return req; }))
            .andExpect(status().isOk());
    }

    @Test
    void rateLimiting_followsRealClientAcrossTrustedProxies() throws Exception {
        String realClientIp = "198.51.100.44";
        for (String proxyIp : new String[] { "172.17.0.10", "172.18.0.10", "172.19.0.10" }) {
            mockMvc.perform(post("/auth/authorize-and-issue")
                    .header("X-Forwarded-For", realClientIp + ", " + proxyIp)
                    .with(req -> { req.setRemoteAddr(proxyIp); return req; }))
                .andExpect(status().isOk());
        }
        mockMvc.perform(post("/auth/authorize-and-issue")
                .header("X-Forwarded-For", realClientIp + ", 172.20.0.10")
                .with(req -> { req.setRemoteAddr("172.20.0.10"); return req; }))
            .andExpect(status().isTooManyRequests());
    }

    @Test
    void jwksEndpoint_usesSeparateRateLimitBucket() throws Exception {
        String clientIp = "172.16.0.100";
        for (int i = 0; i < 3; i++) {
            mockMvc.perform(post("/auth/authorize-and-issue")
                    .with(req -> { req.setRemoteAddr(clientIp); return req; }))
                .andExpect(status().isOk());
        }
        mockMvc.perform(post("/auth/authorize-and-issue")
                .with(req -> { req.setRemoteAddr(clientIp); return req; }))
            .andExpect(status().isTooManyRequests());
        mockMvc.perform(get("/auth/jwks")
                .with(req -> { req.setRemoteAddr(clientIp); return req; }))
            .andExpect(status().isOk());
    }

    @Test
    void institutionalCheckIn_isRateLimited() throws Exception {
        String clientIp = "10.10.10.10";
        for (int i = 0; i < 3; i++) {
            mockMvc.perform(post("/auth/checkin-institutional")
                    .with(req -> { req.setRemoteAddr(clientIp); return req; }))
                .andExpect(status().isOk());
        }
        mockMvc.perform(post("/auth/checkin-institutional")
                .with(req -> { req.setRemoteAddr(clientIp); return req; }))
            .andExpect(status().isTooManyRequests());
    }

    @Test
    void fmuSessionTicketRedemption_isRateLimited() throws Exception {
        String clientIp = "10.10.10.11";
        for (int i = 0; i < 3; i++) {
            mockMvc.perform(post("/auth/fmu/session-ticket/redeem")
                    .with(req -> { req.setRemoteAddr(clientIp); return req; }))
                .andExpect(status().isOk());
        }
        mockMvc.perform(post("/auth/fmu/session-ticket/redeem")
                .with(req -> { req.setRemoteAddr(clientIp); return req; }))
            .andExpect(status().isTooManyRequests());
    }

    @Test
    void fmuSessionTicketRedemption_usesAnIndependentBucketPerObserverGateway() throws Exception {
        String clientIp = "10.10.10.12";
        SecurityContextHolder.getContext().setAuthentication(
            new TestingAuthenticationToken(
                "gateway-a",
                null,
                "ROLE_SESSION_OBSERVER"
            )
        );

        for (int i = 0; i < 3; i++) {
            mockMvc.perform(post("/auth/fmu/session-ticket/redeem")
                    .with(req -> { req.setRemoteAddr(clientIp); return req; }))
                .andExpect(status().isOk());
        }
        mockMvc.perform(post("/auth/fmu/session-ticket/redeem")
                .with(req -> { req.setRemoteAddr(clientIp); return req; }))
            .andExpect(status().isTooManyRequests());

        SecurityContextHolder.getContext().setAuthentication(
            new TestingAuthenticationToken(
                "gateway-b",
                null,
                "ROLE_SESSION_OBSERVER"
            )
        );
        mockMvc.perform(post("/auth/fmu/session-ticket/redeem")
                .with(req -> { req.setRemoteAddr(clientIp); return req; }))
            .andExpect(status().isOk());
    }

    @Test
    void fmuSessionTicketIssue_usesAnIndependentBucketFromPublicAuth() throws Exception {
        String clientIp = "10.10.10.13";
        for (int i = 0; i < 3; i++) {
            mockMvc.perform(post("/auth/authorize-and-issue")
                    .with(req -> { req.setRemoteAddr(clientIp); return req; }))
                .andExpect(status().isOk());
        }

        mockMvc.perform(post("/auth/fmu/session-ticket/issue")
                .header("Authorization", "Bearer booking-a")
                .with(req -> { req.setRemoteAddr(clientIp); return req; }))
            .andExpect(status().isOk());
    }

    @Test
    void fmuSessionTicketIssue_usesAnIndependentBucketPerGateway() throws Exception {
        String clientIp = "10.10.10.14";
        for (int i = 0; i < 3; i++) {
            mockMvc.perform(post("/auth/fmu/session-ticket/issue")
                    .header("Authorization", "Bearer booking-a")
                    .with(req -> { req.setRemoteAddr(clientIp); return req; }))
                .andExpect(status().isOk());
        }
        mockMvc.perform(post("/auth/fmu/session-ticket/issue")
                .header("Authorization", "Bearer booking-a")
                .with(req -> { req.setRemoteAddr(clientIp); return req; }))
            .andExpect(status().isTooManyRequests());

        mockMvc.perform(post("/auth/fmu/session-ticket/issue")
                .header("Authorization", "Bearer booking-b")
                .with(req -> { req.setRemoteAddr(clientIp); return req; }))
            .andExpect(status().isOk());
    }

    @Test
    void fmuSessionTicketIssue_doesNotTrustArbitraryGatewayHeader() throws Exception {
        String clientIp = "10.10.10.15";
        for (int i = 0; i < 3; i++) {
            mockMvc.perform(post("/auth/fmu/session-ticket/issue")
                    .header("Authorization", "Bearer invalid")
                    .header("X-FMU-Gateway-ID", "rotating-gateway-" + i)
                    .with(req -> { req.setRemoteAddr(clientIp); return req; }))
                .andExpect(status().isOk());
        }

        mockMvc.perform(post("/auth/fmu/session-ticket/issue")
                .header("Authorization", "Bearer invalid")
                .header("X-FMU-Gateway-ID", "another-gateway")
                .with(req -> { req.setRemoteAddr(clientIp); return req; }))
            .andExpect(status().isTooManyRequests());
    }

    @Test
    void rateLimiting_canBeDisabled() throws Exception {
        ReflectionTestUtils.setField(filter, "rateLimitEnabled", false);
        for (int i = 0; i < 20; i++) {
            mockMvc.perform(post("/auth/authorize-and-issue")
                    .with(req -> { req.setRemoteAddr("192.168.5.5"); return req; }))
                .andExpect(status().isOk());
        }
    }

    @Test
    void nonRateLimitedHealthEndpoint_isUnaffected() throws Exception {
        for (int i = 0; i < 20; i++) {
            mockMvc.perform(get("/health")
                    .with(req -> { req.setRemoteAddr("192.168.1.1"); return req; }))
                .andExpect(status().isOk());
        }
    }
}
