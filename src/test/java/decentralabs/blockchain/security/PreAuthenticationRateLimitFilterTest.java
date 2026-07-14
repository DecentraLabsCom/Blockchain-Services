package decentralabs.blockchain.security;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import jakarta.annotation.Nonnull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.OncePerRequestFilter;

class PreAuthenticationRateLimitFilterTest {

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        AdminNetworkAccessPolicy policy = new AdminNetworkAccessPolicy();
        ReflectionTestUtils.setField(policy, "adminDashboardLocalOnly", true);
        ReflectionTestUtils.setField(policy, "adminDashboardAllowPrivate", false);
        ReflectionTestUtils.setField(policy, "allowPrivateNetworks", false);
        ReflectionTestUtils.setField(policy, "configuredCidrs", "");
        ReflectionTestUtils.setField(policy, "trustedProxyCidrs", "127.0.0.1/8,::1/128,172.16.0.0/12");

        PreAuthenticationRateLimitFilter filter = new PreAuthenticationRateLimitFilter(policy);
        ReflectionTestUtils.setField(filter, "fmuSessionTicketIpRequestsPerMinute", 1);
        ReflectionTestUtils.setField(filter, "fmuSessionTicketIpRequestsBurst", 1);
        ReflectionTestUtils.setField(filter, "rateLimitEnabled", true);

        mockMvc = MockMvcBuilders.standaloneSetup(new RateLimitTestController())
            .addFilters(filter, new RejectingAuthenticationFilter())
            .build();
    }

    @Test
    void invalidRedeemIsRateLimitedBeforeDownstreamAuthenticationRejectsIt() throws Exception {
        String clientIp = "198.51.100.77";

        mockMvc.perform(post("/auth/fmu/session-ticket/redeem")
                .header("Authorization", "Bearer invalid")
                .with(req -> {
                    req.setRemoteAddr(clientIp);
                    return req;
                }))
            .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/auth/fmu/session-ticket/redeem")
                .header("Authorization", "Bearer invalid-again")
                .with(req -> {
                    req.setRemoteAddr(clientIp);
                    return req;
                }))
            .andExpect(status().isTooManyRequests());
    }

    @RestController
    static class RateLimitTestController {
        @PostMapping("/auth/fmu/session-ticket/redeem")
        String redeem() {
            return "ok";
        }
    }

    static class RejectingAuthenticationFilter extends OncePerRequestFilter {
        @Override
        protected void doFilterInternal(
            @Nonnull HttpServletRequest request,
            @Nonnull HttpServletResponse response,
            @Nonnull FilterChain filterChain
        ) throws ServletException, IOException {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
        }
    }
}
