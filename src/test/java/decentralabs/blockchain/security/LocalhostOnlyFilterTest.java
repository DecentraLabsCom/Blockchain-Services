package decentralabs.blockchain.security;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import jakarta.servlet.http.Cookie;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class LocalhostOnlyFilterTest {

    private MockMvc mockMvc;
    private LocalhostOnlyFilter filter;

    @BeforeEach
    void setUp() {
        filter = new LocalhostOnlyFilter();
        ReflectionTestUtils.setField(filter, "allowPrivateNetworks", false);
        ReflectionTestUtils.setField(filter, "internalToken", "test-token");
        ReflectionTestUtils.setField(filter, "internalTokenHeader", "X-Internal-Token");
        ReflectionTestUtils.setField(filter, "internalTokenCookie", "internal_token");
        ReflectionTestUtils.setField(filter, "internalTokenRequired", true);
        mockMvc = MockMvcBuilders
            .standaloneSetup(new LocalhostFilterTestController())
            .addFilters(filter)
            .build();
    }

    @Test
    void walletEndpoint_blockedFromPrivateNetwork_whenFlagDisabled() throws Exception {
        mockMvc.perform(post("/wallet/test").with(req -> { req.setRemoteAddr("172.17.0.1"); return req; }))
            .andExpect(status().isForbidden());
    }

    @Test
    void walletEndpoint_allowsLoopback() throws Exception {
        mockMvc.perform(post("/wallet/test").with(req -> { req.setRemoteAddr("127.0.0.1"); return req; }))
            .andExpect(status().isOk());
    }

    @Test
    void walletDashboard_blockedFromPublicIp() throws Exception {
        mockMvc.perform(get("/wallet-dashboard/index.html").with(req -> { req.setRemoteAddr("8.8.8.8"); return req; }))
            .andExpect(status().isForbidden());
    }

    @Test
    void onboarding_token_blockedFromPublicIp() throws Exception {
        mockMvc.perform(post("/onboarding/token/apply").with(req -> { req.setRemoteAddr("8.8.8.8"); return req; }))
            .andExpect(status().isForbidden());
    }

    @Test
    void allowsPrivateNetworkWhenEnabledWithToken() throws Exception {
        ReflectionTestUtils.setField(filter, "allowPrivateNetworks", true);
        mockMvc = MockMvcBuilders
            .standaloneSetup(new LocalhostFilterTestController())
            .addFilters(filter)
            .build();

        mockMvc.perform(post("/wallet/test")
                .header("X-Internal-Token", "test-token")
                .with(req -> { req.setRemoteAddr("172.17.0.1"); return req; }))
            .andExpect(status().isOk());
    }

    @Test
    void allowsPrivateNetworkWithBearerToken() throws Exception {
        ReflectionTestUtils.setField(filter, "allowPrivateNetworks", true);
        mockMvc = MockMvcBuilders
            .standaloneSetup(new LocalhostFilterTestController())
            .addFilters(filter)
            .build();

        mockMvc.perform(post("/wallet/test")
                .header("Authorization", "Bearer test-token")
                .with(req -> { req.setRemoteAddr("172.17.0.1"); return req; }))
            .andExpect(status().isOk());
    }

    @Test
    void allowsPrivateNetworkWithCookieToken() throws Exception {
        ReflectionTestUtils.setField(filter, "allowPrivateNetworks", true);
        mockMvc = MockMvcBuilders
            .standaloneSetup(new LocalhostFilterTestController())
            .addFilters(filter)
            .build();

        mockMvc.perform(post("/wallet/test")
                .cookie(new Cookie("internal_token", "test-token"))
                .with(req -> { req.setRemoteAddr("172.17.0.1"); return req; }))
            .andExpect(status().isOk());
    }

    @Test
    void blocksPrivateNetworkWithoutToken() throws Exception {
        ReflectionTestUtils.setField(filter, "allowPrivateNetworks", true);
        mockMvc = MockMvcBuilders
            .standaloneSetup(new LocalhostFilterTestController())
            .addFilters(filter)
            .build();

        mockMvc.perform(post("/wallet/test").with(req -> { req.setRemoteAddr("172.17.0.1"); return req; }))
            .andExpect(status().isForbidden());
    }

    @Test
    void allowsPrivateNetworkWhenTokenNotRequired() throws Exception {
        ReflectionTestUtils.setField(filter, "allowPrivateNetworks", true);
        ReflectionTestUtils.setField(filter, "internalTokenRequired", false);
        mockMvc = MockMvcBuilders
            .standaloneSetup(new LocalhostFilterTestController())
            .addFilters(filter)
            .build();

        mockMvc.perform(post("/wallet/test").with(req -> { req.setRemoteAddr("172.17.0.1"); return req; }))
            .andExpect(status().isOk());
    }
}
