package decentralabs.blockchain.security;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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
    void onboarding_remainsOpen() throws Exception {
        mockMvc.perform(post("/onboarding/token/apply").with(req -> { req.setRemoteAddr("8.8.8.8"); return req; }))
            .andExpect(status().isOk());
    }

    @Test
    void allowsPrivateNetworkWhenEnabled() throws Exception {
        ReflectionTestUtils.setField(filter, "allowPrivateNetworks", true);
        mockMvc = MockMvcBuilders
            .standaloneSetup(new LocalhostFilterTestController())
            .addFilters(filter)
            .build();

        mockMvc.perform(post("/wallet/test").with(req -> { req.setRemoteAddr("172.17.0.1"); return req; }))
            .andExpect(status().isOk());
    }
}
