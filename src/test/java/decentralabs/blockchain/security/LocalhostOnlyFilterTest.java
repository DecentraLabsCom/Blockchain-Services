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
    private AdminNetworkAccessPolicy adminNetworkAccessPolicy;

    @BeforeEach
    void setUp() {
        adminNetworkAccessPolicy = new AdminNetworkAccessPolicy();
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "adminDashboardLocalOnly", true);
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "adminDashboardAllowPrivate", false);
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "allowPrivateNetworks", false);
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "accessTokenRequired", true);
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "configuredCidrs", "");
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "labManagerAllowedCidrs", "");
        filter = new LocalhostOnlyFilter(adminNetworkAccessPolicy);
        ReflectionTestUtils.setField(filter, "accessToken", "test-token");
        ReflectionTestUtils.setField(filter, "accessTokenHeader", "X-Access-Token");
        ReflectionTestUtils.setField(filter, "accessTokenCookie", "access_token");
        ReflectionTestUtils.setField(filter, "labManagerToken", "lab-manager-token");
        ReflectionTestUtils.setField(filter, "labManagerTokenHeader", "X-Lab-Manager-Token");
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
    void accessAuditInternalEndpoint_allowsLoopback() throws Exception {
        mockMvc.perform(post("/access-audit/internal/session-observed")
                .with(req -> { req.setRemoteAddr("127.0.0.1"); return req; }))
            .andExpect(status().isOk());
    }

    @Test
    void accessAuditInternalEndpoint_blocksPrivateNetworkWithoutToken() throws Exception {
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "adminDashboardAllowPrivate", true);
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "allowPrivateNetworks", true);
        mockMvc = MockMvcBuilders
            .standaloneSetup(new LocalhostFilterTestController())
            .addFilters(filter)
            .build();

        mockMvc.perform(post("/access-audit/internal/session-observed")
                .with(req -> { req.setRemoteAddr("172.17.0.1"); return req; }))
            .andExpect(status().isForbidden());
    }

    @Test
    void accessAuditInternalEndpoint_allowsPrivateNetworkWithAccessToken() throws Exception {
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "adminDashboardAllowPrivate", true);
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "allowPrivateNetworks", true);
        mockMvc = MockMvcBuilders
            .standaloneSetup(new LocalhostFilterTestController())
            .addFilters(filter)
            .build();

        mockMvc.perform(post("/access-audit/internal/session-observed")
                .header("X-Access-Token", "test-token")
                .with(req -> { req.setRemoteAddr("172.17.0.1"); return req; }))
            .andExpect(status().isOk());
    }

    @Test
    void labAdminEndpoint_allowsPrivateNetworkWithLabManagerToken() throws Exception {
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "adminDashboardAllowPrivate", true);
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "allowPrivateNetworks", true);
        mockMvc = MockMvcBuilders
            .standaloneSetup(new LocalhostFilterTestController())
            .addFilters(filter)
            .build();

        mockMvc.perform(get("/lab-admin/status")
                .header("X-Lab-Manager-Token", "lab-manager-token")
                .with(req -> { req.setRemoteAddr("172.17.0.1"); return req; }))
            .andExpect(status().isOk());
    }

    @Test
    void labAdminEndpoint_allowsPublicNetworkWithLabManagerToken_whenExternalDashboardAccessEnabled() throws Exception {
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "adminDashboardLocalOnly", false);
        mockMvc = MockMvcBuilders
            .standaloneSetup(new LocalhostFilterTestController())
            .addFilters(filter)
            .build();

        mockMvc.perform(get("/lab-admin/status")
                .header("X-Lab-Manager-Token", "lab-manager-token")
                .with(req -> { req.setRemoteAddr("8.8.8.8"); return req; }))
            .andExpect(status().isOk());
    }

    @Test
    void labAdminEndpoint_blocksLabManagerTokenOutsideAllowedCidrs() throws Exception {
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "adminDashboardLocalOnly", false);
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "labManagerAllowedCidrs", "203.0.113.20/32");
        mockMvc = MockMvcBuilders
            .standaloneSetup(new LocalhostFilterTestController())
            .addFilters(filter)
            .build();

        mockMvc.perform(get("/lab-admin/status")
                .header("X-Lab-Manager-Token", "lab-manager-token")
                .with(req -> { req.setRemoteAddr("198.51.100.25"); return req; }))
            .andExpect(status().isForbidden());
    }

    @Test
    void labAdminEndpoint_allowsLabManagerTokenInsideAllowedCidrs() throws Exception {
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "adminDashboardLocalOnly", false);
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "labManagerAllowedCidrs", "203.0.113.20/32");
        mockMvc = MockMvcBuilders
            .standaloneSetup(new LocalhostFilterTestController())
            .addFilters(filter)
            .build();

        mockMvc.perform(get("/lab-admin/status")
                .header("X-Lab-Manager-Token", "lab-manager-token")
                .with(req -> { req.setRemoteAddr("203.0.113.20"); return req; }))
            .andExpect(status().isOk());
    }

    @Test
    void walletEndpoint_rejectsLabManagerToken() throws Exception {
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "adminDashboardAllowPrivate", true);
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "allowPrivateNetworks", true);
        mockMvc = MockMvcBuilders
            .standaloneSetup(new LocalhostFilterTestController())
            .addFilters(filter)
            .build();

        mockMvc.perform(post("/wallet/test")
                .header("X-Lab-Manager-Token", "lab-manager-token")
                .with(req -> { req.setRemoteAddr("172.17.0.1"); return req; }))
            .andExpect(status().isForbidden());
    }

    @Test
    void walletHealth_allowsPublicIpWithoutToken() throws Exception {
        mockMvc.perform(get("/wallet/health").with(req -> { req.setRemoteAddr("8.8.8.8"); return req; }))
            .andExpect(status().isOk());
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
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "adminDashboardAllowPrivate", true);
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "allowPrivateNetworks", true);
        mockMvc = MockMvcBuilders
            .standaloneSetup(new LocalhostFilterTestController())
            .addFilters(filter)
            .build();

        mockMvc.perform(post("/wallet/test")
                .header("X-Access-Token", "test-token")
                .with(req -> { req.setRemoteAddr("172.17.0.1"); return req; }))
            .andExpect(status().isOk());
    }

    @Test
    void allowsPrivateNetworkWithBearerToken() throws Exception {
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "adminDashboardAllowPrivate", true);
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "allowPrivateNetworks", true);
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
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "adminDashboardAllowPrivate", true);
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "allowPrivateNetworks", true);
        mockMvc = MockMvcBuilders
            .standaloneSetup(new LocalhostFilterTestController())
            .addFilters(filter)
            .build();

        mockMvc.perform(post("/wallet/test")
                .cookie(new Cookie("access_token", "test-token"))
                .with(req -> { req.setRemoteAddr("172.17.0.1"); return req; }))
            .andExpect(status().isOk());
    }

    @Test
    void rejectsPrivateNetworkWithQueryToken() throws Exception {
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "adminDashboardAllowPrivate", true);
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "allowPrivateNetworks", true);
        mockMvc = MockMvcBuilders
            .standaloneSetup(new LocalhostFilterTestController())
            .addFilters(filter)
            .build();

        mockMvc.perform(post("/wallet/test")
                .param("token", "test-token")
                .with(req -> { req.setRemoteAddr("172.17.0.1"); return req; }))
            .andExpect(status().isForbidden());
    }

    @Test
    void blocksPrivateNetworkWithoutToken() throws Exception {
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "adminDashboardAllowPrivate", true);
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "allowPrivateNetworks", true);
        mockMvc = MockMvcBuilders
            .standaloneSetup(new LocalhostFilterTestController())
            .addFilters(filter)
            .build();

        mockMvc.perform(post("/wallet/test").with(req -> { req.setRemoteAddr("172.17.0.1"); return req; }))
            .andExpect(status().isForbidden());
    }

    @Test
    void allowsPrivateNetworkWhenTokenNotRequired() throws Exception {
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "adminDashboardAllowPrivate", true);
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "allowPrivateNetworks", true);
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "accessTokenRequired", false);
        mockMvc = MockMvcBuilders
            .standaloneSetup(new LocalhostFilterTestController())
            .addFilters(filter)
            .build();

        mockMvc.perform(post("/wallet/test").with(req -> { req.setRemoteAddr("172.17.0.1"); return req; }))
            .andExpect(status().isOk());
    }
}
