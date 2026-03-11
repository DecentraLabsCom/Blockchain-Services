package decentralabs.blockchain.controller.treasury;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import decentralabs.blockchain.SecurityConfig;
import decentralabs.blockchain.security.AccessTokenAuthenticationFilter;
import decentralabs.blockchain.security.LocalhostOnlyFilter;
import decentralabs.blockchain.security.PublicEndpointRateLimitFilter;
import decentralabs.blockchain.service.BackendUrlResolver;
import decentralabs.blockchain.service.treasury.InstitutionalAdminService;
import decentralabs.blockchain.dto.treasury.InstitutionalAdminRequest;
import decentralabs.blockchain.dto.treasury.InstitutionalAdminRequest.AdminOperation;
import decentralabs.blockchain.dto.treasury.InstitutionalAdminResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

@SpringBootTest(classes = InstitutionalTreasuryControllerIntegrationTest.TestApplication.class)
@TestPropertySource(properties = {
    "security.access-token.required=true",
    "security.access-token=test-token",
    "security.access-token-header=X-Access-Token",
    "security.access-token-cookie=access_token",
    "allowed-origins=https://app.example/",
    "wallet.allowed-origins=http://localhost:3000",
    "base.domain=https://gateway.example/",
    "rate.limit.enabled=false",
    "spring.autoconfigure.exclude="
        + "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration,"
        + "org.springframework.boot.jdbc.autoconfigure.DataSourceTransactionManagerAutoConfiguration,"
        + "org.springframework.boot.jdbc.autoconfigure.JdbcTemplateAutoConfiguration,"
        + "org.springframework.boot.flyway.autoconfigure.FlywayAutoConfiguration,"
        + "org.springframework.boot.data.redis.autoconfigure.DataRedisAutoConfiguration,"
        + "org.springframework.boot.data.redis.autoconfigure.DataRedisReactiveAutoConfiguration,"
        + "org.springframework.boot.data.redis.autoconfigure.DataRedisRepositoriesAutoConfiguration"
})
class InstitutionalTreasuryControllerIntegrationTest {

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private LocalhostOnlyFilter localhostOnlyFilter;

    private MockMvc mockMvc;

    @MockitoBean
    private InstitutionalAdminService adminService;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
            .addFilters(localhostOnlyFilter)
            .apply(springSecurity())
            .build();
    }

    @Test
    void executeAdminOperation_blocksNonLocalhostRequestsEvenWithValidToken() throws Exception {
        mockMvc.perform(post("/treasury/admin/execute")
                .header("X-Access-Token", "test-token")
                .with(req -> {
                    req.setRemoteAddr("198.51.100.20");
                    return req;
                })
                .contentType(MediaType.APPLICATION_JSON)
                .content(validExecutePayload()))
            .andExpect(status().isForbidden());
    }

    @Test
    void executeAdminOperation_rejectsMissingAccessToken() throws Exception {
        mockMvc.perform(post("/treasury/admin/execute")
                .with(req -> {
                    req.setRemoteAddr("127.0.0.1");
                    return req;
                })
                .contentType(MediaType.APPLICATION_JSON)
                .content(validExecutePayload()))
            .andExpect(status().isForbidden());
    }

    @Test
    void executeAdminOperation_rejectsInvalidAccessToken() throws Exception {
        mockMvc.perform(post("/treasury/admin/execute")
                .header("X-Access-Token", "wrong-token")
                .with(req -> {
                    req.setRemoteAddr("127.0.0.1");
                    return req;
                })
                .contentType(MediaType.APPLICATION_JSON)
                .content(validExecutePayload()))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void executeAdminOperation_acceptsValidAccessTokenAndReturnsControllerPayload() throws Exception {
        when(adminService.executeAdminOperation(any(InstitutionalAdminRequest.class)))
            .thenReturn(InstitutionalAdminResponse.success("ok", "0xabc", "AUTHORIZE_BACKEND"));

        mockMvc.perform(post("/treasury/admin/execute")
                .header("X-Access-Token", "test-token")
                .with(req -> {
                    req.setRemoteAddr("127.0.0.1");
                    return req;
                })
                .contentType(MediaType.APPLICATION_JSON)
                .content(validExecutePayload()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.transactionHash").value("0xabc"))
            .andExpect(jsonPath("$.operationType").value("AUTHORIZE_BACKEND"));
    }

    @Test
    void collectLabPayout_acceptsValidTokenAndMapsServiceFailure() throws Exception {
        when(adminService.collectLabPayoutWithConfiguredWallet("3", "50"))
            .thenReturn(InstitutionalAdminResponse.error("collect failed"));

        mockMvc.perform(post("/treasury/admin/collect-lab-payout")
                .header("X-Access-Token", "test-token")
                .with(req -> {
                    req.setRemoteAddr("127.0.0.1");
                    return req;
                })
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {"labId":"3","maxBatch":"50"}
                    """))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.success").value(false))
            .andExpect(jsonPath("$.message").value("collect failed"));
    }

    private String validExecutePayload() {
        InstitutionalAdminRequest request = new InstitutionalAdminRequest();
        request.setAdminWalletAddress("0x123");
        request.setOperation(AdminOperation.AUTHORIZE_BACKEND);
        request.setBackendAddress("0xbackend");
        request.setTimestamp(System.currentTimeMillis());
        request.setSignature("0x" + "11".repeat(65));
        try {
            return new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(request);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @Import({
        SecurityConfig.class,
        BackendUrlResolver.class,
        AccessTokenAuthenticationFilter.class,
        LocalhostOnlyFilter.class,
        PublicEndpointRateLimitFilter.class,
        InstitutionalTreasuryController.class
    })
    static class TestApplication {
    }
}
