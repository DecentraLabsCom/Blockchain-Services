package decentralabs.blockchain;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import decentralabs.blockchain.security.LocalhostOnlyFilter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

@SpringBootTest(classes = SecurityConfigIntegrationTest.TestApplication.class)
@TestPropertySource(properties = {
    "blockchain.services.mode=consumer-only",
    // Explicit mode must win over the legacy provider flag.
    "features.providers.enabled=true",
    "allowed-origins=https://app.example/",
    "base.domain=https://gateway.example/",
    "management.health.defaults.enabled=false",
    "security.access-token.required=true",
    "security.access-token=test-token",
    "security.access-token-header=X-Access-Token",
    "security.access-token-cookie=access_token",
    "security.trusted-proxy-cidrs=127.0.0.1/8,::1/128,172.16.0.0/12",
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
class SecurityConfigConsumerOnlyIntegrationTest {

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private LocalhostOnlyFilter localhostOnlyFilter;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
            .addFilters(localhostOnlyFilter)
            .apply(springSecurity())
            .build();
    }

    @Test
    void providerAccessCredentialRouteIsDeniedInConsumerOnlyMode() throws Exception {
        performProviderPost("/auth/access-credential", "198.51.100.30")
            .andExpect(status().isForbidden());
    }

    @Test
    void combinedProviderAccessRouteIsDeniedInConsumerOnlyMode() throws Exception {
        performProviderPost("/auth/authorize-and-issue", "198.51.100.31")
            .andExpect(status().isForbidden());
    }

    @Test
    void gatewayAccessCodeRedemptionIsDeniedInConsumerOnlyMode() throws Exception {
        performProviderPost("/auth/access-code/redeem", "198.51.100.32")
            .andExpect(status().isForbidden());
    }

    @Test
    void institutionalConsumerCheckInRemainsAvailable() throws Exception {
        mockMvc.perform(post("/auth/checkin-institutional")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}")
                .with(anonymous())
                .with(request -> {
                    request.setRemoteAddr("198.51.100.33");
                    return request;
                }))
            .andExpect(status().isOk())
            .andExpect(content().string("consumer-checkin-ok"));
    }

    @Test
    void institutionalSamlSessionRemainsAvailable() throws Exception {
        mockMvc.perform(post("/auth/saml/session")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}")
                .with(anonymous())
                .with(request -> {
                    request.setRemoteAddr("198.51.100.36");
                    return request;
                }))
            .andExpect(status().isOk())
            .andExpect(content().string("institutional-session-ok"));
    }

    @Test
    void institutionalConsumerCheckInStatusRemainsAvailable() throws Exception {
        mockMvc.perform(post("/auth/checkin-institutional/status")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}")
                .with(anonymous())
                .with(request -> {
                    request.setRemoteAddr("198.51.100.35");
                    return request;
                }))
            .andExpect(status().isOk())
            .andExpect(content().string("consumer-checkin-status-ok"));
    }

    @Test
    void providerFmuTicketRouteIsDeniedInConsumerOnlyMode() throws Exception {
        performProviderPost("/auth/fmu/session-ticket/issue", "198.51.100.34")
            .andExpect(status().isForbidden());
    }

    @Test
    void labAdminReadSurfaceIsDeniedEvenFromLocalhostInConsumerOnlyMode() throws Exception {
        performLocal(get("/lab-admin/status"))
            .andExpect(status().isForbidden());
    }

    @Test
    void labAdminAssetStagingIsDeniedEvenFromLocalhostInConsumerOnlyMode() throws Exception {
        performLocal(post("/lab-admin/assets"))
            .andExpect(status().isForbidden());

        performLocal(delete("/lab-admin/assets"))
            .andExpect(status().isForbidden());
    }

    @Test
    void labAdminPreflightIsDeniedInConsumerOnlyMode() throws Exception {
        performLocal(options("/lab-admin/assets")
                .header("Origin", "https://gateway.example")
                .header("Access-Control-Request-Method", "POST"))
            .andExpect(status().isForbidden());
    }

    private org.springframework.test.web.servlet.ResultActions performLocal(
        org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder request
    ) throws Exception {
        return mockMvc.perform(request
            .with(anonymous())
            .with(req -> {
                req.setRemoteAddr("127.0.0.1");
                return req;
            }));
    }

    private org.springframework.test.web.servlet.ResultActions performProviderPost(
        String path,
        String remoteAddress
    ) throws Exception {
        return mockMvc.perform(post(path)
            .contentType(MediaType.APPLICATION_JSON)
            .content("{}")
            .with(anonymous())
            .with(request -> {
                request.setRemoteAddr(remoteAddress);
                return request;
            }));
    }
}
