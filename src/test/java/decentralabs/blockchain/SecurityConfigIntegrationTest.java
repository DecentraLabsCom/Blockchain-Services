package decentralabs.blockchain;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import decentralabs.blockchain.security.AccessTokenAuthenticationFilter;
import decentralabs.blockchain.security.AdminNetworkAccessPolicy;
import decentralabs.blockchain.security.LocalhostOnlyFilter;
import decentralabs.blockchain.security.PublicEndpointRateLimitFilter;
import decentralabs.blockchain.service.BackendUrlResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootTest(
    classes = SecurityConfigIntegrationTest.TestApplication.class
)
@TestPropertySource(properties = {
    "features.providers.enabled=true",
    "allowed-origins=https://app.example/",
    "base.domain=https://gateway.example/",
    "management.health.defaults.enabled=false",
    "security.access-token.required=true",
    "security.access-token=test-token",
    "security.access-token-header=X-Access-Token",
    "security.access-token-cookie=access_token",
    "rate.limit.enabled=true",
    "rate.limit.auth.requests.per.minute=2",
    "rate.limit.auth.requests.burst=1",
    "rate.limit.jwks.requests.per.minute=2",
    "spring.autoconfigure.exclude="
        + "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration,"
        + "org.springframework.boot.jdbc.autoconfigure.DataSourceTransactionManagerAutoConfiguration,"
        + "org.springframework.boot.jdbc.autoconfigure.JdbcTemplateAutoConfiguration,"
        + "org.springframework.boot.flyway.autoconfigure.FlywayAutoConfiguration,"
        + "org.springframework.boot.data.redis.autoconfigure.DataRedisAutoConfiguration,"
        + "org.springframework.boot.data.redis.autoconfigure.DataRedisReactiveAutoConfiguration,"
        + "org.springframework.boot.data.redis.autoconfigure.DataRedisRepositoriesAutoConfiguration"
})
class SecurityConfigIntegrationTest {

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private LocalhostOnlyFilter localhostOnlyFilter;

    @Autowired
    private PublicEndpointRateLimitFilter publicEndpointRateLimitFilter;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        ((java.util.Map<?, ?>) ReflectionTestUtils.getField(publicEndpointRateLimitFilter, "authBuckets")).clear();
        ((java.util.Map<?, ?>) ReflectionTestUtils.getField(publicEndpointRateLimitFilter, "jwksBuckets")).clear();
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
            .addFilters(localhostOnlyFilter, publicEndpointRateLimitFilter)
            .apply(springSecurity())
            .build();
    }

    @Test
    void preflightOnPublicAuthEndpoint_allowsConfiguredOrigin() throws Exception {
        mockMvc.perform(options("/auth/saml-auth")
                .header("Origin", "https://app.example")
                .header("Access-Control-Request-Method", "POST")
                .header("Access-Control-Request-Headers", "Content-Type"))
            .andExpect(status().isOk())
            .andExpect(header().string("Access-Control-Allow-Origin", "https://app.example"));
    }

    @Test
    void preflightOnPublicAuthEndpoint_allowsGatewayOriginFromResolver() throws Exception {
        mockMvc.perform(options("/auth/saml-auth")
                .header("Origin", "https://gateway.example")
                .header("Access-Control-Request-Method", "POST"))
            .andExpect(status().isOk())
            .andExpect(header().string("Access-Control-Allow-Origin", "https://gateway.example"));
    }

    @Test
    void walletEndpoint_blocksNonLocalhostRequests() throws Exception {
        mockMvc.perform(get("/wallet/test")
                .with(anonymous())
                .with(req -> {
                    req.setRemoteAddr("8.8.8.8");
                    return req;
                }))
            .andExpect(status().isForbidden());
    }

    @Test
    void walletEndpoint_allowsLocalhostRequests() throws Exception {
        mockMvc.perform(get("/wallet/test")
                .with(anonymous())
                .with(req -> {
                    req.setRemoteAddr("127.0.0.1");
                    return req;
                }))
            .andExpect(status().isOk())
            .andExpect(content().string("wallet-ok"));
    }

    @Test
    void preflightOnWalletEndpoint_allowsGatewayOriginFromResolver() throws Exception {
        mockMvc.perform(options("/wallet/reveal")
                .with(anonymous())
                .with(req -> {
                    req.setRemoteAddr("127.0.0.1");
                    return req;
                })
                .header("Origin", "https://gateway.example")
                .header("Access-Control-Request-Method", "POST")
                .header("Access-Control-Request-Headers", "Content-Type"))
            .andExpect(status().isOk())
            .andExpect(header().string("Access-Control-Allow-Origin", "https://gateway.example"));
    }

    @Test
    void billingAdmin_requiresInternalRoleInProviderModeWhenTokenMissing() throws Exception {
        mockMvc.perform(get("/billing/admin/test")
                .with(anonymous())
                .with(req -> {
                    req.setRemoteAddr("127.0.0.1");
                    return req;
                }))
            .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(roles = "INTERNAL")
    void billingAdmin_acceptsInternalRoleAuthentication() throws Exception {
        mockMvc.perform(get("/billing/admin/test")
                .with(req -> {
                    req.setRemoteAddr("127.0.0.1");
                    return req;
                }))
            .andExpect(status().isOk())
            .andExpect(content().string("billing-admin-ok"));
    }

    @Test
    void intentsEndpoint_isPubliclyAccessible() throws Exception {
        mockMvc.perform(get("/intents/test")
                .with(req -> {
                    req.setRemoteAddr("203.0.113.10");
                    return req;
                }))
            .andExpect(status().isOk())
            .andExpect(content().string("intents-ok"));
    }

    @Test
    void unknownEndpoint_isDeniedByDefault() throws Exception {
        mockMvc.perform(get("/not-mapped")
                .with(req -> {
                    req.setRemoteAddr("127.0.0.1");
                    return req;
                }))
            .andExpect(status().isForbidden());
    }

    @Test
    void publicAuthEndpoint_isRateLimitedPerIp() throws Exception {
        mockMvc.perform(post("/auth/saml-auth")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}")
                .with(req -> {
                    req.setRemoteAddr("198.51.100.20");
                    return req;
                }))
            .andExpect(status().isOk())
            .andExpect(content().string("saml-ok"));

        mockMvc.perform(post("/auth/saml-auth")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}")
                .with(req -> {
                    req.setRemoteAddr("198.51.100.20");
                    return req;
                }))
            .andExpect(status().isTooManyRequests())
            .andExpect(header().string("Retry-After", "60"))
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON));
    }

    @RestController
    static class TestEndpoints {

        @PostMapping("/auth/saml-auth")
        String authSaml() {
            return "saml-ok";
        }

        @GetMapping("/wallet/test")
        String wallet() {
            return "wallet-ok";
        }

        @GetMapping("/billing/admin/test")
        String billingAdmin() {
            return "billing-admin-ok";
        }

        @GetMapping("/intents/test")
        String intents() {
            return "intents-ok";
        }
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @Import({
        SecurityConfig.class,
        BackendUrlResolver.class,
        AccessTokenAuthenticationFilter.class,
        AdminNetworkAccessPolicy.class,
        LocalhostOnlyFilter.class,
        PublicEndpointRateLimitFilter.class,
        TestEndpoints.class
    })
    static class TestApplication {
    }
}
