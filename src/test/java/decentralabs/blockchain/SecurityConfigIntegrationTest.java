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
import decentralabs.blockchain.security.PreAuthenticationRateLimitFilter;
import decentralabs.blockchain.security.PublicEndpointRateLimitFilter;
import decentralabs.blockchain.security.SessionObserverAuthenticationFilter;
import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.service.BackendUrlResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Bean;
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
    "security.trusted-proxy-cidrs=127.0.0.1/8,::1/128,172.16.0.0/12",
    "rate.limit.enabled=true",
    "rate.limit.auth.requests.per.minute=2",
    "rate.limit.auth.requests.burst=1",
    "rate.limit.jwks.requests.per.minute=2",
    "rate.limit.fmu.session-ticket.ip.requests.per.minute=2",
    "rate.limit.fmu.session-ticket.ip.requests.burst=1",
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

    private final WebApplicationContext webApplicationContext;

    private final LocalhostOnlyFilter localhostOnlyFilter;

    private final PublicEndpointRateLimitFilter publicEndpointRateLimitFilter;

    private final PreAuthenticationRateLimitFilter preAuthenticationRateLimitFilter;

    private final AdminNetworkAccessPolicy adminNetworkAccessPolicy;

    @Autowired
    SecurityConfigIntegrationTest(WebApplicationContext webApplicationContext,
                                  LocalhostOnlyFilter localhostOnlyFilter,
                                  PublicEndpointRateLimitFilter publicEndpointRateLimitFilter,
                                  PreAuthenticationRateLimitFilter preAuthenticationRateLimitFilter,
                                  AdminNetworkAccessPolicy adminNetworkAccessPolicy) {
        this.webApplicationContext = webApplicationContext;
        this.localhostOnlyFilter = localhostOnlyFilter;
        this.publicEndpointRateLimitFilter = publicEndpointRateLimitFilter;
        this.preAuthenticationRateLimitFilter = preAuthenticationRateLimitFilter;
        this.adminNetworkAccessPolicy = adminNetworkAccessPolicy;
    }

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "adminDashboardLocalOnly", true);
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "adminDashboardAllowPrivate", false);
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "allowPrivateNetworks", false);
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "accessTokenRequired", true);
        ((java.util.Map<?, ?>) ReflectionTestUtils.getField(publicEndpointRateLimitFilter, "authBuckets")).clear();
        ((java.util.Map<?, ?>) ReflectionTestUtils.getField(publicEndpointRateLimitFilter, "jwksBuckets")).clear();
        ((java.util.Map<?, ?>) ReflectionTestUtils.getField(preAuthenticationRateLimitFilter,
            "fmuSessionTicketIpBuckets")).clear();
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
            .addFilters(localhostOnlyFilter)
            .apply(springSecurity())
            .build();
    }

    @Test
    void preflightOnHealthEndpoint_allowsConfiguredOriginWithoutWildcard() throws Exception {
        mockMvc.perform(options("/health")
                .header("Origin", "https://app.example")
                .header("Access-Control-Request-Method", "GET"))
            .andExpect(status().isOk())
            .andExpect(header().string("Access-Control-Allow-Origin", "https://app.example"));
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
    void walletEndpoint_ignoresLoopbackSpoofFromUntrustedPrivateRemote() throws Exception {
        mockMvc.perform(get("/wallet/test")
                .with(anonymous())
                .header("X-Forwarded-For", "127.0.0.1")
                .header("X-Real-IP", "127.0.0.1")
                .with(req -> {
                    req.setRemoteAddr("10.20.1.5");
                    return req;
                }))
            .andExpect(status().isForbidden());
    }

    @Test
    void walletEndpoint_requiresTokenWhenLocalOnlyDisabled() throws Exception {
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "adminDashboardLocalOnly", false);

        mockMvc.perform(get("/wallet/test")
                .with(anonymous())
                .with(req -> {
                    req.setRemoteAddr("203.0.113.10");
                    return req;
                }))
            .andExpect(status().isForbidden());
    }

    @Test
    void walletEndpoint_acceptsHeaderTokenWhenLocalOnlyDisabled() throws Exception {
        ReflectionTestUtils.setField(adminNetworkAccessPolicy, "adminDashboardLocalOnly", false);

        mockMvc.perform(get("/wallet/test")
                .with(anonymous())
                .header("X-Access-Token", "test-token")
                .with(req -> {
                    req.setRemoteAddr("203.0.113.10");
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
    void labContentEndpoint_isPubliclyAccessibleFromExternalIp() throws Exception {
        mockMvc.perform(get("/lab-content/content/demo/metadata.json")
                .with(anonymous())
                .with(req -> {
                    req.setRemoteAddr("203.0.113.10");
                    return req;
                }))
            .andExpect(status().isOk())
            .andExpect(header().string("Access-Control-Allow-Origin", "*"))
            .andExpect(content().string("lab-content-ok"));
    }

    @Test
    void labContentEndpoint_rejectsUnsafeMethods() throws Exception {
        mockMvc.perform(post("/lab-content/content/demo/metadata.json")
                .with(anonymous())
                .with(req -> {
                    req.setRemoteAddr("203.0.113.10");
                    return req;
                }))
            .andExpect(status().isMethodNotAllowed());
    }

    @Test
    void fmuSessionTicketIssue_isAccessibleWithoutAuthentication() throws Exception {
        mockMvc.perform(post("/auth/fmu/session-ticket/issue")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}")
                .with(req -> {
                    req.setRemoteAddr("172.17.0.10");
                    return req;
                }))
            .andExpect(status().isOk())
            .andExpect(content().string("fmu-session-ticket-ok"));
    }

    @Test
    void fmuSessionTicketRedeem_requiresGatewayAuthentication() throws Exception {
        mockMvc.perform(post("/auth/fmu/session-ticket/redeem")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}")
                .with(req -> {
                    req.setRemoteAddr("172.17.0.10");
                    return req;
                }))
            .andExpect(status().isForbidden());
    }

    @Test
    void fmuSessionTicketRedeemRateLimitRunsBeforeInvalidObserverAuthentication() throws Exception {
        String clientIp = "172.17.0.11";
        mockMvc.perform(post("/auth/fmu/session-ticket/redeem")
                .header("Authorization", "Bearer invalid-observer-token")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}")
                .with(req -> {
                    req.setRemoteAddr(clientIp);
                    return req;
                }))
            .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/auth/fmu/session-ticket/redeem")
                .header("Authorization", "Bearer another-invalid-observer-token")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}")
                .with(req -> {
                    req.setRemoteAddr(clientIp);
                    return req;
                }))
            .andExpect(status().isTooManyRequests());
    }

    @Test
    void accessCredentialEndpoint_isAccessibleWithoutSpringAuthentication() throws Exception {
        mockMvc.perform(post("/auth/access-credential")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}")
                .with(req -> {
                    req.setRemoteAddr("198.51.100.30");
                    return req;
                }))
            .andExpect(status().isOk())
            .andExpect(content().string("access-credential-ok"));
    }

    @Test
    void accessCredentialEndpoint_isRateLimitedPerIp() throws Exception {
        mockMvc.perform(post("/auth/access-credential")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}")
                .with(req -> {
                    req.setRemoteAddr("198.51.100.40");
                    return req;
                }))
            .andExpect(status().isOk())
            .andExpect(content().string("access-credential-ok"));

        mockMvc.perform(post("/auth/access-credential")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}")
                .with(req -> {
                    req.setRemoteAddr("198.51.100.40");
                    return req;
                }))
            .andExpect(status().isTooManyRequests())
            .andExpect(header().string("Retry-After", "60"))
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON));
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

    @RestController
    static class TestEndpoints {

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

        @GetMapping("/lab-content/content/demo/metadata.json")
        org.springframework.http.ResponseEntity<String> labContent() {
            return org.springframework.http.ResponseEntity.ok()
                .header("Access-Control-Allow-Origin", "*")
                .body("lab-content-ok");
        }

        @GetMapping("/health")
        String health() {
            return "health-ok";
        }

        @PostMapping("/auth/fmu/session-ticket/issue")
        String fmuSessionTicketIssue() {
            return "fmu-session-ticket-ok";
        }

        @PostMapping("/auth/fmu/session-ticket/redeem")
        String fmuSessionTicketRedeem() {
            return "fmu-session-ticket-ok";
        }

        @PostMapping("/auth/access-credential")
        String accessCredential() {
            return "access-credential-ok";
        }
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @Import({
        SecurityConfig.class,
        BackendUrlResolver.class,
        AccessTokenAuthenticationFilter.class,
        SessionObserverAuthenticationFilter.class,
        AdminNetworkAccessPolicy.class,
        LocalhostOnlyFilter.class,
        PreAuthenticationRateLimitFilter.class,
        PublicEndpointRateLimitFilter.class,
        TestEndpoints.class
    })
    static class TestApplication {
        @Bean
        ObjectMapper objectMapper() {
            return new ObjectMapper();
        }
    }
}
