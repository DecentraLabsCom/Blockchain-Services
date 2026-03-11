package decentralabs.blockchain.controller.provider;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import decentralabs.blockchain.controller.TestSecurityConfig;
import decentralabs.blockchain.dto.provider.ConsumerProvisioningTokenPayload;
import decentralabs.blockchain.dto.provider.ProvisioningTokenPayload;
import decentralabs.blockchain.security.LocalhostOnlyFilter;
import decentralabs.blockchain.service.organization.InstitutionRegistrationService;
import decentralabs.blockchain.service.organization.ProviderConfigurationPersistenceService;
import decentralabs.blockchain.service.organization.ProvisioningTokenService;
import java.util.Properties;
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

@SpringBootTest(classes = ProviderConfigurationControllerIntegrationTest.TestApplication.class)
@TestPropertySource(properties = {
    "spring.autoconfigure.exclude="
        + "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration,"
        + "org.springframework.boot.jdbc.autoconfigure.DataSourceTransactionManagerAutoConfiguration,"
        + "org.springframework.boot.jdbc.autoconfigure.JdbcTemplateAutoConfiguration,"
        + "org.springframework.boot.flyway.autoconfigure.FlywayAutoConfiguration,"
        + "org.springframework.boot.data.redis.autoconfigure.DataRedisAutoConfiguration,"
        + "org.springframework.boot.data.redis.autoconfigure.DataRedisReactiveAutoConfiguration,"
        + "org.springframework.boot.data.redis.autoconfigure.DataRedisRepositoriesAutoConfiguration"
})
@Import(TestSecurityConfig.class)
class ProviderConfigurationControllerIntegrationTest {

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private LocalhostOnlyFilter localhostOnlyFilter;

    private MockMvc mockMvc;

    @MockitoBean
    private InstitutionRegistrationService registrationService;

    @MockitoBean
    private ProviderConfigurationPersistenceService persistenceService;

    @MockitoBean
    private ProvisioningTokenService provisioningTokenService;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
            .addFilters(localhostOnlyFilter)
            .build();
    }

    @Test
    void status_blocksNonLocalhostRequests() throws Exception {
        mockMvc.perform(get("/institution-config/status")
                .with(req -> {
                    req.setRemoteAddr("203.0.113.10");
                    return req;
                }))
            .andExpect(status().isForbidden());
    }

    @Test
    void applyProviderToken_returnsPartialContentWhenRegistrationFails() throws Exception {
        Properties props = new Properties();
        props.setProperty("marketplace.base-url", "https://marketplace.example.com");
        props.setProperty("public.base-url", "https://gateway.example.com");
        when(persistenceService.loadConfigurationSafe()).thenReturn(props);
        when(provisioningTokenService.validateAndExtract(anyString(), anyString(), anyString()))
            .thenReturn(ProvisioningTokenPayload.builder()
                .marketplaceBaseUrl("https://marketplace.example.com")
                .providerName("Token University")
                .providerEmail("token@university.edu")
                .providerCountry("ES")
                .providerOrganization("token.edu")
                .publicBaseUrl("https://gateway.example.com")
                .jti("jti-1")
                .build());
        when(registrationService.register(any())).thenReturn(false);

        mockMvc.perform(post("/institution-config/apply-provider-token")
                .with(req -> {
                    req.setRemoteAddr("127.0.0.1");
                    return req;
                })
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {"token":"valid-provider-token"}
                    """))
            .andExpect(status().isPartialContent())
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.registered").value(false))
            .andExpect(jsonPath("$.lockedFields[0]").value("providerName"))
            .andExpect(jsonPath("$.config.providerOrganization").value("token.edu"));

        verify(persistenceService).saveConfigurationFromToken(any(ProvisioningTokenPayload.class));
        verify(registrationService, never()).markAsRegistered(any());
    }

    @Test
    void applyConsumerToken_returnsBadRequestWhenTokenIsRejected() throws Exception {
        Properties props = new Properties();
        props.setProperty("marketplace.base-url", "https://marketplace.example.com");
        props.setProperty("public.base-url", "https://gateway.example.com");
        when(persistenceService.loadConfigurationSafe()).thenReturn(props);
        when(provisioningTokenService.validateAndExtractConsumer(anyString(), anyString(), anyString()))
            .thenThrow(new IllegalArgumentException("Invalid consumer provisioning token"));

        mockMvc.perform(post("/institution-config/apply-consumer-token")
                .with(req -> {
                    req.setRemoteAddr("127.0.0.1");
                    return req;
                })
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {"token":"bad-consumer-token"}
                    """))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.success").value(false))
            .andExpect(jsonPath("$.error").value("Invalid consumer provisioning token"));

        verify(persistenceService, never()).saveConfigurationFromConsumerToken(any(ConsumerProvisioningTokenPayload.class));
        verify(registrationService, never()).register(any());
    }

    @Test
    void saveAndRegister_returnsBadRequestForInvalidPublicBaseUrl() throws Exception {
        mockMvc.perform(post("/institution-config/save-and-register")
                .with(req -> {
                    req.setRemoteAddr("127.0.0.1");
                    return req;
                })
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                      "marketplaceBaseUrl":"https://marketplace.example.com",
                      "providerName":"Test University",
                      "providerEmail":"test@university.edu",
                      "providerCountry":"ES",
                      "providerOrganization":"test.edu",
                      "publicBaseUrl":"https://gateway.example.com/",
                      "provisioningToken":"valid-token"
                    }
                    """))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.success").value(false))
            .andExpect(jsonPath("$.error").value("Public base URL must not end with trailing slash"));

        verify(persistenceService, never()).saveConfiguration(any());
        verify(registrationService, never()).register(any());
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @Import({
        ProviderConfigurationController.class,
        LocalhostOnlyFilter.class
    })
    static class TestApplication {
    }
}
