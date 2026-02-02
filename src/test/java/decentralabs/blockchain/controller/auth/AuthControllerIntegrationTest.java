package decentralabs.blockchain.controller.auth;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import decentralabs.blockchain.service.BackendUrlResolver; 
import decentralabs.blockchain.service.auth.KeyService;

@SpringBootTest(classes = AuthController.class)
@TestPropertySource(properties = {
    "endpoint.wallet-auth2=/auth/wallet-auth2",
    "endpoint.saml-auth2=/auth/saml-auth2",
    "endpoint.jwks=/auth/jwks"
})
class AuthControllerIntegrationTest {

    // Provide an ObjectMapper bean in the test context so WebApplicationContext registers JSON converters
    @org.springframework.boot.test.context.TestConfiguration
    static class JacksonTestConfig {
        @org.springframework.context.annotation.Bean
        public com.fasterxml.jackson.databind.ObjectMapper objectMapper() {
            return new com.fasterxml.jackson.databind.ObjectMapper();
        }

        @org.springframework.context.annotation.Bean
        public decentralabs.blockchain.config.JacksonHttpMessageConverter jacksonConverter(com.fasterxml.jackson.databind.ObjectMapper om) {
            return new decentralabs.blockchain.config.JacksonHttpMessageConverter(om);
        }

        @org.springframework.context.annotation.Bean
        public org.springframework.web.servlet.config.annotation.WebMvcConfigurer testWebMvcConfigurer(decentralabs.blockchain.config.JacksonHttpMessageConverter conv) {
            return new org.springframework.web.servlet.config.annotation.WebMvcConfigurer() {
                @Override
                public void extendMessageConverters(java.util.List<org.springframework.http.converter.HttpMessageConverter<?>> converters) {
                    // ensure JSON converter has priority
                    converters.add(0, conv);
                }
            };
        }
    }


    private MockMvc mockMvc;

    @BeforeEach
    public void setup() {
        // Standalone controller with injected mocks (avoids context-level side effects like KeyService PostConstruct)
        AuthController controller = new AuthController();
        org.springframework.test.util.ReflectionTestUtils.setField(controller, "keyService", this.keyService);
        org.springframework.test.util.ReflectionTestUtils.setField(controller, "backendUrlResolver", this.backendUrlResolver);
        // Manually set @Value-injected fields since we instantiate controller directly
        org.springframework.test.util.ReflectionTestUtils.setField(controller, "authPath", "/auth");
        org.springframework.test.util.ReflectionTestUtils.setField(controller, "walletAuth2Endpoint", "/auth/wallet-auth2");
        org.springframework.test.util.ReflectionTestUtils.setField(controller, "samlAuth2Endpoint", "/auth/saml-auth2");
        org.springframework.test.util.ReflectionTestUtils.setField(controller, "jwksEndpoint", "/auth/jwks");

        this.mockMvc = MockMvcBuilders.standaloneSetup(controller)
            .setMessageConverters(new decentralabs.blockchain.config.JacksonHttpMessageConverter(new com.fasterxml.jackson.databind.ObjectMapper()))
            .setControllerAdvice(new decentralabs.blockchain.exception.GlobalExceptionHandler())
            .defaultRequest(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/").accept(org.springframework.http.MediaType.APPLICATION_JSON))
            .build();
    }

    @MockitoBean
    private KeyService keyService;

    @MockitoBean
    private BackendUrlResolver backendUrlResolver;

    @Test
    void shouldExposeOpenIdConfiguration() throws Exception {
        when(backendUrlResolver.resolveBaseDomain()).thenReturn("https://backend.example.com");

        mockMvc.perform(get("/.well-known/openid-configuration"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.issuer").value("https://backend.example.com/auth"))
            .andExpect(jsonPath("$.authorization_endpoint").value("https://backend.example.com/auth/wallet-auth2"))
            .andExpect(jsonPath("$.jwks_uri").value("https://backend.example.com/auth/jwks"));
    }

    @Test
    void shouldExposeJwks() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        when(keyService.getPublicKey()).thenReturn(publicKey);

        mockMvc.perform(get("/auth/jwks"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
            .andExpect(jsonPath("$.keys[0].use").value("sig"))
            .andExpect(jsonPath("$.keys[0].n").exists())
            .andExpect(jsonPath("$.keys[0].e").exists())
            .andExpect(jsonPath("$.keys[0].kid").exists());
    }

    @Test
    void shouldHandleKeyServiceError() throws Exception {
        when(keyService.getPublicKey())
            .thenThrow(new RuntimeException("Key service unavailable"));

        mockMvc.perform(get("/auth/jwks"))
            .andExpect(status().isInternalServerError());
    }

    @Test
    void shouldReturnCorrectKeyFormat() throws Exception {
        // Generate a test RSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        when(keyService.getPublicKey())
            .thenReturn(publicKey);

        mockMvc.perform(get("/auth/jwks"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
            .andExpect(jsonPath("$.keys[0].alg").value("RS256"))
            .andExpect(jsonPath("$.keys[0].use").value("sig"))
            // Verify Base64URL encoding (no padding, URL-safe characters)
            .andExpect(jsonPath("$.keys[0].n").value(org.hamcrest.Matchers.matchesPattern("^[A-Za-z0-9_-]+$")))
            .andExpect(jsonPath("$.keys[0].e").value(org.hamcrest.Matchers.matchesPattern("^[A-Za-z0-9_-]+$")))
            .andExpect(jsonPath("$.keys[0].kid").value(org.hamcrest.Matchers.matchesPattern("^[A-Za-z0-9_-]+$")));
    }

    @Test
    void shouldHandleBackendUrlResolverError() throws Exception {
        when(backendUrlResolver.resolveBaseDomain())
            .thenThrow(new RuntimeException("Backend resolver error"));

        // OpenID config should still work with default values
        mockMvc.perform(get("/.well-known/openid-configuration"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.issuer").exists());
    }
}
