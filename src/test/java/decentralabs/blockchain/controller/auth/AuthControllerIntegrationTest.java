package decentralabs.blockchain.controller.auth;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import decentralabs.blockchain.service.GatewayUrlResolver;
import decentralabs.blockchain.service.auth.KeyService;

@WebMvcTest(controllers = AuthController.class)
@AutoConfigureMockMvc(addFilters = false)
@TestPropertySource(properties = {
    "endpoint.wallet-auth2=/auth/wallet-auth2",
    "endpoint.saml-auth2=/auth/saml-auth2",
    "endpoint.jwks=/auth/jwks"
})
class AuthControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private KeyService keyService;

    @MockitoBean
    private GatewayUrlResolver gatewayUrlResolver;

    @Test
    void shouldExposeOpenIdConfiguration() throws Exception {
        when(gatewayUrlResolver.resolveBaseDomain()).thenReturn("https://gateway.example.com");

        mockMvc.perform(get("/.well-known/openid-configuration"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.issuer").value("https://gateway.example.com/auth"))
            .andExpect(jsonPath("$.authorization_endpoint").value("https://gateway.example.com/auth/wallet-auth2"))
            .andExpect(jsonPath("$.jwks_uri").value("https://gateway.example.com/auth/jwks"));
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
    void shouldHandleGatewayUrlResolverError() throws Exception {
        when(gatewayUrlResolver.resolveBaseDomain())
            .thenThrow(new RuntimeException("Gateway resolver error"));

        // OpenID config should still work with default values
        mockMvc.perform(get("/.well-known/openid-configuration"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.issuer").exists());
    }
}
