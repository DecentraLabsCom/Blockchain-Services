package decentralabs.blockchain.controller.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;

import decentralabs.blockchain.service.GatewayUrlResolver;
import decentralabs.blockchain.service.auth.KeyService;

/**
 * Unit tests for AuthController.
 * Tests OpenID configuration and JWKS endpoints directly (not via MockMvc)
 * to avoid Spring placeholder resolution issues in standalone mode.
 */
@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    @Mock
    private KeyService keyService;

    @Mock
    private GatewayUrlResolver gatewayUrlResolver;

    @InjectMocks
    private AuthController authController;

    private KeyPair keyPair;

    @BeforeEach
    void setUp() throws Exception {
        // Generate real RSA keys
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        keyPair = keyGen.generateKeyPair();

        // Set configuration values via reflection
        ReflectionTestUtils.setField(authController, "authPath", "/auth");
        ReflectionTestUtils.setField(authController, "walletAuth2Endpoint", "/auth/wallet/v2");
        ReflectionTestUtils.setField(authController, "samlAuth2Endpoint", "/auth/saml/v2");
        ReflectionTestUtils.setField(authController, "jwksEndpoint", "/auth/.well-known/jwks.json");
    }

    @Nested
    @DisplayName("OpenID Configuration Endpoint Tests")
    class OpenIdConfigTests {

        @Test
        @DisplayName("Should return OpenID configuration with correct issuer")
        void shouldReturnOpenIdConfigurationWithIssuer() {
            when(gatewayUrlResolver.resolveBaseDomain()).thenReturn("https://gateway.example.com");

            ResponseEntity<Map<String, Object>> response = authController.openidConfig();

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).containsKey("issuer");
            assertThat(response.getBody().get("issuer")).isEqualTo("https://gateway.example.com/auth");
        }

        @Test
        @DisplayName("Should return authorization endpoint in config")
        void shouldReturnAuthorizationEndpoint() {
            when(gatewayUrlResolver.resolveBaseDomain()).thenReturn("https://gateway.example.com");

            ResponseEntity<Map<String, Object>> response = authController.openidConfig();

            assertThat(response.getBody()).containsKey("authorization_endpoint");
            assertThat(response.getBody().get("authorization_endpoint"))
                .isEqualTo("https://gateway.example.com/auth/wallet/v2");
        }

        @Test
        @DisplayName("Should return JWKS URI in config")
        void shouldReturnJwksUri() {
            when(gatewayUrlResolver.resolveBaseDomain()).thenReturn("https://gateway.example.com");

            ResponseEntity<Map<String, Object>> response = authController.openidConfig();

            assertThat(response.getBody()).containsKey("jwks_uri");
            assertThat(response.getBody().get("jwks_uri"))
                .isEqualTo("https://gateway.example.com/auth/.well-known/jwks.json");
        }

        @Test
        @DisplayName("Should use configured base domain")
        void shouldUseConfiguredBaseDomain() {
            when(gatewayUrlResolver.resolveBaseDomain()).thenReturn("https://custom.domain.org");

            ResponseEntity<Map<String, Object>> response = authController.openidConfig();

            assertThat(response.getBody().get("issuer")).isEqualTo("https://custom.domain.org/auth");
        }
    }

    @Nested
    @DisplayName("JWKS Endpoint Tests")
    class JwksEndpointTests {

        @Test
        @DisplayName("Should return JWKS with RSA key")
        void shouldReturnJwksWithRsaKey() throws Exception {
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            when(keyService.getPublicKey()).thenReturn(publicKey);

            ResponseEntity<Map<String, Object>> response = authController.getJWKS();

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).containsKey("keys");
        }

        @Test
        @DisplayName("Should include key type RSA in JWKS")
        @SuppressWarnings("unchecked")
        void shouldIncludeKeyTypeRsa() throws Exception {
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            when(keyService.getPublicKey()).thenReturn(publicKey);

            ResponseEntity<Map<String, Object>> response = authController.getJWKS();
            List<Map<String, Object>> keys = (List<Map<String, Object>>) response.getBody().get("keys");

            assertThat(keys).hasSize(1);
            assertThat(keys.get(0).get("kty")).isEqualTo("RSA");
        }

        @Test
        @DisplayName("Should include algorithm RS256 in JWKS")
        @SuppressWarnings("unchecked")
        void shouldIncludeAlgorithmRs256() throws Exception {
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            when(keyService.getPublicKey()).thenReturn(publicKey);

            ResponseEntity<Map<String, Object>> response = authController.getJWKS();
            List<Map<String, Object>> keys = (List<Map<String, Object>>) response.getBody().get("keys");

            assertThat(keys.get(0).get("alg")).isEqualTo("RS256");
        }

        @Test
        @DisplayName("Should include use signature in JWKS")
        @SuppressWarnings("unchecked")
        void shouldIncludeUseSignature() throws Exception {
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            when(keyService.getPublicKey()).thenReturn(publicKey);

            ResponseEntity<Map<String, Object>> response = authController.getJWKS();
            List<Map<String, Object>> keys = (List<Map<String, Object>>) response.getBody().get("keys");

            assertThat(keys.get(0).get("use")).isEqualTo("sig");
        }

        @Test
        @DisplayName("Should include modulus and exponent in JWKS")
        @SuppressWarnings("unchecked")
        void shouldIncludeModulusAndExponent() throws Exception {
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            when(keyService.getPublicKey()).thenReturn(publicKey);

            ResponseEntity<Map<String, Object>> response = authController.getJWKS();
            List<Map<String, Object>> keys = (List<Map<String, Object>>) response.getBody().get("keys");

            assertThat(keys.get(0)).containsKey("n"); // modulus
            assertThat(keys.get(0)).containsKey("e"); // exponent
            assertThat(keys.get(0).get("n")).isNotNull();
            assertThat(keys.get(0).get("e")).isNotNull();
        }

        @Test
        @DisplayName("Should include kid in JWKS")
        @SuppressWarnings("unchecked")
        void shouldIncludeKid() throws Exception {
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            when(keyService.getPublicKey()).thenReturn(publicKey);

            ResponseEntity<Map<String, Object>> response = authController.getJWKS();
            List<Map<String, Object>> keys = (List<Map<String, Object>>) response.getBody().get("keys");

            assertThat(keys.get(0)).containsKey("kid");
            assertThat(keys.get(0).get("kid")).isNotNull();
        }

        @Test
        @DisplayName("Should return 500 when key service fails")
        void shouldReturn500WhenKeyServiceFails() throws Exception {
            when(keyService.getPublicKey()).thenThrow(new RuntimeException("Key not found"));

            ResponseEntity<Map<String, Object>> response = authController.getJWKS();

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        }

        @Test
        @DisplayName("Should generate consistent kid for same key")
        @SuppressWarnings("unchecked")
        void shouldGenerateConsistentKidForSameKey() throws Exception {
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            when(keyService.getPublicKey()).thenReturn(publicKey);

            ResponseEntity<Map<String, Object>> response1 = authController.getJWKS();
            ResponseEntity<Map<String, Object>> response2 = authController.getJWKS();

            List<Map<String, Object>> keys1 = (List<Map<String, Object>>) response1.getBody().get("keys");
            List<Map<String, Object>> keys2 = (List<Map<String, Object>>) response2.getBody().get("keys");

            assertThat(keys1.get(0).get("kid")).isEqualTo(keys2.get(0).get("kid"));
        }
    }

    @Nested
    @DisplayName("Key Encoding Tests")
    class KeyEncodingTests {

        @Test
        @DisplayName("Should encode modulus as Base64URL without padding")
        @SuppressWarnings("unchecked")
        void shouldEncodeModulusAsBase64UrlWithoutPadding() throws Exception {
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            when(keyService.getPublicKey()).thenReturn(publicKey);

            ResponseEntity<Map<String, Object>> response = authController.getJWKS();
            List<Map<String, Object>> keys = (List<Map<String, Object>>) response.getBody().get("keys");
            String modulus = (String) keys.get(0).get("n");

            // Base64URL should not contain padding (=) or standard Base64 characters (+, /)
            assertThat(modulus).doesNotContain("=");
            assertThat(modulus).doesNotContain("+");
            assertThat(modulus).doesNotContain("/");
        }

        @Test
        @DisplayName("Should encode exponent correctly")
        @SuppressWarnings("unchecked")
        void shouldEncodeExponentCorrectly() throws Exception {
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            when(keyService.getPublicKey()).thenReturn(publicKey);

            ResponseEntity<Map<String, Object>> response = authController.getJWKS();
            List<Map<String, Object>> keys = (List<Map<String, Object>>) response.getBody().get("keys");
            String exponent = (String) keys.get(0).get("e");

            // Common public exponent (65537) encodes to "AQAB"
            BigInteger pubExp = publicKey.getPublicExponent();
            if (pubExp.intValue() == 65537) {
                assertThat(exponent).isEqualTo("AQAB");
            } else {
                assertThat(exponent).isNotEmpty();
            }
        }
    }
}
