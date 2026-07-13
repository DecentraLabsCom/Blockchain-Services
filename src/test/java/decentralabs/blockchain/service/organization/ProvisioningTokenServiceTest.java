package decentralabs.blockchain.service.organization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.dto.provider.ConsumerProvisioningTokenPayload;
import decentralabs.blockchain.dto.provider.ProvisioningTokenPayload;
import io.jsonwebtoken.Jwts;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.Mockito;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;

@ExtendWith(MockitoExtension.class)
class ProvisioningTokenServiceTest {

    private static final String MARKETPLACE_URL = "https://marketplace.example.com";
    private static final String PUBLIC_URL = "https://provider.example.com";
    private static final String PROVIDER_JWKS_URI = MARKETPLACE_URL + "/api/institutions/provisionToken/jwks";
    private static final String CONSUMER_JWKS_URI = MARKETPLACE_URL + "/api/institutions/provisionConsumer/jwks";
    private static final String KEY_ID = "test-kid";

    @Mock
    private RestTemplate restTemplate;

    private ProvisioningTokenService service;
    private KeyPair keyPair;
    private String jwksPayload;

    @BeforeEach
    void setUp() throws Exception {
        service = new ProvisioningTokenService();
        ReflectionTestUtils.setField(service, "restTemplate", restTemplate);
        ReflectionTestUtils.setField(service, "connectTimeoutMs", 5_000);
        ReflectionTestUtils.setField(service, "readTimeoutMs", 10_000);

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();
        jwksPayload = buildJwksJson(KEY_ID, (RSAPublicKey) keyPair.getPublic());

        Mockito.lenient().when(restTemplate.getForEntity(eq(java.net.URI.create(PROVIDER_JWKS_URI)), eq(String.class)))
            .thenReturn(ResponseEntity.ok(jwksPayload));
        Mockito.lenient().when(restTemplate.getForEntity(eq(java.net.URI.create(CONSUMER_JWKS_URI)), eq(String.class)))
            .thenReturn(ResponseEntity.ok(jwksPayload));
    }

    @Test
    void configureRestTemplate_appliesConfiguredTimeouts() {
        ReflectionTestUtils.invokeMethod(service, "configureRestTemplate");

        RestTemplate configured = (RestTemplate) ReflectionTestUtils.getField(service, "restTemplate");
        assertThat(configured).isNotNull();
        assertThat(configured.getRequestFactory()).isInstanceOf(SimpleClientHttpRequestFactory.class);

        SimpleClientHttpRequestFactory factory =
            (SimpleClientHttpRequestFactory) configured.getRequestFactory();
        assertThat(ReflectionTestUtils.getField(factory, "connectTimeout")).isEqualTo(5_000);
        assertThat(ReflectionTestUtils.getField(factory, "readTimeout")).isEqualTo(10_000);
    }

    @Test
    void validateAndExtract_returnsProviderPayloadForValidToken() {
        String token = createToken(
            Map.of(
                "marketplaceBaseUrl", MARKETPLACE_URL,
                "providerName", "Provider Name",
                "providerEmail", "ops@example.com",
                "providerCountry", "ES",
                "providerOrganization", "Decentra Labs",
                "publicBaseUrl", PUBLIC_URL,
                "walletAddress", "0x1234567890123456789012345678901234567890",
                "chainId", 11155111L,
                "verifyingContract", "0xe49a2f59631717691642f929E0FeF1f705866600",
                "registrationNonce", "registration-nonce-1"
            ),
            "provider-jti",
            MARKETPLACE_URL,
            PUBLIC_URL
        );

        ProvisioningTokenPayload payload = service.validateAndExtract(token, MARKETPLACE_URL + "/", PUBLIC_URL + "/");

        assertThat(payload.getMarketplaceBaseUrl()).isEqualTo(MARKETPLACE_URL);
        assertThat(payload.getProviderName()).isEqualTo("Provider Name");
        assertThat(payload.getProviderEmail()).isEqualTo("ops@example.com");
        assertThat(payload.getProviderCountry()).isEqualTo("ES");
        assertThat(payload.getProviderOrganization()).isEqualTo("Decentra Labs");
        assertThat(payload.getPublicBaseUrl()).isEqualTo(PUBLIC_URL);
        assertThat(payload.getJti()).isEqualTo("provider-jti");
        assertThat(payload.getWalletAddress()).isEqualTo("0x1234567890123456789012345678901234567890");
        assertThat(payload.getChainId()).isEqualTo(11155111L);
        assertThat(payload.getVerifyingContract()).isEqualTo("0xe49a2f59631717691642f929E0FeF1f705866600");
        assertThat(payload.getRegistrationNonce()).isEqualTo("registration-nonce-1");
    }

    @Test
    void validateAndExtract_allowsSafeRetryUntilDiamondConsumesJti() {
        String token = createToken(
            Map.of(
                "marketplaceBaseUrl", MARKETPLACE_URL,
                "providerName", "Provider Name",
                "providerEmail", "ops@example.com",
                "providerCountry", "ES",
                "providerOrganization", "Decentra Labs",
                "publicBaseUrl", PUBLIC_URL
            ),
            "replayed-jti",
            MARKETPLACE_URL,
            PUBLIC_URL
        );

        ProvisioningTokenPayload first = service.validateAndExtract(token, MARKETPLACE_URL, PUBLIC_URL);
        ProvisioningTokenPayload retry = service.validateAndExtract(token, MARKETPLACE_URL, PUBLIC_URL);

        assertThat(first.getJti()).isEqualTo("replayed-jti");
        assertThat(retry.getJti()).isEqualTo(first.getJti());
    }

    @Test
    void validateAndExtract_rejectsMarketplaceMismatchClaim() {
        String token = createToken(
            Map.of(
                "marketplaceBaseUrl", "https://evil.example.com",
                "providerName", "Provider Name",
                "providerEmail", "ops@example.com",
                "providerCountry", "ES",
                "providerOrganization", "Decentra Labs",
                "publicBaseUrl", PUBLIC_URL
            ),
            "provider-jti",
            MARKETPLACE_URL,
            PUBLIC_URL
        );

        assertThatThrownBy(() -> service.validateAndExtract(token, MARKETPLACE_URL, PUBLIC_URL))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Marketplace base URL mismatch");
    }

    @Test
    void validateAndExtract_rejectsMalformedJwt() {
        assertThatThrownBy(() -> service.validateAndExtract("not-a-jwt", MARKETPLACE_URL, PUBLIC_URL))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Malformed JWT");
    }

    @Test
    void validateAndExtract_rejectsInvalidProviderEmail() {
        String token = createToken(
            Map.of(
                "marketplaceBaseUrl", MARKETPLACE_URL,
                "providerName", "Provider Name",
                "providerEmail", "bad-email",
                "providerCountry", "ES",
                "providerOrganization", "Decentra Labs",
                "publicBaseUrl", PUBLIC_URL
            ),
            "provider-jti",
            MARKETPLACE_URL,
            PUBLIC_URL
        );

        assertThatThrownBy(() -> service.validateAndExtract(token, MARKETPLACE_URL, PUBLIC_URL))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Invalid provider email");
    }

    @Test
    void validateAndExtract_rejectsInvalidJwkSetFormat() {
        when(restTemplate.getForEntity(eq(java.net.URI.create(PROVIDER_JWKS_URI)), eq(String.class)))
            .thenReturn(ResponseEntity.ok("{\"keys\":{}}"));

        String token = createToken(
            Map.of(
                "marketplaceBaseUrl", MARKETPLACE_URL,
                "providerName", "Provider Name",
                "providerEmail", "ops@example.com",
                "providerCountry", "ES",
                "providerOrganization", "Decentra Labs",
                "publicBaseUrl", PUBLIC_URL
            ),
            "provider-jti",
            MARKETPLACE_URL,
            PUBLIC_URL
        );

        assertThatThrownBy(() -> service.validateAndExtract(token, MARKETPLACE_URL, PUBLIC_URL))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Invalid JWK set format");
    }

    @Test
    void validateAndExtractConsumer_acceptsConsumerTokenWithAudienceArray() {
        String token = createToken(
            Map.of(
                "type", "consumer",
                "marketplaceBaseUrl", MARKETPLACE_URL,
                "consumerName", "Consumer Name",
                "consumerOrganization", "Consumer Org"
            ),
            "consumer-jti",
            MARKETPLACE_URL,
            List.of(PUBLIC_URL, "https://fallback.example.com")
        );

        ConsumerProvisioningTokenPayload payload = service.validateAndExtractConsumer(token, MARKETPLACE_URL, "");

        assertThat(payload.getType()).isEqualTo("consumer");
        assertThat(payload.getMarketplaceBaseUrl()).isEqualTo(MARKETPLACE_URL);
        assertThat(payload.getConsumerName()).isEqualTo("Consumer Name");
        assertThat(payload.getConsumerOrganization()).isEqualTo("Consumer Org");
        assertThat(payload.getJti()).isEqualTo("consumer-jti");
    }

    @Test
    void validateAndExtract_rejectsUnconfiguredMarketplaceInsteadOfTrustingUnsignedClaim() {
        String token = createToken(
            Map.of(
                "marketplaceBaseUrl", MARKETPLACE_URL,
                "providerName", "Provider Name",
                "providerEmail", "ops@example.com",
                "providerCountry", "ES",
                "providerOrganization", "Decentra Labs",
                "publicBaseUrl", PUBLIC_URL
            ),
            "provider-jti",
            MARKETPLACE_URL,
            PUBLIC_URL
        );

        assertThatThrownBy(() -> service.validateAndExtract(token, "", PUBLIC_URL))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("must be configured");
    }

    @Test
    void validateAndExtract_rejectsRemoteHttpPublicBaseUrl() {
        String insecurePublicUrl = "http://provider.example.com";
        String token = createToken(
            Map.of(
                "marketplaceBaseUrl", MARKETPLACE_URL,
                "providerName", "Provider Name",
                "providerEmail", "ops@example.com",
                "providerCountry", "ES",
                "providerOrganization", "Decentra Labs",
                "publicBaseUrl", insecurePublicUrl
            ),
            "provider-http-jti",
            MARKETPLACE_URL,
            insecurePublicUrl
        );

        assertThatThrownBy(() -> service.validateAndExtract(token, MARKETPLACE_URL, insecurePublicUrl))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("HTTPS");
    }

    @Test
    void validateAndExtractConsumer_rejectsNonConsumerToken() {
        String token = createToken(
            Map.of(
                "marketplaceBaseUrl", MARKETPLACE_URL,
                "providerName", "Provider Name",
                "providerEmail", "ops@example.com",
                "providerCountry", "ES",
                "providerOrganization", "Decentra Labs",
                "publicBaseUrl", PUBLIC_URL
            ),
            "provider-jti",
            MARKETPLACE_URL,
            PUBLIC_URL
        );

        assertThatThrownBy(() -> service.validateAndExtractConsumer(token, MARKETPLACE_URL, PUBLIC_URL))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Token is not a consumer provisioning token");
    }

    private String createToken(Map<String, Object> claims, String jti, String issuer, Object audience) {
        long now = System.currentTimeMillis();
        Map<String, Object> signedClaims = new java.util.HashMap<>(claims);
        if (!"consumer".equals(signedClaims.get("type"))) {
            signedClaims.putIfAbsent("walletAddress", "0x1234567890123456789012345678901234567890");
            signedClaims.putIfAbsent("chainId", 11155111L);
            signedClaims.putIfAbsent("verifyingContract", "0xe49a2f59631717691642f929E0FeF1f705866600");
            signedClaims.putIfAbsent("registrationNonce", "registration-nonce-default");
        }
        return Jwts.builder()
            .header().keyId(KEY_ID).and()
            .claims(signedClaims)
            .issuer(issuer)
            .id(jti)
            .claim("aud", audience)
            .issuedAt(new Date(now))
            .expiration(new Date(now + 60_000))
            .signWith(keyPair.getPrivate())
            .compact();
    }

    private static String buildJwksJson(String kid, RSAPublicKey publicKey) {
        String modulus = Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.getModulus().toByteArray());
        String exponent = Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.getPublicExponent().toByteArray());
        return """
            {
              "keys": [
                {
                  "kty": "RSA",
                  "kid": "%s",
                  "use": "sig",
                  "alg": "RS256",
                  "n": "%s",
                  "e": "%s"
                }
              ]
            }
            """.formatted(kid, trimLeadingZero(modulus), trimLeadingZero(exponent));
    }

    private static String trimLeadingZero(String value) {
        byte[] decoded = Base64.getUrlDecoder().decode(value);
        if (decoded.length > 1 && decoded[0] == 0) {
            byte[] trimmed = new byte[decoded.length - 1];
            System.arraycopy(decoded, 1, trimmed, 0, trimmed.length);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(trimmed);
        }
        return value;
    }
}
