package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import io.jsonwebtoken.Jwts;
import decentralabs.blockchain.util.PucHashUtil;

class ExternalOidcTokenValidationServiceTest {

    private KeyPair keyPair;
    private String token;
    private RestTemplate restTemplate;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();
        token = Jwts.builder()
            .header().add("kid", "entra-key").and()
            .issuer("https://login.microsoftonline.com/tenant-1/v2.0")
            .subject("pairwise-subject-123")
            .audience().add("client-123").and()
            .claim("tid", "tenant-1")
            .claim("oid", "oid-123")
            .claim("nonce", "nonce-1")
            .issuedAt(new java.util.Date())
            .expiration(new java.util.Date(System.currentTimeMillis() + 60_000))
            .signWith(keyPair.getPrivate())
            .compact();
        restTemplate = mock(RestTemplate.class);
    }

    @AfterEach
    void tearDown() {
        // Kept as a lifecycle hook so future provider fixtures cannot leak state.
    }

    @Test
    void validatesSignatureAndBindsTokenToMarketplaceEvidence() throws Exception {
        String jwksUrl = "https://login.microsoftonline.com/common/discovery/v2.0/keys";
        when(restTemplate.getForEntity(java.net.URI.create(jwksUrl), String.class)).thenReturn(ResponseEntity.ok(jwks()));
        var service = service(jwksUrl);

        var result = service.validate(
            "entra-id",
            token,
            "https://login.microsoftonline.com/tenant-1/v2.0",
            "oid-123",
            PucHashUtil.hashPuc(token),
            "nonce-1"
        );

        assertThat(result.tenantId()).isEqualTo("tenant-1");
        assertThat(result.subject()).isEqualTo("oid-123");
    }

    @Test
    void rejectsEvidenceThatDoesNotMatchTheSubmittedToken() throws Exception {
        var service = service("https://login.microsoftonline.com/common/discovery/v2.0/keys");

        assertThatThrownBy(() -> service.validate(
            "entra-id", token,
            "https://login.microsoftonline.com/tenant-1/v2.0",
            "oid-123",
            "0x" + "a".repeat(64),
            "nonce-1"
        )).hasMessageContaining("evidence hash mismatch");
    }

    @Test
    void rejectsAnUntrustedTenantEvenWhenTheSignatureIsValid() throws Exception {
        String jwksUrl = "https://login.microsoftonline.com/common/discovery/v2.0/keys";
        when(restTemplate.getForEntity(java.net.URI.create(jwksUrl), String.class)).thenReturn(ResponseEntity.ok(jwks()));
        var service = new ExternalOidcTokenValidationService(
            restTemplate,
            new ObjectMapper(),
            true,
            List.of("https://login.microsoftonline.com/tenant-1/v2.0"),
            List.of("client-123"),
            jwksUrl,
            List.of("tenant-2"),
            60
        );

        assertThatThrownBy(() -> service.validate(
            "entra-id", token,
            "https://login.microsoftonline.com/tenant-1/v2.0",
            "oid-123",
            PucHashUtil.hashPuc(token),
            "nonce-1"
        )).hasMessageContaining("tenant is not allowed");
    }

    private ExternalOidcTokenValidationService service(String jwksUrl) throws Exception {
        return new ExternalOidcTokenValidationService(
            restTemplate,
            new ObjectMapper(),
            true,
            List.of("https://login.microsoftonline.com/tenant-1/v2.0"),
            List.of("client-123"),
            jwksUrl,
            List.of("tenant-1"),
            60
        );
    }

    private String jwks() throws Exception {
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        return new ObjectMapper().writeValueAsString(java.util.Map.of(
            "keys", List.of(java.util.Map.of(
                "kty", "RSA",
                "use", "sig",
                "alg", "RS256",
                "kid", "entra-key",
                "n", Base64.getUrlEncoder().withoutPadding().encodeToString(unsigned(publicKey.getModulus())),
                "e", Base64.getUrlEncoder().withoutPadding().encodeToString(unsigned(publicKey.getPublicExponent()))
            ))
        ));
    }

    private byte[] unsigned(java.math.BigInteger value) {
        byte[] bytes = value.toByteArray();
        return bytes.length > 1 && bytes[0] == 0
            ? java.util.Arrays.copyOfRange(bytes, 1, bytes.length)
            : bytes;
    }
}
