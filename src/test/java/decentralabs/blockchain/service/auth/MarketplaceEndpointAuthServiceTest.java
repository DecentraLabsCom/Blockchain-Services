package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.jsonwebtoken.Jwts;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.Date;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class MarketplaceEndpointAuthServiceTest {

    @Mock
    private MarketplaceKeyService marketplaceKeyService;

    @InjectMocks
    private MarketplaceEndpointAuthService service;

    private KeyPair keyPair;

    @BeforeEach
    void setUp() throws Exception {
        // default configuration values
        ReflectionTestUtils.setField(service, "enabled", true);
        ReflectionTestUtils.setField(service, "issuer", "marketplace");
        ReflectionTestUtils.setField(service, "audience", "blockchain-services");
        ReflectionTestUtils.setField(service, "clockSkewSeconds", 60L);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        keyPair = keyGen.generateKeyPair();
        // lenient stub because some tests do not exercise token parsing
        org.mockito.Mockito.lenient().when(marketplaceKeyService.getPublicKey(false))
                .thenReturn(keyPair.getPublic());
    }

    private String makeJwt(Map<String, Object> claims) {
        PrivateKey privateKey = keyPair.getPrivate();
        long now = System.currentTimeMillis();
        // add audience claim manually (newer JwtBuilder API expects the audience helper to be used via the builder,
        // but that helper doesn't accept a single string parameter, so it's simpler to include it in the map)
        Map<String, Object> payload = new java.util.HashMap<>(claims);
        payload.put("aud", "blockchain-services");
        return Jwts.builder()
                .claims(payload)
                .issuer("marketplace")
                .issuedAt(new Date(now))
                .expiration(new Date(now + 60_000))
                .signWith(privateKey) // algorithm chosen based on key (RS256)
                .compact();
    }

    @Test
    void shouldReturnEmptyMapWhenDisabled() {
        ReflectionTestUtils.setField(service, "enabled", false);
        assertThat(service.enforceAuthorization(null, "anything")).isEmpty();
        assertThat(service.enforceToken(null, "foo")).isEmpty();
    }

    @Test
    void shouldRejectMissingToken() {
        assertThatThrownBy(() -> service.enforceToken(null, null))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("missing_marketplace_token");
    }

    @Test
    void shouldRejectInvalidToken() {
        assertThatThrownBy(() -> service.enforceToken("not-a-token", null))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("invalid_marketplace_token");
    }

    @Test
    void shouldRejectWhenScopeMissing() {
        String jwt = makeJwt(Map.of("userid", "u1", "scope", "read write"));
        Map<String, Object> claims = service.enforceToken(jwt, null);
        assertThat(claims).containsEntry("userid", "u1");

        assertThatThrownBy(() -> service.enforceToken(jwt, "admin:manage"))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("missing_marketplace_scope");
    }

    @Test
    void shouldReturnClaimsWhenValidAndScopePresent() {
        String jwt = makeJwt(Map.of("userid", "u1", "scope", "foo bar"));
        Map<String, Object> claims = service.enforceToken(jwt, "bar");
        assertThat(claims).containsEntry("userid", "u1");
    }

    @Test
    void enforceAuthorizationShouldHandleBearerHeader() {
        String jwt = makeJwt(Map.of("userid", "u2"));
        String header = "Bearer " + jwt;
        Map<String, Object> claims = service.enforceAuthorization(header, null);
        assertThat(claims).containsEntry("userid", "u2");
    }

    @Test
    void enforceAuthorizationShouldIgnoreBadPrefix() {
        // not a bearer prefix -> token extracted will be null -> UNAUTHORIZED
        assertThatThrownBy(() -> service.enforceAuthorization("Token abc", null))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("missing_marketplace_token");
    }

    @Test
    void scopeClaimAsCollectionShouldWork() {
        String jwt = makeJwt(Map.of("userid", "u3", "scopes", java.util.List.of("a", "b")));
        Map<String, Object> claims = service.enforceToken(jwt, "b");
        assertThat(claims).containsEntry("userid", "u3");
    }
}
