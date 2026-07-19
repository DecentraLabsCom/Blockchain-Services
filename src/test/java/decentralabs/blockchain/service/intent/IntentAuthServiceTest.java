package decentralabs.blockchain.service.intent;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.lenient;

import decentralabs.blockchain.service.auth.MarketplaceKeyService;
import decentralabs.blockchain.service.BackendUrlResolver;
import io.jsonwebtoken.Jwts;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.Date;
import java.util.List;
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
class IntentAuthServiceTest {

    @Mock
    private MarketplaceKeyService marketplaceKeyService;

    @Mock
    private BackendUrlResolver backendUrlResolver;

    @InjectMocks
    private IntentAuthService service;

    private KeyPair keyPair;

    @BeforeEach
    void setUp() throws Exception {
        ReflectionTestUtils.setField(service, "enabled", true);
        ReflectionTestUtils.setField(service, "issuer", "marketplace");
        ReflectionTestUtils.setField(service, "audience", "https://backend.example.edu");
        ReflectionTestUtils.setField(service, "institutionId", "institution.edu");
        ReflectionTestUtils.setField(service, "serviceSubject", "marketplace");
        ReflectionTestUtils.setField(service, "maxTtlSeconds", 60L);
        ReflectionTestUtils.setField(service, "submitScope", "intents:submit");
        ReflectionTestUtils.setField(service, "statusScope", "intents:status");
        ReflectionTestUtils.setField(service, "clockSkewSeconds", 60L);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        keyPair = keyGen.generateKeyPair();
        lenient().when(marketplaceKeyService.getPublicKey(false)).thenReturn(keyPair.getPublic());
    }

    @Test
    void disabledAuthorization_skipsValidation() {
        ReflectionTestUtils.setField(service, "enabled", false);

        assertThatCode(() -> service.enforceSubmitAuthorization(null)).doesNotThrowAnyException();
        assertThatCode(() -> service.enforceStatusAuthorization(null)).doesNotThrowAnyException();
    }

    @Test
    void submitAuthorization_rejectsMissingBearerHeader() {
        assertThatThrownBy(() -> service.enforceSubmitAuthorization(null))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("missing_intents_token");
    }

    @Test
    void submitAuthorization_rejectsInvalidToken() {
        assertThatThrownBy(() -> service.enforceSubmitAuthorization("Bearer not-a-jwt"))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("invalid_intents_token");
    }

    @Test
    void submitAuthorization_acceptsValidTokenWithStringScope() {
        String jwt = makeJwt(Map.of("scope", "intents:submit"));

        assertThatCode(() -> service.enforceSubmitAuthorization("Bearer " + jwt)).doesNotThrowAnyException();
    }

    @Test
    void statusAuthorization_acceptsValidTokenWithCollectionScope() {
        String jwt = makeJwt(Map.of("scopes", List.of("intents:status")));

        assertThatCode(() -> service.enforceStatusAuthorization("Bearer " + jwt)).doesNotThrowAnyException();
    }

    @Test
    void submitAuthorization_rejectsMissingScope() {
        String jwt = makeJwt(Map.of("scope", "read write"));

        assertThatThrownBy(() -> service.enforceSubmitAuthorization("Bearer " + jwt))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("missing_intents_scope");
    }

    @Test
    void authorizationAndRegistrationUseDedicatedScopes() {
        String authorizationJwt = makeJwt(Map.of("scope", "intents:authorize"));
        assertThatCode(() -> service.enforceAuthorizeAuthorization("Bearer " + authorizationJwt))
            .doesNotThrowAnyException();
        assertThatThrownBy(() -> service.enforceSubmitAuthorization("Bearer " + authorizationJwt))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("missing_intents_scope");

        String minedJwt = makeJwt(Map.of("scope", "intents:registration-mined"));
        assertThatCode(() -> service.enforceRegistrationMinedAuthorization("Bearer " + minedJwt))
            .doesNotThrowAnyException();
    }

    @Test
    void submitAuthorization_rejectsTokenForAnotherBackendAudience() {
        String jwt = makeJwt(Map.of("scope", "intents:submit", "aud", "https://other-backend.example"));

        assertThatThrownBy(() -> service.enforceSubmitAuthorization("Bearer " + jwt))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("invalid_intents_token");
    }

    @Test
    void submitAuthorization_rejectsBadPrefix() {
        assertThatThrownBy(() -> service.enforceSubmitAuthorization("Token abc"))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("missing_intents_token");
    }

    @Test
    void submitAuthorization_rejectsTokenForAnotherInstitution() {
        String jwt = makeJwt(Map.of("scope", "intents:submit", "institutionId", "other.edu"));

        assertThatThrownBy(() -> service.enforceSubmitAuthorization("Bearer " + jwt))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("invalid_intents_token");
    }

    @Test
    void submitAuthorization_rejectsNonMarketplaceSubject() {
        String jwt = makeJwt(Map.of("scope", "intents:submit", "sub", "blockchain-services"));

        assertThatThrownBy(() -> service.enforceSubmitAuthorization("Bearer " + jwt))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("invalid_intents_token");
    }

    @Test
    void submitAuthorization_rejectsMissingJti() {
        String jwt = makeJwt(Map.of("scope", "intents:submit"), false);

        assertThatThrownBy(() -> service.enforceSubmitAuthorization("Bearer " + jwt))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("invalid_intents_token");
    }

    private String makeJwt(Map<String, Object> claims) {
        return makeJwt(claims, true);
    }

    private String makeJwt(Map<String, Object> claims, boolean includeJti) {
        PrivateKey privateKey = keyPair.getPrivate();
        long now = System.currentTimeMillis();
        Map<String, Object> payload = new java.util.HashMap<>(claims);
        payload.putIfAbsent("aud", "https://backend.example.edu");
        payload.putIfAbsent("sub", "marketplace");
        payload.putIfAbsent("institutionId", "institution.edu");
        var builder = Jwts.builder()
            .claims(payload)
            .issuer("marketplace")
            .issuedAt(new Date(now))
            .expiration(new Date(now + 30_000));
        if (includeJti) {
            builder.id(java.util.UUID.randomUUID().toString());
        }
        return builder.signWith(privateKey).compact();
    }
}
