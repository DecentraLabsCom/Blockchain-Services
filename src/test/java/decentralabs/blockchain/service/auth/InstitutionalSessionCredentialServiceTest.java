package decentralabs.blockchain.service.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.lenient;

import decentralabs.blockchain.service.BackendUrlResolver;
import decentralabs.blockchain.service.intent.IntentPayloadCipher;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import java.time.Instant;
import java.util.Date;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class InstitutionalSessionCredentialServiceTest {

    @Mock
    private JwtService jwtService;

    @Mock
    private BackendUrlResolver backendUrlResolver;

    @Mock
    private IntentPayloadCipher payloadCipher;

    @Captor
    private ArgumentCaptor<java.util.Map<String, Object>> tokenClaimsCaptor;

    private InstitutionalSessionCredentialService service;

    @BeforeEach
    void setUp() {
        service = new InstitutionalSessionCredentialService(jwtService, backendUrlResolver, payloadCipher);
        ReflectionTestUtils.setField(service, "ttlSeconds", 3600L);
        lenient().when(backendUrlResolver.resolveBaseDomain()).thenReturn("https://backend.example");
        lenient().when(payloadCipher.encrypt("user@example.edu")).thenReturn("ciphertext");
    }

    @Test
    void issuesABackendOwnedCredentialWithEncryptedPucAndAbsoluteHorizon() throws Exception {
        when(jwtService.generateToken(any(), any())).thenReturn("backend-session-token");

        InstitutionalSessionCredentialService.IssuedCredential issued = service.issue(
            "UNED.ES",
            "user@example.edu",
            "principal",
            "0x" + "a".repeat(64)
        );

        assertEquals("backend-session-token", issued.token());
        assertEquals("uned.es", issued.institutionId());
        assertEquals("0x" + "a".repeat(64), issued.samlAssertionHash());
        verify(jwtService).generateToken(tokenClaimsCaptor.capture(), org.mockito.ArgumentMatchers.isNull());
        assertEquals("ciphertext", tokenClaimsCaptor.getValue().get("pucCiphertext"));
        assertEquals(issued.expiresAt().getEpochSecond(), tokenClaimsCaptor.getValue().get("reauthenticationAt"));
    }

    @Test
    void validatesTheBackendCredentialAndDecryptsItsPuc() {
        Instant issuedAt = Instant.now().minusSeconds(30);
        Instant expiresAt = Instant.now().plusSeconds(3600);
        Claims claims = buildClaims(issuedAt, expiresAt, true);
        when(jwtService.extractAllClaims("token")).thenReturn(claims);
        when(payloadCipher.decrypt("ciphertext")).thenReturn("user@example.edu");

        InstitutionalSessionCredentialService.Credential credential = service.validate("token");

        assertEquals("user@example.edu", credential.puc());
        assertEquals("uned.es", credential.institutionId());
        assertEquals(expiresAt.getEpochSecond(), credential.expiresAt().getEpochSecond());
    }

    @Test
    void rejectsCredentialsWithAnExpiredReauthenticationHorizon() {
        Instant expiredAt = Instant.now().minusSeconds(1);
        Claims claims = buildClaims(Instant.now().minusSeconds(3600), expiredAt, true);
        when(jwtService.extractAllClaims("expired")).thenReturn(claims);

        ResponseStatusException exception = assertThrows(
            ResponseStatusException.class,
            () -> service.validate("expired")
        );
        assertEquals("invalid_institutional_session", exception.getReason());
    }

    private Claims buildClaims(Instant issuedAt, Instant expiresAt, boolean includeMode) {
        var builder = Jwts.claims()
            .subject("institutional-session")
            .id("session-jti")
            .issuedAt(Date.from(issuedAt))
            .expiration(Date.from(expiresAt))
            .add("sessionType", "institutional_saml_session")
            .add("aud", "https://backend.example")
            .add("institutionId", "uned.es")
            .add("pucCiphertext", "ciphertext")
            .add("samlAssertionHash", "0x" + "a".repeat(64))
            .add("reauthenticationAt", expiresAt.getEpochSecond());
        if (includeMode) builder.add("stableUserIdMode", "principal");
        return builder.build();
    }
}
