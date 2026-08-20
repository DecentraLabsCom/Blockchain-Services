package decentralabs.blockchain.service.intent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import decentralabs.blockchain.dto.intent.ActionIntentPayload;
import decentralabs.blockchain.dto.intent.IntentAckResponse;
import decentralabs.blockchain.dto.intent.IntentAuthorizationCompleteRequest;
import decentralabs.blockchain.dto.intent.IntentAuthorizationRequest;
import decentralabs.blockchain.dto.intent.IntentAuthorizationStatusResponse;
import decentralabs.blockchain.dto.intent.IntentMeta;
import decentralabs.blockchain.dto.intent.IntentSubmission;
import decentralabs.blockchain.service.BackendUrlResolver;
import decentralabs.blockchain.service.auth.InstitutionalSessionCredentialService;
import decentralabs.blockchain.service.auth.WebauthnCredentialService;
import decentralabs.blockchain.service.auth.WebauthnCredentialService.WebauthnCredential;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class IntentAuthorizationServiceTest {

    @Mock
    private IntentService intentService;

    @Mock
    private IntentExecutionService intentExecutionService;

    @Mock
    private WebauthnCredentialService webauthnCredentialService;

    @Mock
    private InstitutionalSessionCredentialService institutionalSessionCredentialService;

    @Mock
    private BackendUrlResolver backendUrlResolver;

    private IntentAuthorizationService service;

    @Mock
    private IntentAuthorizationSessionPersistenceService sessionPersistence;

    private final Map<String, IntentAuthorizationSessionPersistenceService.StoredSession> storedSessions =
        new HashMap<>();

    @BeforeEach
    void setUp() throws Exception {
        service = new IntentAuthorizationService(
            intentService,
            intentExecutionService,
            webauthnCredentialService,
            institutionalSessionCredentialService,
            backendUrlResolver,
            sessionPersistence
        );
        ReflectionTestUtils.setField(service, "rpId", "example.com");
        ReflectionTestUtils.setField(service, "baseUrl", "https://backend.example/");
        ReflectionTestUtils.setField(service, "sessionTtlSeconds", 300L);
        ReflectionTestUtils.setField(service, "cleanupIntervalSeconds", 60L);
        ReflectionTestUtils.setField(service, "processingLeaseSeconds", 60L);
        storedSessions.clear();
        org.mockito.Mockito.doAnswer(invocation -> {
            IntentAuthorizationService.AuthorizationSession session = invocation.getArgument(0);
            storedSessions.put(session.getSessionId(), stored(session, "PENDING", null, null, null));
            return null;
        }).when(sessionPersistence).create(any(IntentAuthorizationService.AuthorizationSession.class));
        when(sessionPersistence.find(anyString())).thenAnswer(invocation ->
            Optional.ofNullable(storedSessions.get(invocation.getArgument(0)))
        );
        when(sessionPersistence.claim(anyString(), anyLong())).thenAnswer(invocation -> {
            String sessionId = invocation.getArgument(0);
            IntentAuthorizationSessionPersistenceService.StoredSession current = storedSessions.get(sessionId);
            if (current == null || current.isTerminal() || "PROCESSING".equals(current.status())) {
                return Optional.empty();
            }
            IntentAuthorizationSessionPersistenceService.StoredSession claimed = stored(
                current.session(), "PROCESSING", null, null, null
            );
            storedSessions.put(sessionId, claimed);
            return Optional.of(new IntentAuthorizationSessionPersistenceService.ClaimedSession(
                claimed, "claim-1", "worker-1", 1L
            ));
        });
        when(sessionPersistence.complete(any(), anyString(), any(), any(), anyInt(), any(Instant.class), anyLong()))
            .thenAnswer(invocation -> {
                IntentAuthorizationSessionPersistenceService.ClaimedSession claim = invocation.getArgument(0);
                String status = invocation.getArgument(1);
                IntentAckResponse ack = invocation.getArgument(2);
                String error = invocation.getArgument(3);
                int httpStatus = invocation.getArgument(4);
                Instant completedAt = invocation.getArgument(5);
                storedSessions.put(
                    claim.stored().session().getSessionId(),
                    stored(claim.stored().session(), status, error, ack, completedAt, httpStatus)
                );
                return true;
            });
        when(sessionPersistence.expireIfNeeded(anyString(), anyLong())).thenAnswer(invocation -> {
            String sessionId = invocation.getArgument(0);
            IntentAuthorizationSessionPersistenceService.StoredSession current = storedSessions.get(sessionId);
            if (current == null || current.isTerminal()) {
                return false;
            }
            storedSessions.put(
                sessionId,
                stored(current.session(), "FAILED_TERMINAL", "Session expired", null, Instant.now(), 410)
            );
            return true;
        });
        lenient().when(institutionalSessionCredentialService.validate(anyString())).thenReturn(
            new InstitutionalSessionCredentialService.Credential(
                "user@example.edu",
                "uned.es",
                "principal",
                "0x" + "a".repeat(64),
                Instant.now(),
                Instant.now().plusSeconds(3600),
                Instant.now().plusSeconds(3600),
                "test-session"
            )
        );
    }

    @AfterEach
    void tearDown() {
        service.shutdown();
    }

    @Test
    void createSession_buildsPendingSessionWithActiveDistinctCredentials() {
        when(webauthnCredentialService.getCredentials("user@example.edu")).thenReturn(List.of(
            credential("cred-old", true, 100L),
            credential("cred-new", true, 300L),
            credential("cred-new", true, 250L),
            credential("cred-revoked", false, 500L)
        ));

        IntentAuthorizationService.AuthorizationSession session = service.createSession(validAuthorizationRequest());

        assertThat(session.getSessionId()).hasSize(32);
        assertThat(session.getAllowedCredentials())
            .extracting((IntentAuthorizationService.AllowedCredential credential) -> credential.getId())
            .containsExactly("cred-new", "cred-old");
        assertThat(session.getReturnUrl()).isEqualTo("https://app.example/callback");
        assertThat(new String(Base64.getUrlDecoder().decode(session.getChallenge()), StandardCharsets.UTF_8))
            .isEqualTo("user@example.edu|request-123|0xpayload|7|100|200|3");

        IntentAuthorizationStatusResponse status = service.getStatus(session.getSessionId());
        assertThat(status.getStatus()).isEqualTo("PENDING");
        assertThat(status.getRequestId()).isEqualTo("request-123");
    }

    @Test
    void createSession_usesDeclaredPrincipalModeWhenSamlAlsoContainsTargetedId() throws Exception {
        when(webauthnCredentialService.getCredentials("user@example.edu"))
            .thenReturn(List.of(credential("cred-1", true, 100L)));
        IntentAuthorizationRequest request = validAuthorizationRequest();
        request.setStableUserIdMode("principal");

        IntentAuthorizationService.AuthorizationSession session = service.createSession(request);

        verify(webauthnCredentialService).getCredentials("user@example.edu");
        assertThat(new String(Base64.getUrlDecoder().decode(session.getChallenge()), StandardCharsets.UTF_8))
            .startsWith("user@example.edu|request-123|");
    }

    @Test
    void createSession_preservesStoredWebAuthnTransportsForBrowserHints() {
        when(webauthnCredentialService.getCredentials("user@example.edu"))
            .thenReturn(List.of(credential("cred-1", true, 100L, "hybrid,internal,unknown")));

        IntentAuthorizationService.AuthorizationSession session = service.createSession(validAuthorizationRequest());

        assertThat(session.getAllowedCredentials())
            .singleElement()
            .satisfies(allowed -> {
                assertThat(allowed.getId()).isEqualTo("cred-1");
                assertThat(allowed.getTransports()).containsExactly("hybrid", "internal");
            });
    }

    @Test
    void createSession_rejectsInvalidSaml() throws Exception {
        when(institutionalSessionCredentialService.validate(anyString()))
            .thenThrow(new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_institutional_session"));

        assertThatThrownBy(() -> service.createSession(validAuthorizationRequest()))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("invalid_institutional_session");
    }

    @Test
    void createSession_rejectsMissingRequest() {
        assertThatThrownBy(() -> service.createSession(null))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("missing_intent_authorization_request");
    }

    @Test
    void createSession_logsSanitizedSamlFailureDiagnostics() throws Exception {
        Logger logger = (Logger) LoggerFactory.getLogger(IntentAuthorizationService.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            when(institutionalSessionCredentialService.validate(anyString()))
                .thenThrow(new SecurityException("signature failed\nraw-assertion-must-not-be-logged"));

            assertThatThrownBy(() -> service.createSession(validAuthorizationRequest()))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("invalid_saml");

            assertThat(appender.list)
                .extracting((ILoggingEvent event) -> event.getFormattedMessage())
                .anySatisfy(message -> {
                    assertThat(message)
                        .contains("exceptionType=SecurityException")
                        .contains("rootCauseType=SecurityException")
                        .doesNotContain("signature failed")
                        .doesNotContain("raw-assertion-must-not-be-logged")
                        .doesNotContain("\n");
                });
        } finally {
            logger.detachAppender(appender);
            appender.stop();
        }
    }

    @Test
    void createSession_rejectsWhenNoActiveCredentialsAvailable() {
        when(webauthnCredentialService.getCredentials("user@example.edu"))
            .thenReturn(List.of(credential("cred-1", false, 100L)));

        assertThatThrownBy(() -> service.createSession(validAuthorizationRequest()))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("webauthn_credential_not_registered");
    }

    @Test
    void readOnlySessionReadsRejectExpiredSessionWithoutPersistingExpiration() {
        when(webauthnCredentialService.getCredentials("user@example.edu"))
            .thenReturn(List.of(credential("cred-1", true, 100L)));
        ReflectionTestUtils.setField(service, "sessionTtlSeconds", -1L);

        IntentAuthorizationService.AuthorizationSession session = service.createSession(validAuthorizationRequest());

        assertThatThrownBy(() -> service.getSession(session.getSessionId()))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("Session expired");

        IntentAuthorizationStatusResponse status = service.getStatus(session.getSessionId());
        assertThat(status.getStatus()).isEqualTo("FAILED_TERMINAL");
        assertThat(status.getError()).isEqualTo("Session expired");
        verify(sessionPersistence, never()).expireIfNeeded(anyString(), anyLong());
    }

    @Test
    void completeAuthorization_rejectsUnknownSession() {
        assertThatThrownBy(() -> service.completeAuthorization(validCompleteRequest("missing", "cred-1")))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("Session not found");
    }

    @Test
    void completeAuthorization_rejectsCredentialNotAllowed() {
        when(webauthnCredentialService.getCredentials("user@example.edu"))
            .thenReturn(List.of(credential("cred-1", true, 100L)));
        IntentAuthorizationService.AuthorizationSession session = service.createSession(validAuthorizationRequest());

        assertThatThrownBy(() -> service.completeAuthorization(validCompleteRequest(session.getSessionId(), "other-cred")))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("webauthn_credential_not_allowed");

        assertThat(service.getStatus(session.getSessionId()).getStatus()).isEqualTo("FAILED_RETRYABLE");
    }

    @Test
    void completeAuthorization_storesSuccessAndCopiesAssertionFields() {
        when(webauthnCredentialService.getCredentials("user@example.edu"))
            .thenReturn(List.of(credential("cred-1", true, 100L)));
        IntentAckResponse ack = new IntentAckResponse();
        ack.setRequestId("request-123");
        ack.setStatus("accepted");
        when(intentService.processIntent(any(IntentSubmission.class))).thenReturn(ack);

        IntentAuthorizationService.AuthorizationSession session = service.createSession(validAuthorizationRequest());
        IntentAuthorizationCompleteRequest request = validCompleteRequest(session.getSessionId(), "cred-1");

        IntentAckResponse response = service.completeAuthorization(request);

        assertThat(response.getStatus()).isEqualTo("accepted");
        ArgumentCaptor<IntentSubmission> submissionCaptor = ArgumentCaptor.forClass(IntentSubmission.class);
        verify(intentService).processIntent(submissionCaptor.capture());
        IntentSubmission submission = submissionCaptor.getValue();
        assertThat(submission.getWebauthnCredentialId()).isEqualTo("cred-1");
        assertThat(submission.getWebauthnClientDataJSON()).isEqualTo("client-data");
        assertThat(submission.getWebauthnAuthenticatorData()).isEqualTo("auth-data");
        assertThat(submission.getWebauthnSignature()).isEqualTo("signature");

        IntentAuthorizationStatusResponse status = service.getStatus(session.getSessionId());
        assertThat(status.getStatus()).isEqualTo("SUCCESS");
        assertThat(status.getCompletedAt()).isNotNull();
        verify(intentExecutionService).processQueuedIntent("request-123");
    }

    @Test
    void completeAuthorization_replaysDurableSuccessWithoutReprocessingIntent() {
        when(webauthnCredentialService.getCredentials("user@example.edu"))
            .thenReturn(List.of(credential("cred-1", true, 100L)));
        IntentAckResponse ack = new IntentAckResponse();
        ack.setRequestId("request-123");
        ack.setStatus("accepted");
        when(intentService.processIntent(any(IntentSubmission.class))).thenReturn(ack);

        IntentAuthorizationService.AuthorizationSession session = service.createSession(validAuthorizationRequest());
        IntentAuthorizationCompleteRequest request = validCompleteRequest(session.getSessionId(), "cred-1");

        assertThat(service.completeAuthorization(request)).isSameAs(ack);
        assertThat(service.completeAuthorization(request).getStatus()).isEqualTo("accepted");
        verify(intentService).processIntent(any(IntentSubmission.class));
    }

    @Test
    void completeAuthorization_storesFailedStatusWhenIntentProcessingThrows() {
        when(webauthnCredentialService.getCredentials("user@example.edu"))
            .thenReturn(List.of(credential("cred-1", true, 100L)));
        when(intentService.processIntent(any(IntentSubmission.class)))
            .thenThrow(new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_intent"));

        IntentAuthorizationService.AuthorizationSession session = service.createSession(validAuthorizationRequest());

        assertThatThrownBy(() -> service.completeAuthorization(validCompleteRequest(session.getSessionId(), "cred-1")))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("invalid_intent");

        IntentAuthorizationStatusResponse status = service.getStatus(session.getSessionId());
        assertThat(status.getStatus()).isEqualTo("FAILED_TERMINAL");
        assertThat(status.getError()).isEqualTo("invalid_intent");
    }

    @Test
    void buildCeremonyUrl_andRpId_useConfiguredOrFallbackValues() {
        assertThat(service.buildCeremonyUrl("session-123"))
            .isEqualTo("https://backend.example/intents/authorize/ceremony/session-123");
        assertThat(service.getRelyingPartyId()).isEqualTo("example.com");

        ReflectionTestUtils.setField(service, "baseUrl", "");
        ReflectionTestUtils.setField(service, "rpId", " ");
        when(backendUrlResolver.resolveBaseDomain()).thenReturn("https://gateway.example:8443/");

        assertThat(service.buildCeremonyUrl("session-abc"))
            .isEqualTo("https://gateway.example:8443/intents/authorize/ceremony/session-abc");
        assertThat(service.getRelyingPartyId()).isEqualTo("gateway.example");
    }

    @Test
    void cleanupExpiredSessions_delegatesToDurableStore() {
        ReflectionTestUtils.setField(service, "sessionTtlSeconds", 0L);

        assertThatCode(() -> ReflectionTestUtils.invokeMethod(service, "cleanupExpiredSessions")).doesNotThrowAnyException();
        verify(sessionPersistence).cleanupExpiredSessions(0L);
    }

    private IntentAuthorizationSessionPersistenceService.StoredSession stored(
        IntentAuthorizationService.AuthorizationSession session,
        String status,
        String error,
        IntentAckResponse ack,
        Instant completedAt
    ) {
        return stored(session, status, error, ack, completedAt, 400);
    }

    private IntentAuthorizationSessionPersistenceService.StoredSession stored(
        IntentAuthorizationService.AuthorizationSession session,
        String status,
        String error,
        IntentAckResponse ack,
        Instant completedAt,
        int httpStatus
    ) {
        return new IntentAuthorizationSessionPersistenceService.StoredSession(
            session,
            status,
            error,
            httpStatus,
            ack,
            completedAt,
            1L,
            null,
            null,
            0L,
            null
        );
    }

    private IntentAuthorizationRequest validAuthorizationRequest() {
        IntentAuthorizationRequest request = new IntentAuthorizationRequest();
        request.setMeta(validMeta());
        request.setActionPayload(validActionPayload());
        request.setSignature("0xsig");
        request.setInstitutionalSessionToken("institutional-token");
        request.setReturnUrl("https://app.example/callback");
        return request;
    }

    private IntentMeta validMeta() {
        IntentMeta meta = new IntentMeta();
        meta.setRequestId("request-123");
        meta.setSigner("0xsigner");
        meta.setExecutor("0xexecutor");
        meta.setAction(3);
        meta.setPayloadHash("0xpayload");
        meta.setNonce(7L);
        meta.setRequestedAt(100L);
        meta.setExpiresAt(200L);
        return meta;
    }

    private ActionIntentPayload validActionPayload() {
        ActionIntentPayload payload = new ActionIntentPayload();
        payload.setExecutor("0xexecutor");
        payload.setPucHash(decentralabs.blockchain.util.PucHashUtil.hashPuc("user@example.edu"));
        payload.setLabId(BigInteger.ONE);
        return payload;
    }

    private IntentAuthorizationCompleteRequest validCompleteRequest(String sessionId, String credentialId) {
        IntentAuthorizationCompleteRequest request = new IntentAuthorizationCompleteRequest();
        request.setSessionId(sessionId);
        request.setCredentialId(credentialId);
        request.setClientDataJSON("client-data");
        request.setAuthenticatorData("auth-data");
        request.setSignature("signature");
        return request;
    }

    private WebauthnCredential credential(String credentialId, boolean active, Long createdAt) {
        return credential(credentialId, active, createdAt, null);
    }

    private WebauthnCredential credential(String credentialId, boolean active, Long createdAt, String transports) {
        return new WebauthnCredential(credentialId, "public-key", null, 0L, active, createdAt, createdAt, null, null, null, transports);
    }
}
