package decentralabs.blockchain.service.intent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.dto.intent.ActionIntentPayload;
import decentralabs.blockchain.dto.intent.IntentAckResponse;
import decentralabs.blockchain.dto.intent.IntentAuthorizationCompleteRequest;
import decentralabs.blockchain.dto.intent.IntentAuthorizationRequest;
import decentralabs.blockchain.dto.intent.IntentAuthorizationStatusResponse;
import decentralabs.blockchain.dto.intent.IntentMeta;
import decentralabs.blockchain.dto.intent.IntentSubmission;
import decentralabs.blockchain.service.BackendUrlResolver;
import decentralabs.blockchain.service.auth.SamlValidationService;
import decentralabs.blockchain.service.auth.WebauthnCredentialService;
import decentralabs.blockchain.service.auth.WebauthnCredentialService.WebauthnCredential;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class IntentAuthorizationServiceTest {

    @Mock
    private IntentService intentService;

    @Mock
    private WebauthnCredentialService webauthnCredentialService;

    @Mock
    private SamlValidationService samlValidationService;

    @Mock
    private BackendUrlResolver backendUrlResolver;

    @InjectMocks
    private IntentAuthorizationService service;

    @BeforeEach
    void setUp() throws Exception {
        ReflectionTestUtils.setField(service, "rpId", "example.com");
        ReflectionTestUtils.setField(service, "baseUrl", "https://backend.example/");
        ReflectionTestUtils.setField(service, "sessionTtlSeconds", 300L);
        ReflectionTestUtils.setField(service, "cleanupIntervalSeconds", 60L);
        lenient().when(samlValidationService.validateSamlAssertionWithSignature(any())).thenReturn(Map.of("userid", "user@example.edu"));
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
        assertThat(session.getCredentialIds()).containsExactly("cred-new", "cred-old");
        assertThat(session.getReturnUrl()).isEqualTo("https://app.example/callback");
        assertThat(new String(Base64.getUrlDecoder().decode(session.getChallenge()), StandardCharsets.UTF_8))
            .isEqualTo("user@example.edu|request-123|0xpayload|7|100|200|3");

        IntentAuthorizationStatusResponse status = service.getStatus(session.getSessionId());
        assertThat(status.getStatus()).isEqualTo("PENDING");
        assertThat(status.getRequestId()).isEqualTo("request-123");
    }

    @Test
    void createSession_rejectsInvalidSaml() throws Exception {
        when(samlValidationService.validateSamlAssertionWithSignature(any())).thenReturn(Map.of());

        assertThatThrownBy(() -> service.createSession(validAuthorizationRequest()))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("missing_puc_for_webauthn");
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
    void getSession_rejectsExpiredSessionAndRemovesIt() {
        when(webauthnCredentialService.getCredentials("user@example.edu"))
            .thenReturn(List.of(credential("cred-1", true, 100L)));
        ReflectionTestUtils.setField(service, "sessionTtlSeconds", -1L);

        IntentAuthorizationService.AuthorizationSession session = service.createSession(validAuthorizationRequest());

        assertThatThrownBy(() -> service.getSession(session.getSessionId()))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("Session expired");

        assertThatThrownBy(() -> service.getStatus(session.getSessionId()))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("Session not found");
    }

    @Test
    void completeAuthorization_rejectsUnknownSession() {
        assertThatThrownBy(() -> service.completeAuthorization(validCompleteRequest("missing", "cred-1")))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("Invalid or expired session");
    }

    @Test
    void completeAuthorization_rejectsCredentialNotAllowed() {
        when(webauthnCredentialService.getCredentials("user@example.edu"))
            .thenReturn(List.of(credential("cred-1", true, 100L)));
        IntentAuthorizationService.AuthorizationSession session = service.createSession(validAuthorizationRequest());

        assertThatThrownBy(() -> service.completeAuthorization(validCompleteRequest(session.getSessionId(), "other-cred")))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("webauthn_credential_not_allowed");
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
        assertThat(status.getStatus()).isEqualTo("FAILED");
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
    void cleanupExpiredSessions_removesExpiredPendingAndCompletedEntries() {
        when(webauthnCredentialService.getCredentials("user@example.edu"))
            .thenReturn(List.of(credential("cred-1", true, 100L)));
        IntentAckResponse ack = new IntentAckResponse();
        ack.setRequestId("request-123");
        ack.setStatus("accepted");
        when(intentService.processIntent(any(IntentSubmission.class))).thenReturn(ack);

        IntentAuthorizationService.AuthorizationSession pending = new IntentAuthorizationService.AuthorizationSession(
            "expired-pending",
            buildSubmission(),
            List.of("cred-1"),
            "challenge",
            null,
            Instant.now().minusSeconds(5)
        );
        @SuppressWarnings("unchecked")
        java.util.concurrent.ConcurrentHashMap<String, IntentAuthorizationService.AuthorizationSession> pendingSessions =
            (java.util.concurrent.ConcurrentHashMap<String, IntentAuthorizationService.AuthorizationSession>)
                ReflectionTestUtils.getField(service, "pendingSessions");
        pendingSessions.put("expired-pending", pending);

        IntentAuthorizationService.AuthorizationSession completed = service.createSession(validAuthorizationRequest());
        service.completeAuthorization(validCompleteRequest(completed.getSessionId(), "cred-1"));

        @SuppressWarnings("unchecked")
        java.util.concurrent.ConcurrentHashMap<String, Object> completedSessions =
            (java.util.concurrent.ConcurrentHashMap<String, Object>) ReflectionTestUtils.getField(service, "completedSessions");
        ReflectionTestUtils.setField(service, "sessionTtlSeconds", 0L);
        try {
            Thread.sleep(10L);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new AssertionError(ex);
        }

        assertThatCode(() -> ReflectionTestUtils.invokeMethod(service, "cleanupExpiredSessions")).doesNotThrowAnyException();

        assertThat(pendingSessions).doesNotContainKey("expired-pending");
        assertThat(completedSessions).doesNotContainKey(completed.getSessionId());
    }

    private IntentAuthorizationRequest validAuthorizationRequest() {
        IntentAuthorizationRequest request = new IntentAuthorizationRequest();
        request.setMeta(validMeta());
        request.setActionPayload(validActionPayload());
        request.setSignature("0xsig");
        request.setSamlAssertion("assertion");
        request.setReturnUrl("https://app.example/callback");
        return request;
    }

    private IntentSubmission buildSubmission() {
        IntentSubmission submission = new IntentSubmission();
        submission.setMeta(validMeta());
        submission.setActionPayload(validActionPayload());
        submission.setSignature("0xsig");
        submission.setSamlAssertion("assertion");
        return submission;
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
        payload.setPucHash("0x" + "1".repeat(64));
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
        return new WebauthnCredential(credentialId, "public-key", null, 0L, active, createdAt, createdAt, null, null, null, null);
    }
}
