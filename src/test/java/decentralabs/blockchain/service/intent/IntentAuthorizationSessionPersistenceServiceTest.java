package decentralabs.blockchain.service.intent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.dto.intent.ActionIntentPayload;
import decentralabs.blockchain.dto.intent.IntentAckResponse;
import decentralabs.blockchain.dto.intent.IntentMeta;
import decentralabs.blockchain.dto.intent.IntentSubmission;
import java.math.BigInteger;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;

@ExtendWith(MockitoExtension.class)
class IntentAuthorizationSessionPersistenceServiceTest {

    @Mock
    private ObjectProvider<JdbcTemplate> jdbcTemplateProvider;

    @Mock
    private JdbcTemplate jdbcTemplate;

    private IntentPayloadCipher payloadCipher;
    private IntentAuthorizationSessionPersistenceService service;

    @BeforeEach
    void setUp() {
        when(jdbcTemplateProvider.getIfAvailable()).thenReturn(jdbcTemplate);
        payloadCipher = new IntentPayloadCipher(Base64.getEncoder().encodeToString(new byte[32]));
        service = new IntentAuthorizationSessionPersistenceService(
            jdbcTemplateProvider,
            new ObjectMapper(),
            payloadCipher
        );
    }

    @Test
    void createEncryptsTheCompleteCeremonyPayloadBeforePersisting() {
        IntentAuthorizationService.AuthorizationSession session = session();

        service.create(session);

        ArgumentCaptor<Object[]> arguments = ArgumentCaptor.forClass(Object[].class);
        verify(jdbcTemplate).update(anyString(), arguments.capture());
        String ciphertext = (String) arguments.getValue()[3];

        assertThat(ciphertext).startsWith("v1.");
        assertThat(payloadCipher.decrypt(ciphertext))
            .contains("submission")
            .contains("allowedCredentials")
            .doesNotContain("samlAssertion");
        assertThat(ciphertext).doesNotContain("assertion");
    }

    @Test
    void claimUsesAtomicProcessingTransitionAndLeasePredicate() {
        when(jdbcTemplate.update(anyString(), any(Object[].class))).thenReturn(0);

        assertThat(service.claim("session-123", 60)).isEmpty();

        ArgumentCaptor<String> sql = ArgumentCaptor.forClass(String.class);
        verify(jdbcTemplate).update(sql.capture(), any(Object[].class));
        assertThat(sql.getValue())
            .contains("status = 'PROCESSING'")
            .contains("status IN ('PENDING', 'FAILED_RETRYABLE')")
            .contains("claim_expires_at <= CURRENT_TIMESTAMP(6)")
            .contains("expires_at > CURRENT_TIMESTAMP(6)");
    }

    @Test
    void completeUsesTheClaimFenceAndPersistsTheAck() {
        IntentAuthorizationService.AuthorizationSession session = session();
        IntentAuthorizationSessionPersistenceService.StoredSession stored =
            new IntentAuthorizationSessionPersistenceService.StoredSession(
                session, "PROCESSING", null, null, null, null, 2L,
                "claim-1", "worker-1", 3L, Instant.now().plusSeconds(60)
            );
        IntentAuthorizationSessionPersistenceService.ClaimedSession claim =
            new IntentAuthorizationSessionPersistenceService.ClaimedSession(stored, "claim-1", "worker-1", 3L);
        IntentAckResponse ack = new IntentAckResponse();
        ack.setRequestId("request-123");
        ack.setStatus("accepted");
        when(jdbcTemplate.update(anyString(), any(Object[].class))).thenReturn(1);

        assertThat(service.complete(
            claim, "SUCCESS", ack, null, 200, Instant.now(), 300
        )).isTrue();

        ArgumentCaptor<String> sql = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Object[]> arguments = ArgumentCaptor.forClass(Object[].class);
        verify(jdbcTemplate).update(sql.capture(), arguments.capture());
        assertThat(sql.getValue())
            .contains("status = 'PROCESSING'")
            .contains("claim_id = ?")
            .contains("claimed_by = ?")
            .contains("claim_version = ?")
            .contains("claim_expires_at > CURRENT_TIMESTAMP(6)");
        assertThat(arguments.getValue()).contains("SUCCESS");
        assertThat((String) arguments.getValue()[3]).contains("request-123");
    }

    private IntentAuthorizationService.AuthorizationSession session() {
        IntentMeta meta = new IntentMeta();
        meta.setRequestId("request-123");
        meta.setSigner("0xsigner");
        meta.setExecutor("0xexecutor");
        meta.setAction(3);
        meta.setPayloadHash("0xpayload");
        meta.setNonce(7L);
        meta.setRequestedAt(100L);
        meta.setExpiresAt(200L);

        ActionIntentPayload actionPayload = new ActionIntentPayload();
        actionPayload.setExecutor("0xexecutor");
        actionPayload.setPucHash("0x" + "1".repeat(64));
        actionPayload.setLabId(BigInteger.ONE);

        IntentSubmission submission = new IntentSubmission();
        submission.setMeta(meta);
        submission.setActionPayload(actionPayload);
        submission.setSignature("0xsig");

        return new IntentAuthorizationService.AuthorizationSession(
            "session-123",
            submission,
            List.of(new IntentAuthorizationService.AllowedCredential("cred-1", List.of("internal"))),
            "challenge",
            "https://app.example/callback",
            Instant.now().plusSeconds(300)
        );
    }
}
