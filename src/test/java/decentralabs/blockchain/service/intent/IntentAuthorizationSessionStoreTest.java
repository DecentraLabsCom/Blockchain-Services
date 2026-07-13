package decentralabs.blockchain.service.intent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.dto.intent.IntentMeta;
import decentralabs.blockchain.dto.intent.IntentSubmission;
import decentralabs.blockchain.service.auth.AccessCodeTokenCipher;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;

@ExtendWith(MockitoExtension.class)
class IntentAuthorizationSessionStoreTest {
    @Mock private ObjectProvider<JdbcTemplate> jdbcTemplateProvider;
    @Mock private JdbcTemplate jdbcTemplate;
    @Mock private AccessCodeTokenCipher cipher;

    private IntentAuthorizationSessionStore store;

    @BeforeEach
    void setUp() {
        when(jdbcTemplateProvider.getIfAvailable()).thenReturn(jdbcTemplate);
        store = new IntentAuthorizationSessionStore(jdbcTemplateProvider, cipher);
    }

    @Test
    void savePendingEncryptsSubmissionBeforePersistence() {
        when(cipher.encrypt(anyString())).thenReturn("v1.encrypted");
        IntentAuthorizationService.AuthorizationSession session = session();

        store.savePending(session);

        verify(cipher).encrypt(anyString());
        verify(jdbcTemplate).update(
            anyString(),
            org.mockito.ArgumentMatchers.eq("session-1"),
            org.mockito.ArgumentMatchers.eq("request-1"),
            org.mockito.ArgumentMatchers.eq("v1.encrypted"),
            anyString(),
            org.mockito.ArgumentMatchers.eq("challenge"),
            org.mockito.ArgumentMatchers.eq("https://market.example"),
            any(java.sql.Timestamp.class)
        );
    }

    @Test
    void claimPendingDoesNotLoadSessionWhenAnotherReplicaWonClaim() {
        when(jdbcTemplate.update(anyString(), org.mockito.ArgumentMatchers.eq("session-1"))).thenReturn(0);

        assertThat(store.claimPending("session-1")).isEmpty();

        verify(jdbcTemplate).update(anyString(), org.mockito.ArgumentMatchers.eq("session-1"));
        verifyNoMoreInteractions(jdbcTemplate);
    }

    private IntentAuthorizationService.AuthorizationSession session() {
        IntentMeta meta = new IntentMeta();
        meta.setRequestId("request-1");
        meta.setSigner("0x0000000000000000000000000000000000000001");
        meta.setExecutor("0x0000000000000000000000000000000000000002");
        meta.setAction(8);
        meta.setPayloadHash("0x" + "11".repeat(32));
        meta.setNonce(1L);
        meta.setRequestedAt(1L);
        meta.setExpiresAt(2L);
        IntentSubmission submission = new IntentSubmission();
        submission.setMeta(meta);
        return new IntentAuthorizationService.AuthorizationSession(
            "session-1",
            submission,
            List.of("credential-1"),
            "challenge",
            "https://market.example",
            Instant.now().plusSeconds(300)
        );
    }
}
