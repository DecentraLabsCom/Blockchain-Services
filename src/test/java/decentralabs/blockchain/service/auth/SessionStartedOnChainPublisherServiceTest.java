package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

@ExtendWith(MockitoExtension.class)
class SessionStartedOnChainPublisherServiceTest {

    @Mock
    private ObjectProvider<JdbcTemplate> jdbcTemplateProvider;

    @Mock
    private JdbcTemplate jdbcTemplate;

    @Mock
    private SessionStartedOnChainClient onChainClient;

    @Test
    void publishesPendingAttestationAndStoresTxHash() throws Exception {
        SessionStartedOnChainPublisherService service = buildService(jdbcTemplate);
        mockPendingAttestation();
        when(jdbcTemplate.update(anyString(), any(Object[].class))).thenReturn(1);
        when(onChainClient.hasSessionStarted("0xabc")).thenReturn(false);
        when(onChainClient.markSessionStarted(any(SessionStartedOnChainSubmission.class))).thenReturn("0xtxhash");

        int published = service.publishPending(10);

        assertThat(published).isEqualTo(1);
        ArgumentCaptor<SessionStartedOnChainSubmission> submission =
            ArgumentCaptor.forClass(SessionStartedOnChainSubmission.class);
        verify(onChainClient).markSessionStarted(submission.capture());
        assertThat(submission.getValue().reservationKey()).isEqualTo("0xabc");
        assertThat(submission.getValue().labId()).isEqualTo("42");
        verify(jdbcTemplate).update(contains("onchain_tx_hash = ?"), eq("0xtxhash"), eq(7L));
    }

    @Test
    void marksAsPublishedWhenContractAlreadyRecordedSessionStarted() throws Exception {
        SessionStartedOnChainPublisherService service = buildService(jdbcTemplate);
        mockPendingAttestation();
        when(jdbcTemplate.update(anyString(), any(Object[].class))).thenReturn(1);
        when(onChainClient.hasSessionStarted("0xabc")).thenReturn(true);

        int published = service.publishPending(10);

        assertThat(published).isEqualTo(1);
        verify(onChainClient, never()).markSessionStarted(any(SessionStartedOnChainSubmission.class));
        verify(jdbcTemplate).update(contains("SET onchain_published_at = CURRENT_TIMESTAMP"), eq(7L));
    }

    @Test
    void unlocksAndStoresErrorWhenPublicationFails() throws Exception {
        SessionStartedOnChainPublisherService service = buildService(jdbcTemplate);
        mockPendingAttestation();
        when(jdbcTemplate.update(anyString(), any(Object[].class))).thenReturn(1);
        when(onChainClient.hasSessionStarted("0xabc")).thenReturn(false);
        when(onChainClient.markSessionStarted(any(SessionStartedOnChainSubmission.class)))
            .thenThrow(new IllegalStateException("contract rejected"));

        int published = service.publishPending(10);

        assertThat(published).isZero();
        verify(jdbcTemplate).update(
            contains("onchain_publish_last_error = ?"),
            eq("contract rejected"),
            eq(7L)
        );
    }

    @Test
    void skipsWhenDatasourceIsUnavailable() {
        SessionStartedOnChainPublisherService service = buildService(null);

        int published = service.publishPending();

        assertThat(published).isZero();
        verify(onChainClient, never()).hasSessionStarted(anyString());
    }

    private SessionStartedOnChainPublisherService buildService(JdbcTemplate template) {
        when(jdbcTemplateProvider.getIfAvailable()).thenReturn(template);
        return new SessionStartedOnChainPublisherService(jdbcTemplateProvider, onChainClient);
    }

    private void mockPendingAttestation() throws Exception {
        when(jdbcTemplate.query(anyString(), anySubmissionRowMapper(), any(Object[].class)))
            .thenAnswer(invocation -> {
                RowMapper<?> mapper = invocation.getArgument(1);
                ResultSet rs = org.mockito.Mockito.mock(ResultSet.class);
                when(rs.getLong("id")).thenReturn(7L);
                when(rs.getString("reservation_key")).thenReturn("0xabc");
                when(rs.getString("lab_id")).thenReturn("42");
                when(rs.getString("puc_hash")).thenReturn("0x" + "1".repeat(64));
                when(rs.getString("signer_address")).thenReturn("0x1111111111111111111111111111111111111111");
                when(rs.getString("gateway_id")).thenReturn("gateway-a");
                when(rs.getString("session_id")).thenReturn("guac-session-1");
                when(rs.getString("access_type")).thenReturn("guacamole");
                when(rs.getTimestamp("started_at")).thenReturn(Timestamp.from(Instant.ofEpochSecond(1_700_010_000L)));
                when(rs.getString("nonce")).thenReturn("0x" + "2".repeat(64));
                when(rs.getString("credential_hash")).thenReturn("a".repeat(64));
                when(rs.getString("client_proof_hash")).thenReturn("0x" + "3".repeat(64));
                when(rs.getString("signature")).thenReturn("0x" + "4".repeat(130));
                return List.of(mapper.mapRow(rs, 0));
            });
    }

    private RowMapper<?> anySubmissionRowMapper() {
        return ArgumentMatchers.<RowMapper<?>>any();
    }
}
