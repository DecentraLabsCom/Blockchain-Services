package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class SessionStartedOnChainPublisherServiceTest {
    @Mock private ObjectProvider<JdbcTemplate> jdbcTemplateProvider;
    @Mock private JdbcTemplate jdbcTemplate;
    @Mock private SessionStartedOnChainClient onChainClient;
    @Mock private InstitutionalWalletTransactionDispatcher transactionDispatcher;

    @Test
    void dispatchesWithDurablyReservedNonceAndDoesNotWaitForReceipt() throws Exception {
        SessionStartedOnChainPublisherService service = buildService(jdbcTemplate);
        mockSubmittedQuery(List.of());
        mockPendingQuery("QUEUED", 0, null, null, null, null);
        when(jdbcTemplate.update(anyString(), any(Object[].class))).thenReturn(1);
        when(onChainClient.hasSessionStarted("0xabc")).thenReturn(false);
        when(onChainClient.signerAddress()).thenReturn("0xwallet");
        when(onChainClient.markSessionStarted(any(), eq(BigInteger.valueOf(45)), eq(0)))
            .thenReturn("0x" + "a".repeat(64));
        mockDispatch(BigInteger.valueOf(45), "0x" + "a".repeat(64));

        assertThat(service.publishPending(10)).isEqualTo(1);

        verify(onChainClient).markSessionStarted(any(), eq(BigInteger.valueOf(45)), eq(0));
        verify(jdbcTemplate).update(
            contains("onchain_wallet_address = ?"), eq("0xwallet"), eq(BigInteger.valueOf(45)), eq(7L)
        );
        verify(jdbcTemplate).update(contains("onchain_status = 'SUBMITTED'"), eq("0x" + "a".repeat(64)), eq(7L));
        verify(onChainClient, never()).transactionState(anyString());
    }

    @Test
    void receiptMonitorMarksSubmittedTransactionAsMined() throws Exception {
        SessionStartedOnChainPublisherService service = buildService(jdbcTemplate);
        String hash = "0x" + "b".repeat(64);
        mockSubmittedQuery(List.of(
            mappedRecord("SUBMITTED", 1, "0xwallet", BigInteger.valueOf(45), hash, Instant.now())
        ));
        mockPendingEmpty();
        when(onChainClient.transactionState(hash)).thenReturn(SessionStartedOnChainClient.TransactionState.SUCCEEDED);

        assertThat(service.publishPending(10)).isEqualTo(1);

        verify(jdbcTemplate).update(contains("onchain_status = 'MINED_SUCCESS'"), eq(hash), eq(7L), eq(hash));
        verify(transactionDispatcher, never()).dispatch(anyString(), any(), any(), any(), any());
    }

    @Test
    void reusesReservedNonceForReplacementBroadcast() throws Exception {
        SessionStartedOnChainPublisherService service = buildService(jdbcTemplate);
        mockSubmittedQuery(List.of());
        mockPendingQuery("RETRY", 2, "0xwallet", BigInteger.valueOf(47), "0x" + "c".repeat(64), Instant.now());
        when(jdbcTemplate.update(anyString(), any(Object[].class))).thenReturn(1);
        when(onChainClient.hasSessionStarted("0xabc")).thenReturn(false);
        when(onChainClient.signerAddress()).thenReturn("0xwallet");
        when(onChainClient.markSessionStarted(any(), eq(BigInteger.valueOf(47)), eq(2)))
            .thenReturn("0x" + "d".repeat(64));
        mockDispatchWithExistingNonce(BigInteger.valueOf(47), "0x" + "d".repeat(64));

        assertThat(service.publishPending(10)).isEqualTo(1);

        verify(transactionDispatcher).dispatch(eq("0xwallet"), eq(BigInteger.valueOf(47)), any(), any(), any());
        verify(onChainClient).markSessionStarted(any(), eq(BigInteger.valueOf(47)), eq(2));
    }

    @Test
    void marksAlreadyRecordedSessionWithoutBroadcast() throws Exception {
        SessionStartedOnChainPublisherService service = buildService(jdbcTemplate);
        mockSubmittedQuery(List.of());
        mockPendingQuery("QUEUED", 0, null, null, null, null);
        when(jdbcTemplate.update(anyString(), any(Object[].class))).thenReturn(1);
        when(onChainClient.hasSessionStarted("0xabc")).thenReturn(true);

        assertThat(service.publishPending(10)).isEqualTo(1);

        verify(transactionDispatcher, never()).dispatch(anyString(), any(), any(), any(), any());
        verify(jdbcTemplate).update(contains("onchain_status = 'MINED_SUCCESS'"), eq(7L));
    }

    @Test
    void queryExcludesAttestationsAtMaxPublishAttempts() {
        SessionStartedOnChainPublisherService service = buildService(jdbcTemplate);
        ReflectionTestUtils.setField(service, "maxAttempts", 3);
        mockSubmittedQuery(List.of());
        when(jdbcTemplate.query(contains("onchain_status IN"), anyTransactionRowMapper(), any(Object[].class)))
            .thenReturn(List.of());

        assertThat(service.publishPending(10)).isZero();

        verify(jdbcTemplate).query(
            contains("onchain_publish_attempts < ?"), anyTransactionRowMapper(), eq(3), any(Timestamp.class), eq(10)
        );
    }

    @Test
    void skipsWhenDatasourceIsUnavailable() {
        SessionStartedOnChainPublisherService service = buildService(null);
        assertThat(service.publishPending()).isZero();
        verify(onChainClient, never()).hasSessionStarted(anyString());
    }

    private SessionStartedOnChainPublisherService buildService(JdbcTemplate template) {
        when(jdbcTemplateProvider.getIfAvailable()).thenReturn(template);
        return new SessionStartedOnChainPublisherService(jdbcTemplateProvider, onChainClient, transactionDispatcher);
    }

    private void mockSubmittedQuery(List<SessionStartedTransactionRecord> rows) {
        when(jdbcTemplate.query(
            contains("WHERE onchain_status = 'SUBMITTED'"), anyTransactionRowMapper(), eq(10)
        )).thenAnswer(invocation -> rows);
    }

    private void mockPendingEmpty() {
        when(jdbcTemplate.query(
            contains("onchain_status IN"), anyTransactionRowMapper(), any(Object[].class)
        )).thenReturn(List.of());
    }

    private void mockPendingQuery(
        String status, int attempts, String wallet, BigInteger txNonce, String hash, Instant submittedAt
    ) throws Exception {
        when(jdbcTemplate.query(
            contains("onchain_status IN"), anyTransactionRowMapper(), any(Object[].class)
        )).thenAnswer(invocation -> {
            RowMapper<?> mapper = invocation.getArgument(1);
            return List.of(mapRow(mapper, status, attempts, wallet, txNonce, hash, submittedAt));
        });
    }

    private SessionStartedTransactionRecord mappedRecord(
        String status, int attempts, String wallet, BigInteger txNonce, String hash, Instant submittedAt
    ) throws Exception {
        RowMapper<SessionStartedTransactionRecord> mapper = extractMapper();
        return mapRow(mapper, status, attempts, wallet, txNonce, hash, submittedAt);
    }

    @SuppressWarnings("unchecked")
    private RowMapper<SessionStartedTransactionRecord> extractMapper() throws Exception {
        SessionStartedOnChainPublisherService service = buildService(jdbcTemplate);
        var method = SessionStartedOnChainPublisherService.class.getDeclaredMethod("transactionRowMapper");
        method.setAccessible(true);
        return (RowMapper<SessionStartedTransactionRecord>) method.invoke(service);
    }

    private SessionStartedTransactionRecord mapRow(
        RowMapper<?> mapper, String status, int attempts, String wallet,
        BigInteger txNonce, String hash, Instant submittedAt
    ) throws Exception {
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
        when(rs.getString("onchain_status")).thenReturn(status);
        when(rs.getInt("onchain_publish_attempts")).thenReturn(attempts);
        when(rs.getString("onchain_wallet_address")).thenReturn(wallet);
        when(rs.getObject("onchain_nonce")).thenReturn(txNonce == null ? null : new BigDecimal(txNonce));
        if (txNonce != null) {
            when(rs.getBigDecimal("onchain_nonce")).thenReturn(new BigDecimal(txNonce));
        }
        when(rs.getString("onchain_tx_hash")).thenReturn(hash);
        when(rs.getTimestamp("onchain_submitted_at"))
            .thenReturn(submittedAt == null ? null : Timestamp.from(submittedAt));
        @SuppressWarnings("unchecked")
        SessionStartedTransactionRecord record =
            ((RowMapper<SessionStartedTransactionRecord>) mapper).mapRow(rs, 0);
        return record;
    }

    private void mockDispatch(BigInteger nonce, String hash) throws Exception {
        when(transactionDispatcher.dispatch(eq("0xwallet"), isNull(), any(), any(), any()))
            .thenAnswer(invocation -> executeDispatch(invocation, nonce, hash, true));
    }

    private void mockDispatchWithExistingNonce(BigInteger nonce, String hash) throws Exception {
        when(transactionDispatcher.dispatch(eq("0xwallet"), eq(nonce), any(), any(), any()))
            .thenAnswer(invocation -> executeDispatch(invocation, nonce, hash, false));
    }

    private String executeDispatch(
        org.mockito.invocation.InvocationOnMock invocation, BigInteger nonce, String hash, boolean persistNonce
    ) {
        Consumer<BigInteger> nonceConsumer = invocation.getArgument(2);
        Function<BigInteger, String> broadcaster = invocation.getArgument(3);
        Consumer<String> hashConsumer = invocation.getArgument(4);
        if (persistNonce) nonceConsumer.accept(nonce);
        assertThat(broadcaster.apply(nonce)).isEqualTo(hash);
        hashConsumer.accept(hash);
        return hash;
    }

    private RowMapper<?> anyTransactionRowMapper() {
        return ArgumentMatchers.<RowMapper<?>>any();
    }
}
