package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.dto.auth.CheckInResponse;
import java.math.BigInteger;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class InstitutionalWalletNonceDispatcherTest {
    @Mock private InstitutionalCheckInOutboxService outboxService;
    @Mock private InstitutionalCheckInSubmissionService submissionService;
    @Mock private InstitutionalWalletTransactionDispatcher transactionDispatcher;

    @Test
    void persistsReservedNonceAndTransactionHashBeforeReleasingWalletDispatch() throws Exception {
        InstitutionalCheckInOutboxRecord record = new InstitutionalCheckInOutboxRecord(
            7L, "0xabc", "42", "0xpayer", "0xpuchash", "session-7", "SUBMITTING", 0,
            Instant.now(), null, "0xsigner", null, null
        );
        CheckInResponse response = new CheckInResponse();
        response.setTxHash("0x" + "a".repeat(64));
        when(submissionService.signerAddress()).thenReturn("0xsigner");
        when(submissionService.submit("0xabc", "0xpuchash", BigInteger.valueOf(47), 0)).thenReturn(response);
        BigInteger chainId = BigInteger.valueOf(11155111);
        when(transactionDispatcher.dispatch(eq("0xsigner"), eq(null), eq(null), any(), any(), any()))
            .thenAnswer(invocation -> {
                java.util.function.BiConsumer<BigInteger, BigInteger> persistNonce = invocation.getArgument(3);
                java.util.function.Function<BigInteger, String> broadcast = invocation.getArgument(4);
                java.util.function.Consumer<String> persistHash = invocation.getArgument(5);
                persistNonce.accept(chainId, BigInteger.valueOf(47));
                String hash = broadcast.apply(BigInteger.valueOf(47));
                persistHash.accept(hash);
                return hash;
            });

        InstitutionalWalletNonceDispatcher dispatcher = new InstitutionalWalletNonceDispatcher(
            outboxService, submissionService, transactionDispatcher
        );

        CheckInResponse result = dispatcher.dispatch(record);

        assertThat(result).isSameAs(response);
        verify(outboxService).markNonceReserved(7L, "0xsigner", chainId, BigInteger.valueOf(47));
        verify(outboxService).markSubmitted(7L, response.getTxHash());
    }

    @Test
    void keepsTheReservedNonceWhenBroadcastOutcomeIsUncertain() throws Exception {
        InstitutionalCheckInOutboxRecord record = new InstitutionalCheckInOutboxRecord(
            8L, "0xdef", "42", "0xpayer", "0xpuchash", "session-8", "RETRY", 1,
            Instant.now(), null, "0xsigner", BigInteger.ONE, BigInteger.valueOf(48), Instant.now(), 0L
        );
        when(submissionService.signerAddress()).thenReturn("0xsigner");
        when(submissionService.submit("0xdef", "0xpuchash", BigInteger.valueOf(48), 1))
            .thenThrow(new IllegalStateException("rpc response lost"));
        when(transactionDispatcher.dispatch(
            eq("0xsigner"), eq(BigInteger.ONE), eq(BigInteger.valueOf(48)), any(), any(), any()
        ))
            .thenAnswer(invocation -> {
                java.util.function.Function<BigInteger, String> broadcast = invocation.getArgument(4);
                return broadcast.apply(BigInteger.valueOf(48));
            });
        InstitutionalWalletNonceDispatcher dispatcher = new InstitutionalWalletNonceDispatcher(
            outboxService, submissionService, transactionDispatcher
        );

        assertThatThrownBy(() -> dispatcher.dispatch(record))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("rpc response lost");

        verify(submissionService).submit("0xdef", "0xpuchash", BigInteger.valueOf(48), 1);
        verify(transactionDispatcher).dispatch(
            eq("0xsigner"), eq(BigInteger.ONE), eq(BigInteger.valueOf(48)), any(), any(), any()
        );
    }
}
