package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.never;
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
    void rejectsMissingOutboxRecordAsPreBroadcastRetryable() {
        InstitutionalWalletNonceDispatcher dispatcher = new InstitutionalWalletNonceDispatcher(
            outboxService, submissionService, transactionDispatcher
        );

        assertThatThrownBy(() -> dispatcher.dispatch(null))
            .isInstanceOf(InstitutionalWalletDispatchException.class)
            .extracting("outcome")
            .isEqualTo(InstitutionalWalletDispatchException.Outcome.PRE_BROADCAST_PERMANENT);

        verify(submissionService, never()).signerAddress();
    }

    @Test
    void persistsReservedNonceAndTransactionHashBeforeReleasingWalletDispatch() throws Exception {
        InstitutionalCheckInOutboxRecord record = new InstitutionalCheckInOutboxRecord(
            7L, "0xabc", "42", "0xpayer", "0xpuchash", "session-7", "SUBMITTING", 0,
            Instant.now(), null, "0xsigner", null, null
        );
        CheckInResponse response = new CheckInResponse();
        response.setTxHash("0x" + "a".repeat(64));
        when(submissionService.signerAddress()).thenReturn("0xsigner");
        when(outboxService.markSubmittedAfterPreparation(any(), any())).thenReturn(true);
        InstitutionalCheckInSubmissionService.PreparedCheckIn prepared =
            new InstitutionalCheckInSubmissionService.PreparedCheckIn(
                response,
                new InstitutionalWalletTransactionDispatcher.PreparedTransaction(
                    "0x01", response.getTxHash()
                )
            );
        when(submissionService.prepare(
            eq("0xabc"), eq("0xpuchash"), eq(BigInteger.valueOf(47)),
            isNull(BigInteger.class), isNull(BigInteger.class), eq(0)
        )).thenReturn(prepared);
        BigInteger chainId = BigInteger.valueOf(11155111);
        when(transactionDispatcher.dispatchPrepared(eq("0xsigner"), eq(null), eq(null), any(), any(), any(), any()))
            .thenAnswer(invocation -> {
                java.util.function.BiConsumer<BigInteger, BigInteger> persistNonce = invocation.getArgument(3);
                java.util.function.Function<BigInteger, InstitutionalWalletTransactionDispatcher.PreparedTransaction> prepare = invocation.getArgument(4);
                java.util.function.Consumer<InstitutionalWalletTransactionDispatcher.PreparedTransaction> persistPrepared = invocation.getArgument(5);
                java.util.function.Consumer<String> persistHash = invocation.getArgument(6);
                persistNonce.accept(chainId, BigInteger.valueOf(47));
                var tx = prepare.apply(BigInteger.valueOf(47));
                persistPrepared.accept(tx);
                persistHash.accept(tx.transactionHash());
                return tx.transactionHash();
            });

        InstitutionalWalletNonceDispatcher dispatcher = new InstitutionalWalletNonceDispatcher(
            outboxService, submissionService, transactionDispatcher
        );

        CheckInResponse result = dispatcher.dispatch(record);

        assertThat(result).isSameAs(response);
        verify(outboxService).markNonceReserved(7L, "0xsigner", chainId, BigInteger.valueOf(47));
        verify(outboxService).markSubmittedAfterPreparation(record, response.getTxHash());
    }

    @Test
    void keepsTheReservedNonceWhenBroadcastOutcomeIsUncertain() throws Exception {
        InstitutionalCheckInOutboxRecord record = new InstitutionalCheckInOutboxRecord(
            8L, "0xdef", "42", "0xpayer", "0xpuchash", "session-8", "RETRY", 1,
            Instant.now(), null, "0xsigner", BigInteger.ONE, BigInteger.valueOf(48), Instant.now(), 0L
        );
        when(submissionService.signerAddress()).thenReturn("0xsigner");
        when(submissionService.prepare(
            eq("0xdef"), eq("0xpuchash"), eq(BigInteger.valueOf(48)),
            isNull(BigInteger.class), isNull(BigInteger.class), eq(1)
        ))
            .thenThrow(new IllegalStateException("rpc response lost"));
        when(transactionDispatcher.dispatchPrepared(
            eq("0xsigner"), eq(BigInteger.ONE), eq(BigInteger.valueOf(48)), any(), any(), any(), any()
        ))
            .thenAnswer(invocation -> {
                java.util.function.Function<BigInteger, InstitutionalWalletTransactionDispatcher.PreparedTransaction> prepare = invocation.getArgument(4);
                return prepare.apply(BigInteger.valueOf(48)).transactionHash();
            });
        InstitutionalWalletNonceDispatcher dispatcher = new InstitutionalWalletNonceDispatcher(
            outboxService, submissionService, transactionDispatcher
        );

        assertThatThrownBy(() -> dispatcher.dispatch(record))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("rpc response lost");

        verify(submissionService).prepare(
            eq("0xdef"), eq("0xpuchash"), eq(BigInteger.valueOf(48)),
            isNull(BigInteger.class), isNull(BigInteger.class), eq(1)
        );
        verify(transactionDispatcher).dispatchPrepared(
            eq("0xsigner"), eq(BigInteger.ONE), eq(BigInteger.valueOf(48)), any(), any(), any(), any()
        );
    }

    @Test
    void staleSubmittingRowRebroadcastsPersistedTransactionBeforePreparingReplacement() throws Exception {
        String previousHash = "0x" + "c".repeat(64);
        InstitutionalCheckInOutboxRecord record = new InstitutionalCheckInOutboxRecord(
            9L, "0xghi", "42", "0xpayer", "0xpuchash", "session-9", "SUBMITTING", 1,
            Instant.now(), previousHash, "0xsigner", BigInteger.ONE, BigInteger.valueOf(49), Instant.now(), 2L,
            "0xold-raw"
        );
        when(submissionService.signerAddress()).thenReturn("0xsigner");
        when(outboxService.markSubmitted(any(InstitutionalCheckInOutboxRecord.class), any())).thenReturn(true);
        when(transactionDispatcher.rebroadcastPrepared(any()))
            .thenReturn(previousHash);

        InstitutionalWalletNonceDispatcher dispatcher = new InstitutionalWalletNonceDispatcher(
            outboxService, submissionService, transactionDispatcher
        );

        CheckInResponse result = dispatcher.dispatch(record);

        assertThat(result.getTxHash()).isEqualTo(previousHash);
        verify(transactionDispatcher).rebroadcastPrepared(any());
        verify(outboxService).markSubmitted(record, previousHash);
        verify(submissionService, never()).prepare(any(), any(), any(), any(), any(), anyInt());
        verify(transactionDispatcher, never()).dispatchPrepared(any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void replacementClaimPreparesNewGasWithTheExistingNonce() throws Exception {
        String previousHash = "0x" + "b".repeat(64);
        String replacementHash = "0x" + "d".repeat(64);
        InstitutionalCheckInOutboxRecord record = new InstitutionalCheckInOutboxRecord(
            11L, "0xreplacement", "42", "0xpayer", "0xpuchash", "session-11", "SUBMITTING", 2,
            Instant.now(), previousHash, "0xsigner", BigInteger.ONE, BigInteger.valueOf(51),
            Instant.now(), 4L, "0xold-raw", BigInteger.valueOf(100), BigInteger.valueOf(120), 1L
        );
        CheckInResponse response = new CheckInResponse();
        response.setTxHash(replacementHash);
        when(submissionService.signerAddress()).thenReturn("0xsigner");
        when(submissionService.prepare(
            "0xreplacement", "0xpuchash", BigInteger.valueOf(51),
            BigInteger.valueOf(100), BigInteger.valueOf(120), 2
        )).thenReturn(new InstitutionalCheckInSubmissionService.PreparedCheckIn(
            response,
            new InstitutionalWalletTransactionDispatcher.PreparedTransaction(
                "0xnew-raw", replacementHash, BigInteger.valueOf(120)
            )
        ));
        when(outboxService.markSubmittedAfterPreparation(any(), eq(replacementHash))).thenReturn(true);
        when(transactionDispatcher.dispatchPrepared(
            eq("0xsigner"), eq(BigInteger.ONE), eq(BigInteger.valueOf(51)), any(), any(), any(), any()
        )).thenAnswer(invocation -> {
            java.util.function.Function<BigInteger, InstitutionalWalletTransactionDispatcher.PreparedTransaction> prepare =
                invocation.getArgument(4);
            java.util.function.Consumer<InstitutionalWalletTransactionDispatcher.PreparedTransaction> persistPrepared =
                invocation.getArgument(5);
            java.util.function.Consumer<String> persistHash = invocation.getArgument(6);
            var prepared = prepare.apply(BigInteger.valueOf(51));
            persistPrepared.accept(prepared);
            persistHash.accept(prepared.transactionHash());
            return prepared.transactionHash();
        });

        InstitutionalWalletNonceDispatcher dispatcher = new InstitutionalWalletNonceDispatcher(
            outboxService, submissionService, transactionDispatcher
        );

        CheckInResponse result = dispatcher.dispatch(record, true);

        assertThat(result).isSameAs(response);
        verify(submissionService).prepare(
            "0xreplacement", "0xpuchash", BigInteger.valueOf(51),
            BigInteger.valueOf(100), BigInteger.valueOf(120), 2
        );
        verify(transactionDispatcher).dispatchPrepared(
            eq("0xsigner"), eq(BigInteger.ONE), eq(BigInteger.valueOf(51)), any(), any(), any(), any()
        );
        verify(transactionDispatcher, never()).rebroadcastPrepared(any());
        verify(outboxService).markPrepared(
            eq(record), any(InstitutionalWalletTransactionDispatcher.PreparedTransaction.class)
        );
    }

    @Test
    void staleSubmittingRowWithPartialMaterialDoesNotOverwriteExistingEvidence() throws Exception {
        InstitutionalCheckInOutboxRecord record = new InstitutionalCheckInOutboxRecord(
            10L, "0xjkl", "42", "0xpayer", "0xpuchash", "session-10", "SUBMITTING", 1,
            Instant.now(), "0x" + "f".repeat(64), "0xsigner", BigInteger.ONE, BigInteger.valueOf(50),
            Instant.now(), 3L, null
        );
        when(submissionService.signerAddress()).thenReturn("0xsigner");

        assertThatThrownBy(() -> new InstitutionalWalletNonceDispatcher(
            outboxService, submissionService, transactionDispatcher
        ).dispatch(record))
            .isInstanceOf(InstitutionalWalletDispatchException.class)
            .extracting("outcome")
            .isEqualTo(InstitutionalWalletDispatchException.Outcome.PRE_BROADCAST_PERMANENT);

        verify(submissionService, never()).prepare(any(), any(), any(), any(), any(), anyInt());
        verify(transactionDispatcher, never()).dispatchPrepared(any(), any(), any(), any(), any(), any(), any());
    }
}
