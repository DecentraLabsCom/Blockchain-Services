package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.dto.auth.CheckInResponse;
import java.math.BigInteger;
import java.time.Instant;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;
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
    void rejectsMissingClaim() {
        InstitutionalWalletNonceDispatcher dispatcher = dispatcher();

        assertThatThrownBy(() -> dispatcher.dispatch((InstitutionalCheckInOutboxClaim) null))
            .isInstanceOf(InstitutionalWalletDispatchException.class)
            .extracting("outcome")
            .isEqualTo(InstitutionalWalletDispatchException.Outcome.PRE_BROADCAST_PERMANENT);
        verify(submissionService, never()).signerAddress();
    }

    @Test
    void persistsReservedNonceAndTransactionHashThroughTheSameClaim() throws Exception {
        InstitutionalCheckInOutboxRecord record = submittingRecord(7L, null, null, 0L);
        InstitutionalCheckInOutboxClaim claim = claim(record);
        CheckInResponse response = new CheckInResponse();
        response.setTxHash("0x" + "a".repeat(64));
        when(submissionService.signerAddress()).thenReturn("0xsigner");
        when(outboxService.markNonceReserved(claim, "0xsigner", BigInteger.ONE, BigInteger.valueOf(47)))
            .thenReturn(true);
        when(outboxService.markSubmittedAfterPreparation(eq(claim), any(), eq(response.getTxHash())))
            .thenReturn(true);
        when(submissionService.prepare(
            eq("0xabc"), eq("0xpuchash"), eq(BigInteger.valueOf(47)),
            isNull(BigInteger.class), isNull(BigInteger.class), eq(0)
        )).thenReturn(new InstitutionalCheckInSubmissionService.PreparedCheckIn(
            response,
            new InstitutionalWalletTransactionDispatcher.PreparedTransaction("0x01", response.getTxHash())
        ));
        when(transactionDispatcher.dispatchPrepared(
            eq("0xsigner"), eq(null), eq(null), any(), any(), any(), any()
        )).thenAnswer(invocation -> {
            BiConsumer<BigInteger, BigInteger> persistNonce = invocation.getArgument(3);
            Function<BigInteger, InstitutionalWalletTransactionDispatcher.PreparedTransaction> prepare =
                invocation.getArgument(4);
            Consumer<InstitutionalWalletTransactionDispatcher.PreparedTransaction> persistPrepared =
                invocation.getArgument(5);
            Consumer<String> persistHash = invocation.getArgument(6);
            persistNonce.accept(BigInteger.ONE, BigInteger.valueOf(47));
            var prepared = prepare.apply(BigInteger.valueOf(47));
            persistPrepared.accept(prepared);
            persistHash.accept(prepared.transactionHash());
            return prepared.transactionHash();
        });

        CheckInResponse result = dispatcher().dispatch(claim);

        assertThat(result).isSameAs(response);
        verify(outboxService).markNonceReserved(claim, "0xsigner", BigInteger.ONE, BigInteger.valueOf(47));
        verify(outboxService).markPrepared(eq(claim), any(), any());
        verify(outboxService).markSubmittedAfterPreparation(eq(claim), any(), eq(response.getTxHash()));
    }

    @Test
    void staleSubmittingRowRebroadcastsPersistedTransactionBeforePreparingReplacement() throws Exception {
        String previousHash = "0x" + "c".repeat(64);
        InstitutionalCheckInOutboxRecord record = submittingRecord(9L, previousHash, "0xold-raw", 2L);
        InstitutionalCheckInOutboxClaim claim = claim(record);
        when(submissionService.signerAddress()).thenReturn("0xsigner");
        when(transactionDispatcher.rebroadcastPrepared(any())).thenReturn(previousHash);
        when(outboxService.markSubmitted(claim, record, previousHash)).thenReturn(true);

        CheckInResponse result = dispatcher().dispatch(claim);

        assertThat(result.getTxHash()).isEqualTo(previousHash);
        verify(transactionDispatcher).rebroadcastPrepared(any());
        verify(outboxService).markSubmitted(claim, record, previousHash);
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
        InstitutionalCheckInOutboxClaim claim = claim(record);
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
        when(outboxService.markSubmittedAfterPreparation(eq(claim), any(), eq(replacementHash)))
            .thenReturn(true);
        when(transactionDispatcher.dispatchPrepared(
            eq("0xsigner"), eq(BigInteger.ONE), eq(BigInteger.valueOf(51)), any(), any(), any(), any()
        )).thenAnswer(invocation -> {
            Function<BigInteger, InstitutionalWalletTransactionDispatcher.PreparedTransaction> prepare =
                invocation.getArgument(4);
            Consumer<InstitutionalWalletTransactionDispatcher.PreparedTransaction> persistPrepared =
                invocation.getArgument(5);
            Consumer<String> persistHash = invocation.getArgument(6);
            var prepared = prepare.apply(BigInteger.valueOf(51));
            persistPrepared.accept(prepared);
            persistHash.accept(prepared.transactionHash());
            return prepared.transactionHash();
        });

        CheckInResponse result = dispatcher().dispatch(claim, true);

        assertThat(result).isSameAs(response);
        verify(transactionDispatcher, never()).rebroadcastPrepared(any());
        verify(outboxService).markPrepared(eq(claim), any(), any());
    }

    private InstitutionalWalletNonceDispatcher dispatcher() {
        return new InstitutionalWalletNonceDispatcher(outboxService, submissionService, transactionDispatcher);
    }

    private InstitutionalCheckInOutboxClaim claim(InstitutionalCheckInOutboxRecord record) {
        return new InstitutionalCheckInOutboxClaim(record, "claim-id", "worker", record.version());
    }

    private InstitutionalCheckInOutboxRecord submittingRecord(
        long id, String txHash, String raw, long version
    ) {
        return new InstitutionalCheckInOutboxRecord(
            id, "0xabc", "42", "0xpayer", "0xpuchash", "session", "SUBMITTING", 0,
            Instant.now(), txHash, "0xsigner", null, null, Instant.now(), version, raw
        );
    }
}
