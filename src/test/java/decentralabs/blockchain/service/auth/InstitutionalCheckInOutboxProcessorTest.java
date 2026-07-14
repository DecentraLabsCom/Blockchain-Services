package decentralabs.blockchain.service.auth;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.service.wallet.BlockchainBookingService;
import java.math.BigInteger;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class InstitutionalCheckInOutboxProcessorTest {
    @Mock
    private InstitutionalCheckInOutboxService outboxService;

    @Mock
    private BlockchainBookingService bookingService;

    @Mock
    private InstitutionalWalletNonceDispatcher nonceDispatcher;

    private InstitutionalCheckInOutboxProcessor processor;

    @BeforeEach
    void setUp() {
        processor = new InstitutionalCheckInOutboxProcessor(outboxService, bookingService, nonceDispatcher);
        ReflectionTestUtils.setField(processor, "maxAttempts", 3);
        ReflectionTestUtils.setField(processor, "retryBaseDelayMs", 1000L);
        ReflectionTestUtils.setField(processor, "retryMaxDelayMs", 10_000L);
    }

    @Test
    void submitsConfirmedReservationAndMarksSuccess() throws Exception {
        var record = record(0);
        when(outboxService.claim(1L)).thenReturn(true);
        when(bookingService.getCheckInBookingInfo(
            "0x1111111111111111111111111111111111111111",
            "0xabc",
            "42",
            null
        )).thenReturn(Map.of("reservationStatus", BigInteger.ONE));
        processor.process(record);

        verify(nonceDispatcher).dispatch(record);
    }

    @Test
    void scheduledProcessingAlwaysDrainsTheRequiredOutbox() throws Exception {
        var record = record(0);
        ReflectionTestUtils.setField(processor, "batchSize", 1);
        when(outboxService.findDue(any(Instant.class), eq(1))).thenReturn(List.of(record));
        when(outboxService.claim(record.id())).thenReturn(true);
        when(bookingService.getCheckInBookingInfo(any(), any(), any(), eq(null)))
            .thenReturn(Map.of("reservationStatus", BigInteger.ONE));

        processor.processDueCheckIns();

        verify(nonceDispatcher).dispatch(record);
    }

    @Test
    void marksSuccessWithoutSubmittingWhenReservationAccessAlreadyAuthorized() throws Exception {
        var record = record(0);
        when(outboxService.claim(1L)).thenReturn(true);
        when(bookingService.getCheckInBookingInfo(any(), any(), any(), eq(null)))
            .thenReturn(Map.of("reservationStatus", BigInteger.valueOf(2)));

        processor.process(record);

        verify(nonceDispatcher, never()).dispatch(any());
        verify(outboxService).markMinedSuccess(1L, null);
    }

    @Test
    void schedulesRetryWhenSubmissionFailsBeforeMaxAttempts() throws Exception {
        var record = record(1);
        when(outboxService.claim(1L)).thenReturn(true);
        when(bookingService.getCheckInBookingInfo(any(), any(), any(), eq(null)))
            .thenReturn(Map.of("reservationStatus", BigInteger.ONE));
        org.mockito.Mockito.doThrow(new IllegalStateException("nonce pending"))
            .when(nonceDispatcher).dispatch(record);

        processor.process(record);

        verify(outboxService).markRetry(eq(1L), eq(2), any(Instant.class), eq("nonce pending"));
    }

    @Test
    void marksFailedWhenMaxAttemptsIsReached() throws Exception {
        var record = record(2);
        when(outboxService.claim(1L)).thenReturn(true);
        when(bookingService.getCheckInBookingInfo(any(), any(), any(), eq(null)))
            .thenReturn(Map.of("reservationStatus", BigInteger.ONE));
        org.mockito.Mockito.doThrow(new IllegalStateException("rpc down"))
            .when(nonceDispatcher).dispatch(record);

        processor.process(record);

        verify(outboxService).markFailed(1L, 3, "rpc down");
    }

    @Test
    void quarantinesAnUncertainBroadcastEvenWithoutATransactionHash() throws Exception {
        var record = record(2);
        when(outboxService.claim(1L)).thenReturn(true);
        when(bookingService.getCheckInBookingInfo(any(), any(), any(), eq(null)))
            .thenReturn(Map.of("reservationStatus", BigInteger.ONE));
        org.mockito.Mockito.doThrow(new InstitutionalWalletDispatchException(
            "broadcast outcome uncertain", new IllegalStateException("rpc response lost")
        )).when(nonceDispatcher).dispatch(record);

        processor.process(record);

        verify(outboxService).markBroadcastUncertain(1L, 3, "broadcast outcome uncertain");
        verify(outboxService, never()).markFailed(eq(1L), anyInt(), anyString());
    }

    @Test
    void retriesWhenNonceAllocationFailsBeforeBroadcast() throws Exception {
        var record = record(1);
        when(outboxService.claim(1L)).thenReturn(true);
        when(bookingService.getCheckInBookingInfo(any(), any(), any(), eq(null)))
            .thenReturn(Map.of("reservationStatus", BigInteger.ONE));
        org.mockito.Mockito.doThrow(new InstitutionalWalletDispatchException(
            "nonce allocation blocked",
            InstitutionalWalletDispatchException.Outcome.PRE_BROADCAST_BLOCKED,
            new IllegalStateException("wallet busy")
        )).when(nonceDispatcher).dispatch(record);

        processor.process(record);

        verify(outboxService).markRetry(eq(1L), eq(1), any(Instant.class), eq("nonce allocation blocked"));
        verify(outboxService, never()).markBroadcastUncertain(anyLong(), anyInt(), anyString());
    }

    @Test
    void preservesReplacementIntentAcrossClaimAndReload() throws Exception {
        var due = record("REPLACEMENT_PENDING", 2);
        var claimed = new InstitutionalCheckInOutboxRecord(
            due.id(), due.reservationKey(), due.labId(), due.institutionalWallet(), due.pucHash(),
            due.accessSessionId(), "SUBMITTING", due.attempts(), due.nextAttemptAt(), due.txHash(),
            due.walletAddress(), due.chainId(), due.nonce(), due.submittedAt(), due.version() + 1,
            due.signedRawTransaction()
        );
        when(outboxService.claim(due.id())).thenReturn(true);
        when(outboxService.findById(due.id())).thenReturn(claimed);
        when(bookingService.getCheckInBookingInfo(any(), any(), any(), eq(null)))
            .thenReturn(Map.of("reservationStatus", BigInteger.ONE));

        processor.process(due);

        verify(nonceDispatcher).dispatch(claimed, true);
        verify(nonceDispatcher, never()).dispatch(claimed);
    }

    @Test
    void rePreparesMaterialRetainedByFailedReservedNonceInsteadOfRebroadcastingIt() throws Exception {
        var due = new InstitutionalCheckInOutboxRecord(
            2L, "0xfailed", "42", "0x1111111111111111111111111111111111111111", "0xpuchash",
            "session-2", "PENDING", 0, Instant.now(), "0x" + "a".repeat(64),
            "0x1111111111111111111111111111111111111111", BigInteger.ONE, BigInteger.valueOf(12),
            Instant.now(), 3L, "0xold-raw"
        );
        var claimed = new InstitutionalCheckInOutboxRecord(
            due.id(), due.reservationKey(), due.labId(), due.institutionalWallet(), due.pucHash(),
            due.accessSessionId(), "SUBMITTING", due.attempts(), due.nextAttemptAt(), due.txHash(),
            due.walletAddress(), due.chainId(), due.nonce(), due.submittedAt(), due.version() + 1,
            due.signedRawTransaction()
        );
        when(outboxService.claim(due.id())).thenReturn(true);
        when(outboxService.findById(due.id())).thenReturn(claimed);
        when(bookingService.getCheckInBookingInfo(any(), any(), any(), eq(null)))
            .thenReturn(Map.of("reservationStatus", BigInteger.ONE));

        processor.process(due);

        verify(nonceDispatcher).dispatch(claimed, true);
    }

    private InstitutionalCheckInOutboxRecord record(int attempts) {
        return record("PENDING", attempts);
    }

    private InstitutionalCheckInOutboxRecord record(String status, int attempts) {
        return new InstitutionalCheckInOutboxRecord(
            1L,
            "0xabc",
            "42",
            "0x1111111111111111111111111111111111111111",
            "0xpuchash",
            "session-1",
            status,
            attempts,
            Instant.now(),
            null,
            "0x1111111111111111111111111111111111111111",
            null,
            null
        );
    }
}
