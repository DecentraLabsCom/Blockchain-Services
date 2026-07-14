package decentralabs.blockchain.service.auth;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import decentralabs.blockchain.service.wallet.BlockchainBookingService;

@ExtendWith(MockitoExtension.class)
class InstitutionalCheckInReceiptMonitorTest {
    @Mock private InstitutionalCheckInOutboxService outboxService;
    @Mock private CheckInOnChainService checkInOnChainService;
    @Mock private BlockchainBookingService bookingService;
    @InjectMocks private InstitutionalCheckInReceiptMonitor monitor;

    @Test
    void requeuesStuckTransactionUsingItsExistingNonce() {
        ReflectionTestUtils.setField(monitor, "stuckTransactionMs", 1L);
        ReflectionTestUtils.setField(monitor, "maxAttempts", 8);
        InstitutionalCheckInOutboxRecord record = new InstitutionalCheckInOutboxRecord(
            3L, "0xabc", "42", "0xpayer", "0xpuchash", "session", "SUBMITTED", 2,
            Instant.now(), "0x" + "a".repeat(64), "0xsigner", BigInteger.valueOf(12), Instant.now().minusSeconds(1)
        );
        when(checkInOnChainService.transactionState(record.txHash()))
            .thenReturn(CheckInOnChainService.TransactionState.PENDING);

        monitor.monitor(record);

        verify(outboxService).markReplacementPending(eq(record), eq(3), any(Instant.class), eq("Check-in transaction is still pending; retrying with the same nonce and higher gas"));
    }

    @Test
    void failsAStuckTransactionWhenTheGlobalReplacementLimitIsReached() {
        ReflectionTestUtils.setField(monitor, "stuckTransactionMs", 1L);
        ReflectionTestUtils.setField(monitor, "maxAttempts", 8);
        InstitutionalCheckInOutboxRecord record = new InstitutionalCheckInOutboxRecord(
            4L, "0xdef", "42", "0xpayer", "0xpuchash", "session", "SUBMITTED", 7,
            Instant.now(), "0x" + "b".repeat(64), "0xsigner", BigInteger.valueOf(13), Instant.now().minusSeconds(1)
        );
        when(checkInOnChainService.transactionState(record.txHash()))
            .thenReturn(CheckInOnChainService.TransactionState.PENDING);

        monitor.monitor(record);

        verify(outboxService).markStuckUnknown(
            record,
            8,
            "Check-in transaction remained pending after the maximum number of broadcasts"
        );
        verify(outboxService, never()).markSubmittedRetry(eq(record), eq(8), any(Instant.class), any(String.class));
    }

    @Test
    void reconcilesUnknownTransactionFromAuthoritativeContractState() {
        InstitutionalCheckInOutboxRecord record = unknownRecord(5L, 14L);
        when(bookingService.getCheckInBookingInfo("0xpayer", "0xabc", "42", null))
            .thenReturn(Map.of("reservationStatus", BigInteger.valueOf(2)));

        monitor.reconcileUnknown(record);

        verify(outboxService).markUnknownMinedSuccess(record);
        verify(checkInOnChainService, never()).transactionStateStrict(any(String.class));
    }

    @Test
    void retriesUnknownTransactionOnlyWhenNodeProvesItsNonceWasNotConsumed() {
        InstitutionalCheckInOutboxRecord record = unknownRecord(6L, 15L);
        when(bookingService.getCheckInBookingInfo("0xpayer", "0xabc", "42", null))
            .thenReturn(Map.of("reservationStatus", BigInteger.ONE));
        when(checkInOnChainService.transactionStateStrict(record.txHash()))
            .thenReturn(CheckInOnChainService.TransactionState.PENDING);
        when(checkInOnChainService.transactionVisible(record.txHash())).thenReturn(false);
        when(checkInOnChainService.pendingNonce("0xsigner")).thenReturn(BigInteger.valueOf(15));

        monitor.reconcileUnknown(record);

        verify(outboxService).markUnknownRetry(eq(record), any(Instant.class), any(String.class));
    }

    @Test
    void returnsVisibleStuckUnknownToSubmittedWithoutRebroadcasting() {
        InstitutionalCheckInOutboxRecord record = unknownRecord(16L, 17L);
        when(bookingService.getCheckInBookingInfo("0xpayer", "0xabc", "42", null))
            .thenReturn(Map.of("reservationStatus", BigInteger.ONE));
        when(checkInOnChainService.transactionStateStrict(record.txHash()))
            .thenReturn(CheckInOnChainService.TransactionState.PENDING);
        when(checkInOnChainService.transactionVisible(record.txHash())).thenReturn(true);

        monitor.reconcileUnknown(record);

        verify(outboxService).markUnknownVisibleSubmitted(record);
        verify(checkInOnChainService, never()).pendingNonce(any(String.class));
    }

    @Test
    void promotesTheHistoricalCheckInHashThatActuallyMined() {
        String currentHash = "0x" + "2".repeat(64);
        String historicalHash = "0x" + "1".repeat(64);
        InstitutionalCheckInOutboxRecord record = new InstitutionalCheckInOutboxRecord(
            17L, "0xabc", "42", "0xpayer", "0xpuchash", "session", "SUBMITTED", 2,
            Instant.now(), currentHash, "0xsigner", BigInteger.ONE, BigInteger.valueOf(18),
            Instant.now().minusSeconds(1), 4L
        );
        when(outboxService.findReplacedHashes(record.id())).thenReturn(java.util.List.of(historicalHash));
        when(checkInOnChainService.transactionState(currentHash))
            .thenReturn(CheckInOnChainService.TransactionState.PENDING);
        when(checkInOnChainService.transactionState(historicalHash))
            .thenReturn(CheckInOnChainService.TransactionState.SUCCEEDED);

        monitor.monitor(record);

        verify(outboxService).markSubmittedMinedSuccess(record, historicalHash);
    }

    @Test
    void reconcilesUncertainBroadcastWithoutHashFromContractAndNonceState() {
        InstitutionalCheckInOutboxRecord record = new InstitutionalCheckInOutboxRecord(
            7L, "0xabc", "42", "0xpayer", "0xpuchash", "session", "STUCK_UNKNOWN", 3,
            Instant.now(), null, "0xsigner", BigInteger.valueOf(16), Instant.now().minusSeconds(60)
        );
        when(bookingService.getCheckInBookingInfo("0xpayer", "0xabc", "42", null))
            .thenReturn(Map.of("reservationStatus", BigInteger.ONE));
        when(checkInOnChainService.pendingNonce("0xsigner")).thenReturn(BigInteger.valueOf(16));

        monitor.reconcileUnknown(record);

        verify(outboxService).markUnknownRetry(eq(record), any(Instant.class), any(String.class));
        verify(checkInOnChainService, never()).transactionStateStrict(any(String.class));
    }

    private InstitutionalCheckInOutboxRecord unknownRecord(long id, long nonce) {
        return new InstitutionalCheckInOutboxRecord(
            id, "0xabc", "42", "0xpayer", "0xpuchash", "session", "STUCK_UNKNOWN", 8,
            Instant.now(), "0x" + "c".repeat(64), "0xsigner", BigInteger.valueOf(nonce),
            Instant.now().minusSeconds(60)
        );
    }
}
