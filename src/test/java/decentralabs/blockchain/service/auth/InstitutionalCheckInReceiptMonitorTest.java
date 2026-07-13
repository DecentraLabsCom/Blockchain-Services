package decentralabs.blockchain.service.auth;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class InstitutionalCheckInReceiptMonitorTest {
    @Mock private InstitutionalCheckInOutboxService outboxService;
    @Mock private CheckInOnChainService checkInOnChainService;
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

        verify(outboxService).markSubmittedRetry(eq(record), eq(3), any(Instant.class), eq("Check-in transaction is still pending; retrying with the same nonce and higher gas"));
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
}
