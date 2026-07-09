package decentralabs.blockchain.service.auth;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.dto.auth.CheckInResponse;
import decentralabs.blockchain.service.wallet.BlockchainBookingService;
import java.math.BigInteger;
import java.time.Instant;
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
    private InstitutionalCheckInSubmissionService submissionService;

    private InstitutionalCheckInOutboxProcessor processor;

    @BeforeEach
    void setUp() {
        processor = new InstitutionalCheckInOutboxProcessor(outboxService, bookingService, submissionService);
        ReflectionTestUtils.setField(processor, "maxAttempts", 3);
        ReflectionTestUtils.setField(processor, "retryBaseDelayMs", 1000L);
        ReflectionTestUtils.setField(processor, "retryMaxDelayMs", 10_000L);
    }

    @Test
    void submitsConfirmedReservationAndMarksSuccess() {
        var record = record(0);
        when(outboxService.claim(1L)).thenReturn(true);
        when(bookingService.getCheckInBookingInfo(
            "0x1111111111111111111111111111111111111111",
            "0xabc",
            "42",
            null
        )).thenReturn(Map.of("reservationStatus", BigInteger.ONE));
        CheckInResponse response = new CheckInResponse();
        response.setTxHash("0xtx");
        when(submissionService.submit("0xabc", "0xpuchash")).thenReturn(response);

        processor.process(record);

        verify(submissionService).submit("0xabc", "0xpuchash");
        verify(outboxService).markSucceeded(1L, "0xtx");
    }

    @Test
    void marksSuccessWithoutSubmittingWhenReservationAccessAlreadyAuthorized() {
        var record = record(0);
        when(outboxService.claim(1L)).thenReturn(true);
        when(bookingService.getCheckInBookingInfo(any(), any(), any(), eq(null)))
            .thenReturn(Map.of("reservationStatus", BigInteger.valueOf(2)));

        processor.process(record);

        verify(submissionService, never()).submit(any(), any());
        verify(outboxService).markSucceeded(1L, null);
    }

    @Test
    void schedulesRetryWhenSubmissionFailsBeforeMaxAttempts() {
        var record = record(1);
        when(outboxService.claim(1L)).thenReturn(true);
        when(bookingService.getCheckInBookingInfo(any(), any(), any(), eq(null)))
            .thenReturn(Map.of("reservationStatus", BigInteger.ONE));
        when(submissionService.submit("0xabc", "0xpuchash"))
            .thenThrow(new IllegalStateException("nonce pending"));

        processor.process(record);

        verify(outboxService).markRetry(eq(1L), eq(2), any(Instant.class), eq("nonce pending"));
    }

    @Test
    void marksFailedWhenMaxAttemptsIsReached() {
        var record = record(2);
        when(outboxService.claim(1L)).thenReturn(true);
        when(bookingService.getCheckInBookingInfo(any(), any(), any(), eq(null)))
            .thenReturn(Map.of("reservationStatus", BigInteger.ONE));
        when(submissionService.submit("0xabc", "0xpuchash"))
            .thenThrow(new IllegalStateException("rpc down"));

        processor.process(record);

        verify(outboxService).markFailed(1L, 3, "rpc down");
    }

    private InstitutionalCheckInOutboxRecord record(int attempts) {
        return new InstitutionalCheckInOutboxRecord(
            1L,
            "0xabc",
            "42",
            "0x1111111111111111111111111111111111111111",
            "0xpuchash",
            "session-1",
            "PENDING",
            attempts,
            Instant.now()
        );
    }
}
