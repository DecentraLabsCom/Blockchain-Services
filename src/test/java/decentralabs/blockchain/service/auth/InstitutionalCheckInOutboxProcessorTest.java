package decentralabs.blockchain.service.auth;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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
    @Mock private InstitutionalCheckInOutboxService outboxService;
    @Mock private BlockchainBookingService bookingService;
    @Mock private InstitutionalWalletNonceDispatcher nonceDispatcher;
    @Mock private CheckInOnChainService checkInOnChainService;

    private InstitutionalCheckInOutboxProcessor processor;

    @BeforeEach
    void setUp() {
        processor = new InstitutionalCheckInOutboxProcessor(
            outboxService, bookingService, nonceDispatcher, checkInOnChainService
        );
        ReflectionTestUtils.setField(processor, "maxAttempts", 3);
        ReflectionTestUtils.setField(processor, "retryBaseDelayMs", 1000L);
        ReflectionTestUtils.setField(processor, "retryMaxDelayMs", 10_000L);
    }

    @Test
    void submitsUsingTheDurableClaimReturnedByTheOutbox() throws Exception {
        InstitutionalCheckInOutboxRecord due = record("PENDING", 0);
        InstitutionalCheckInOutboxClaim claim = claim(due);
        when(outboxService.claim(due.id())).thenReturn(claim);
        authorizedBooking();

        processor.process(due);

        verify(nonceDispatcher).dispatch(claim);
    }

    @Test
    void marksAuthorizedRowsThroughTheSameClaim() throws Exception {
        InstitutionalCheckInOutboxRecord due = record("PENDING", 0);
        InstitutionalCheckInOutboxClaim claim = claim(due);
        when(outboxService.claim(due.id())).thenReturn(claim);
        when(bookingService.getCheckInBookingInfo(any(), any(), any(), eq(null)))
            .thenReturn(Map.of("reservationStatus", BigInteger.valueOf(2)));

        processor.process(due);

        verify(nonceDispatcher, never()).dispatch(any(InstitutionalCheckInOutboxClaim.class));
        verify(outboxService).markMinedSuccess(claim, claim.record(), null);
    }

    @Test
    void retriesWhenSubmissionFailsBeforeMaxAttempts() throws Exception {
        InstitutionalCheckInOutboxRecord due = record("PENDING", 1);
        InstitutionalCheckInOutboxClaim claim = claim(due);
        when(outboxService.claim(due.id())).thenReturn(claim);
        authorizedBooking();
        doThrow(new IllegalStateException("nonce pending"))
            .when(nonceDispatcher).dispatch(claim);

        processor.process(due);

        verify(outboxService).markRetry(eq(claim), eq(2), any(Instant.class), eq("nonce pending"));
    }

    @Test
    void marksFailedWhenMaxAttemptsIsReached() throws Exception {
        InstitutionalCheckInOutboxRecord due = record("PENDING", 2);
        InstitutionalCheckInOutboxClaim claim = claim(due);
        when(outboxService.claim(due.id())).thenReturn(claim);
        authorizedBooking();
        doThrow(new IllegalStateException("rpc down"))
            .when(nonceDispatcher).dispatch(claim);

        processor.process(due);

        verify(outboxService).markFailed(claim, 3, "rpc down");
    }

    @Test
    void quarantinesAnUncertainBroadcastThroughTheClaim() throws Exception {
        InstitutionalCheckInOutboxRecord due = record("PENDING", 2);
        InstitutionalCheckInOutboxClaim claim = claim(due);
        when(outboxService.claim(due.id())).thenReturn(claim);
        authorizedBooking();
        doThrow(new InstitutionalWalletDispatchException(
            "broadcast outcome uncertain", new IllegalStateException("rpc response lost")
        )).when(nonceDispatcher).dispatch(claim);

        processor.process(due);

        verify(outboxService).markBroadcastUncertain(claim, 3, "broadcast outcome uncertain");
        verify(outboxService, never()).markFailed(any(), anyInt(), any());
    }

    @Test
    void preservesReplacementIntentInTheReturnedClaim() throws Exception {
        InstitutionalCheckInOutboxRecord due = record("REPLACEMENT_PENDING", 2);
        InstitutionalCheckInOutboxClaim claim = claim(due);
        when(outboxService.claim(due.id())).thenReturn(claim);
        authorizedBooking();

        processor.process(due);

        verify(nonceDispatcher).dispatch(claim, true);
        verify(nonceDispatcher, never()).dispatch(claim);
    }

    private void authorizedBooking() {
        when(bookingService.getCheckInBookingInfo(any(), any(), any(), eq(null)))
            .thenReturn(Map.of("reservationStatus", BigInteger.ONE));
    }

    private InstitutionalCheckInOutboxClaim claim(InstitutionalCheckInOutboxRecord due) {
        InstitutionalCheckInOutboxRecord claimed = new InstitutionalCheckInOutboxRecord(
            due.id(), due.reservationKey(), due.labId(), due.institutionalWallet(), due.pucHash(),
            due.accessSessionId(), "SUBMITTING", due.attempts(), due.nextAttemptAt(), due.txHash(),
            due.walletAddress(), due.chainId(), due.nonce(), due.submittedAt(), due.version() + 1,
            due.signedRawTransaction(), due.originalGasPrice(), due.currentGasPrice(), due.generation()
        );
        return new InstitutionalCheckInOutboxClaim(claimed, "claim-id", "worker", claimed.version());
    }

    private InstitutionalCheckInOutboxRecord record(String status, int attempts) {
        return new InstitutionalCheckInOutboxRecord(
            1L, "0xabc", "42", "0x1111111111111111111111111111111111111111", "0xpuchash",
            "session-1", status, attempts, Instant.now(), null,
            "0x1111111111111111111111111111111111111111", null, null
        );
    }
}
