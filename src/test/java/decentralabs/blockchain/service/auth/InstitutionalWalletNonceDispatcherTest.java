package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.dto.auth.CheckInResponse;
import java.math.BigInteger;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class InstitutionalWalletNonceDispatcherTest {
    @Mock private InstitutionalCheckInOutboxService outboxService;
    @Mock private InstitutionalCheckInSubmissionService submissionService;
    @Mock private CheckInOnChainService checkInOnChainService;
    @InjectMocks private InstitutionalWalletNonceDispatcher dispatcher;

    @Test
    void persistsReservedNonceAndTransactionHashBeforeReleasingWalletDispatch() throws Exception {
        InstitutionalCheckInOutboxRecord record = new InstitutionalCheckInOutboxRecord(
            7L, "0xabc", "42", "0xpayer", "0xpuchash", "session-7", "SUBMITTING", 0,
            Instant.now(), null, "0xsigner", null, null
        );
        CheckInResponse response = new CheckInResponse();
        response.setTxHash("0x" + "a".repeat(64));
        when(submissionService.signerAddress()).thenReturn("0xsigner");
        when(checkInOnChainService.pendingNonce("0xsigner")).thenReturn(BigInteger.valueOf(45));
        when(outboxService.reserveNextNonce("0xsigner", BigInteger.valueOf(45))).thenReturn(BigInteger.valueOf(47));
        when(submissionService.submit("0xabc", "0xpuchash", BigInteger.valueOf(47), 0)).thenReturn(response);

        CheckInResponse result = dispatcher.dispatch(record);

        assertThat(result).isSameAs(response);
        verify(outboxService).markNonceReserved(7L, "0xsigner", BigInteger.valueOf(47));
        verify(outboxService).markSubmitted(7L, response.getTxHash());
    }

    @Test
    void keepsTheReservedNonceWhenBroadcastOutcomeIsUncertain() {
        InstitutionalCheckInOutboxRecord record = new InstitutionalCheckInOutboxRecord(
            8L, "0xdef", "42", "0xpayer", "0xpuchash", "session-8", "RETRY", 1,
            Instant.now(), null, "0xsigner", BigInteger.valueOf(48), Instant.now()
        );
        when(submissionService.signerAddress()).thenReturn("0xsigner");
        when(submissionService.submit("0xdef", "0xpuchash", BigInteger.valueOf(48), 1))
            .thenThrow(new IllegalStateException("rpc response lost"));

        assertThatThrownBy(() -> dispatcher.dispatch(record))
            .isInstanceOf(InstitutionalWalletDispatchException.class);

        verify(submissionService).submit("0xdef", "0xpuchash", BigInteger.valueOf(48), 1);
        verify(outboxService, org.mockito.Mockito.never()).reserveNextNonce(eq("0xsigner"), org.mockito.ArgumentMatchers.any());
    }
}
