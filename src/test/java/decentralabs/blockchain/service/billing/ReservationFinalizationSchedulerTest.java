package decentralabs.blockchain.service.billing;

import static org.mockito.Mockito.never;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.service.auth.InstitutionalWalletTransactionDispatcher;
import decentralabs.blockchain.service.wallet.InstitutionalTransactionOutboxService;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import java.math.BigInteger;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class ReservationFinalizationSchedulerTest {
    private static final String WALLET = "0x1111111111111111111111111111111111111111";

    @Mock
    private WalletService walletService;

    @Mock
    private InstitutionalWalletService institutionalWalletService;

    @Mock
    private ReservationFinalizationOnChainClient onChainClient;

    @Mock
    private InstitutionalTransactionOutboxService outboxService;

    @Mock
    private InstitutionalWalletTransactionDispatcher transactionDispatcher;

    private ReservationFinalizationScheduler scheduler;

    @BeforeEach
    void setUp() {
        scheduler = new ReservationFinalizationScheduler(
            walletService,
            institutionalWalletService,
            onChainClient,
            outboxService,
            transactionDispatcher
        );
        ReflectionTestUtils.setField(scheduler, "enabled", true);
        ReflectionTestUtils.setField(scheduler, "configuredMaxBatch", 10);
        ReflectionTestUtils.setField(scheduler, "configuredMaxLabsPerRun", 25);
        ReflectionTestUtils.setField(scheduler, "intervalMs", 60000L);
        ReflectionTestUtils.setField(
            scheduler,
            "contractAddress",
            "0x2222222222222222222222222222222222222222"
        );
    }

    @Test
    void disabledSchedulerDoesNotTouchWalletOrChain() {
        ReflectionTestUtils.setField(scheduler, "enabled", false);

        scheduler.finalizeScheduled();

        verify(institutionalWalletService, never()).isConfigured();
        verify(onChainClient, never()).connectedChainId();
    }

    @Test
    void unconfiguredWalletDoesNotEnumerateLabs() {
        when(institutionalWalletService.isConfigured()).thenReturn(false);

        scheduler.finalizePending();

        verify(walletService, never()).getLabsOwnedByProvider(WALLET);
        verify(onChainClient, never()).connectedChainId();
    }

    @Test
    void candidateStatusIsRequiredBeforeCreatingAnOutboxAttempt() {
        when(institutionalWalletService.isConfigured()).thenReturn(true);
        when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(WALLET);
        when(onChainClient.connectedChainId()).thenReturn(BigInteger.ONE);
        when(walletService.getLabsOwnedByProvider(WALLET)).thenReturn(List.of(BigInteger.valueOf(7)));
        when(onChainClient.readStatus(BigInteger.valueOf(7))).thenReturn(
            new ReservationFinalizationOnChainClient.FinalizationStatus(
                BigInteger.ZERO,
                BigInteger.ONE,
                BigInteger.ZERO,
                BigInteger.valueOf(Long.MAX_VALUE),
                BigInteger.ZERO
            )
        );

        scheduler.finalizePending();

        verify(outboxService, never()).reserveOrLoad(
            org.mockito.ArgumentMatchers.anyString(),
            org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.anyString(),
            org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.anyString(),
            org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.anyString()
        );
    }

    @Test
    void failedPreflightDoesNotReserveNonceOrOutboxAttempt() {
        BigInteger labId = BigInteger.valueOf(7);
        configureCandidateLab(labId);
        doThrow(new IllegalStateException("preflight failed"))
            .when(onChainClient).validatePreflight(labId, BigInteger.TEN);

        scheduler.finalizePending();

        verify(outboxService, never()).reserveOrLoad(
            org.mockito.ArgumentMatchers.anyString(),
            org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.anyString(),
            org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.anyString(),
            org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.anyString()
        );
    }

    @Test
    void rotatesAcrossLabsWhenProviderOwnsMoreThanPerRunLimit() {
        when(institutionalWalletService.isConfigured()).thenReturn(true);
        when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(WALLET);
        when(onChainClient.connectedChainId()).thenReturn(BigInteger.ONE);
        List<BigInteger> labs = java.util.stream.LongStream.rangeClosed(1, 30)
            .mapToObj(BigInteger::valueOf)
            .toList();
        when(walletService.getLabsOwnedByProvider(WALLET)).thenReturn(labs);
        when(onChainClient.readStatus(org.mockito.ArgumentMatchers.any())).thenReturn(
            new ReservationFinalizationOnChainClient.FinalizationStatus(
                BigInteger.ZERO, BigInteger.ONE, BigInteger.ZERO, BigInteger.valueOf(Long.MAX_VALUE), BigInteger.ZERO
            )
        );

        scheduler.finalizePending();
        scheduler.finalizePending();

        verify(onChainClient).readStatus(BigInteger.valueOf(26));
        verify(onChainClient).readStatus(BigInteger.valueOf(30));
    }

    private void configureCandidateLab(BigInteger labId) {
        when(institutionalWalletService.isConfigured()).thenReturn(true);
        when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(WALLET);
        when(onChainClient.connectedChainId()).thenReturn(BigInteger.ONE);
        when(walletService.getLabsOwnedByProvider(WALLET)).thenReturn(List.of(labId));
        when(onChainClient.readStatus(labId)).thenReturn(
            new ReservationFinalizationOnChainClient.FinalizationStatus(
                BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO, BigInteger.ONE, BigInteger.ZERO
            )
        );
    }
}
