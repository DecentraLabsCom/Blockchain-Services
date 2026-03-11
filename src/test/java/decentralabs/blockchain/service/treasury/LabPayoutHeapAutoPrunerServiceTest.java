package decentralabs.blockchain.service.treasury;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.dto.treasury.InstitutionalAdminResponse;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class LabPayoutHeapAutoPrunerServiceTest {

    @Mock
    private InstitutionalWalletService institutionalWalletService;

    @Mock
    private WalletService walletService;

    @Mock
    private InstitutionalAdminService adminService;

    private LabPayoutHeapAutoPrunerService service;

    @BeforeEach
    void setUp() {
        service = new LabPayoutHeapAutoPrunerService(institutionalWalletService, walletService, adminService);
        ReflectionTestUtils.setField(service, "autoPruneMaxIterations", 100);
        ReflectionTestUtils.setField(service, "autoPruneMaxLabsPerRun", 25);
    }

    @Test
    void runAutoPrune_skipsWhenAlreadyRunning() {
        ReflectionTestUtils.setField(service, "running", new AtomicBoolean(true));

        service.runAutoPrune();

        verifyNoInteractions(institutionalWalletService, walletService, adminService);
    }

    @Test
    void runAutoPrune_skipsWhenInstitutionalWalletIsMissing() {
        when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn("");

        service.runAutoPrune();

        verify(institutionalWalletService).getInstitutionalWalletAddress();
        verifyNoInteractions(walletService, adminService);
    }

    @Test
    void runAutoPrune_skipsWhenProviderHasNoLabs() {
        when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn("0xprovider");
        when(walletService.getLabsOwnedByProvider("0xprovider")).thenReturn(List.of());

        service.runAutoPrune();

        verify(walletService).getLabsOwnedByProvider("0xprovider");
        verifyNoInteractions(adminService);
    }

    @Test
    void runAutoPrune_sanitizesLimitsAndAdvancesCursorAcrossSubset() {
        ReflectionTestUtils.setField(service, "autoPruneMaxIterations", 2000);
        ReflectionTestUtils.setField(service, "autoPruneMaxLabsPerRun", 2);
        ReflectionTestUtils.setField(service, "labCursor", new AtomicInteger(1));
        when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn("0xprovider");
        when(walletService.getLabsOwnedByProvider("0xprovider"))
            .thenReturn(List.of(BigInteger.ONE, BigInteger.TWO, BigInteger.valueOf(3)));
        when(walletService.simulatePrunePayoutHeap("0xprovider", BigInteger.TWO, BigInteger.valueOf(1000)))
            .thenReturn(Optional.of(BigInteger.ONE));
        when(walletService.simulatePrunePayoutHeap("0xprovider", BigInteger.valueOf(3), BigInteger.valueOf(1000)))
            .thenReturn(Optional.empty());
        when(adminService.prunePayoutHeapInternal(BigInteger.TWO, BigInteger.valueOf(1000)))
            .thenReturn(success());

        service.runAutoPrune();

        verify(walletService).simulatePrunePayoutHeap("0xprovider", BigInteger.TWO, BigInteger.valueOf(1000));
        verify(walletService).simulatePrunePayoutHeap("0xprovider", BigInteger.valueOf(3), BigInteger.valueOf(1000));
        verify(adminService).prunePayoutHeapInternal(BigInteger.TWO, BigInteger.valueOf(1000));
        AtomicInteger cursor = (AtomicInteger) ReflectionTestUtils.getField(service, "labCursor");
        assertThat(cursor).isNotNull();
        assertThat(cursor.get()).isEqualTo(0);
    }

    @Test
    void runAutoPrune_skipsInvalidLabsAndNonPositiveSimulationResults() {
        ReflectionTestUtils.setField(service, "autoPruneMaxIterations", 0);
        ReflectionTestUtils.setField(service, "autoPruneMaxLabsPerRun", 10);
        when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn("0xprovider");
        when(walletService.getLabsOwnedByProvider("0xprovider"))
            .thenReturn(Arrays.asList(null, BigInteger.ZERO, BigInteger.ONE));
        when(walletService.simulatePrunePayoutHeap("0xprovider", BigInteger.ONE, BigInteger.ONE))
            .thenReturn(Optional.of(BigInteger.ZERO));

        service.runAutoPrune();

        verify(walletService).simulatePrunePayoutHeap("0xprovider", BigInteger.ONE, BigInteger.ONE);
        verifyNoInteractions(adminService);
    }

    @Test
    void runAutoPrune_continuesAfterInternalPruneFailure() {
        when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn("0xprovider");
        when(walletService.getLabsOwnedByProvider("0xprovider"))
            .thenReturn(List.of(BigInteger.ONE, BigInteger.TWO));
        when(walletService.simulatePrunePayoutHeap("0xprovider", BigInteger.ONE, BigInteger.valueOf(100)))
            .thenReturn(Optional.of(BigInteger.ONE));
        when(walletService.simulatePrunePayoutHeap("0xprovider", BigInteger.TWO, BigInteger.valueOf(100)))
            .thenReturn(Optional.of(BigInteger.TWO));
        when(adminService.prunePayoutHeapInternal(BigInteger.ONE, BigInteger.valueOf(100)))
            .thenReturn(failure("gas too low"));
        when(adminService.prunePayoutHeapInternal(BigInteger.TWO, BigInteger.valueOf(100)))
            .thenReturn(success());

        service.runAutoPrune();

        verify(adminService).prunePayoutHeapInternal(BigInteger.ONE, BigInteger.valueOf(100));
        verify(adminService).prunePayoutHeapInternal(BigInteger.TWO, BigInteger.valueOf(100));
    }

    @Test
    void runAutoPrune_resetsRunningFlagWhenExecutionThrows() {
        when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn("0xprovider");
        when(walletService.getLabsOwnedByProvider("0xprovider")).thenThrow(new RuntimeException("boom"));

        assertThatCode(() -> service.runAutoPrune()).doesNotThrowAnyException();

        AtomicBoolean running = (AtomicBoolean) ReflectionTestUtils.getField(service, "running");
        assertThat(running).isNotNull();
        assertThat(running.get()).isFalse();
    }

    private InstitutionalAdminResponse success() {
        InstitutionalAdminResponse response = new InstitutionalAdminResponse();
        response.setSuccess(true);
        response.setMessage("ok");
        return response;
    }

    private InstitutionalAdminResponse failure(String message) {
        InstitutionalAdminResponse response = new InstitutionalAdminResponse();
        response.setSuccess(false);
        response.setMessage(message);
        return response;
    }
}
