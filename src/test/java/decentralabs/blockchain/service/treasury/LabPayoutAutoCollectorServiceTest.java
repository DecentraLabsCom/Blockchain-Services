package decentralabs.blockchain.service.treasury;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.dto.treasury.InstitutionalAdminResponse;
import decentralabs.blockchain.dto.wallet.CollectSimulationResult;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class LabPayoutAutoCollectorServiceTest {

    @Mock
    private InstitutionalWalletService institutionalWalletService;

    @Mock
    private WalletService walletService;

    @Mock
    private InstitutionalAdminService adminService;

    private LabPayoutAutoCollectorService service;

    @BeforeEach
    void setUp() {
        service = new LabPayoutAutoCollectorService(institutionalWalletService, walletService, adminService);
        ReflectionTestUtils.setField(service, "autoCollectMaxBatch", 50);
        ReflectionTestUtils.setField(service, "autoCollectMaxRoundsPerLab", 4);
    }

    @Test
    void runAutoCollect_skipsWhenAlreadyRunning() {
        ReflectionTestUtils.setField(service, "running", new AtomicBoolean(true));

        service.runAutoCollect();

        verifyNoInteractions(institutionalWalletService, walletService, adminService);
    }

    @Test
    void runAutoCollect_skipsWhenInstitutionalWalletIsMissing() {
        when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(" ");

        service.runAutoCollect();

        verify(institutionalWalletService).getInstitutionalWalletAddress();
        verifyNoInteractions(walletService, adminService);
    }

    @Test
    void runAutoCollect_skipsWhenProviderHasNoLabs() {
        when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn("0xprovider");
        when(walletService.getLabsOwnedByProvider("0xprovider")).thenReturn(List.of());

        service.runAutoCollect();

        verify(walletService).getLabsOwnedByProvider("0xprovider");
        verifyNoInteractions(adminService);
    }

    @Test
    void runAutoCollect_sanitizesBatchAndRoundsAndSkipsInvalidLabs() {
        ReflectionTestUtils.setField(service, "autoCollectMaxBatch", 150);
        ReflectionTestUtils.setField(service, "autoCollectMaxRoundsPerLab", 0);
        when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn("0xprovider");
        when(walletService.getLabsOwnedByProvider("0xprovider"))
            .thenReturn(Arrays.asList(null, BigInteger.ZERO, BigInteger.ONE));
        when(walletService.simulateCollectLabPayout("0xprovider", BigInteger.ONE, BigInteger.valueOf(100)))
            .thenReturn(new CollectSimulationResult(true, null));
        when(adminService.collectLabPayoutInternal(BigInteger.ONE, BigInteger.valueOf(100)))
            .thenReturn(success());

        service.runAutoCollect();

        verify(walletService).simulateCollectLabPayout("0xprovider", BigInteger.ONE, BigInteger.valueOf(100));
        verify(adminService).collectLabPayoutInternal(BigInteger.ONE, BigInteger.valueOf(100));
    }

    @Test
    void runAutoCollect_stopsCollectingCurrentLabWhenSimulationTurnsFalse() {
        when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn("0xprovider");
        when(walletService.getLabsOwnedByProvider("0xprovider")).thenReturn(List.of(BigInteger.ONE));
        when(walletService.simulateCollectLabPayout("0xprovider", BigInteger.ONE, BigInteger.valueOf(50)))
            .thenReturn(new CollectSimulationResult(true, null))
            .thenReturn(new CollectSimulationResult(true, null))
            .thenReturn(new CollectSimulationResult(false, "nothing left"));
        when(adminService.collectLabPayoutInternal(BigInteger.ONE, BigInteger.valueOf(50)))
            .thenReturn(success())
            .thenReturn(success());

        service.runAutoCollect();

        verify(walletService, org.mockito.Mockito.times(3))
            .simulateCollectLabPayout("0xprovider", BigInteger.ONE, BigInteger.valueOf(50));
        verify(adminService, org.mockito.Mockito.times(2))
            .collectLabPayoutInternal(BigInteger.ONE, BigInteger.valueOf(50));
    }

    @Test
    void runAutoCollect_stopsCurrentLabWhenInternalCollectFails() {
        when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn("0xprovider");
        when(walletService.getLabsOwnedByProvider("0xprovider")).thenReturn(List.of(BigInteger.ONE, BigInteger.TWO));
        when(walletService.simulateCollectLabPayout("0xprovider", BigInteger.ONE, BigInteger.valueOf(50)))
            .thenReturn(new CollectSimulationResult(true, null));
        when(walletService.simulateCollectLabPayout("0xprovider", BigInteger.TWO, BigInteger.valueOf(50)))
            .thenReturn(new CollectSimulationResult(false, "empty"));
        when(adminService.collectLabPayoutInternal(BigInteger.ONE, BigInteger.valueOf(50)))
            .thenReturn(failure("rpc reverted"));

        service.runAutoCollect();

        verify(adminService).collectLabPayoutInternal(BigInteger.ONE, BigInteger.valueOf(50));
        verify(walletService).simulateCollectLabPayout("0xprovider", BigInteger.TWO, BigInteger.valueOf(50));
        verify(adminService, never()).collectLabPayoutInternal(BigInteger.TWO, BigInteger.valueOf(50));
    }

    @Test
    void runAutoCollect_resetsRunningFlagWhenExecutionThrows() {
        when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn("0xprovider");
        when(walletService.getLabsOwnedByProvider("0xprovider")).thenThrow(new RuntimeException("boom"));

        assertThatCode(() -> service.runAutoCollect()).doesNotThrowAnyException();

        AtomicBoolean running = (AtomicBoolean) ReflectionTestUtils.getField(service, "running");
        org.assertj.core.api.Assertions.assertThat(running).isNotNull();
        org.assertj.core.api.Assertions.assertThat(running.get()).isFalse();
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
