package decentralabs.blockchain.service.billing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.domain.CreditLot;
import decentralabs.blockchain.domain.CreditMovement;
import decentralabs.blockchain.domain.MicaOfferVolume;
import decentralabs.blockchain.domain.ProviderInvoiceRecord;
import decentralabs.blockchain.domain.ProviderNetworkMembership;
import decentralabs.blockchain.domain.ProviderPayout;
import decentralabs.blockchain.service.persistence.CreditAccountPersistenceService;
import decentralabs.blockchain.service.persistence.MicaVolumePersistenceService;
import decentralabs.blockchain.service.persistence.ProviderNetworkPersistenceService;
import decentralabs.blockchain.service.persistence.ProviderSettlementPersistenceService;
import java.math.BigDecimal;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class ComplianceExportServiceTest {

    private static final String ADDRESS = "0xABCDEFabcdefABCDEFabcdefABCDEFabcdefABCD";

    @Mock
    private CreditAccountPersistenceService creditPersistence;

    @Mock
    private ProviderSettlementPersistenceService settlementPersistence;

    @Mock
    private ProviderNetworkPersistenceService networkPersistence;

    @Mock
    private MicaVolumePersistenceService micaPersistence;

    private ComplianceExportService service;

    @BeforeEach
    void setUp() {
        service = new ComplianceExportService(
            creditPersistence,
            settlementPersistence,
            networkPersistence,
            micaPersistence
        );
    }

    @Test
    void exportsPrepaidBalancesUsingNormalizedAddress() {
        CreditLot lot = org.mockito.Mockito.mock(CreditLot.class);
        when(creditPersistence.findCreditLots(ADDRESS.toLowerCase())).thenReturn(List.of(lot));

        assertThat(service.exportPrepaidBalancesByLot(ADDRESS)).containsExactly(lot);
        verify(creditPersistence).findCreditLots(ADDRESS.toLowerCase());
    }

    @Test
    void exportsOnlyCaptureMovementsAndPreservesLimit() {
        CreditMovement capture = org.mockito.Mockito.mock(CreditMovement.class);
        CreditMovement refund = org.mockito.Mockito.mock(CreditMovement.class);
        when(capture.getMovementType()).thenReturn(CreditMovement.Type.CAPTURE);
        when(refund.getMovementType()).thenReturn(CreditMovement.Type.RELEASE);
        when(creditPersistence.findMovements(ADDRESS.toLowerCase(), 17))
            .thenReturn(List.of(capture, refund));

        assertThat(service.exportConsumedByPeriod(ADDRESS, 17)).containsExactly(capture);
        verify(creditPersistence).findMovements(ADDRESS.toLowerCase(), 17);
    }

    @Test
    void exportsOnlyExpiredCreditLots() {
        CreditLot expired = org.mockito.Mockito.mock(CreditLot.class);
        CreditLot active = org.mockito.Mockito.mock(CreditLot.class);
        when(expired.isExpired()).thenReturn(true);
        when(active.isExpired()).thenReturn(false);
        when(creditPersistence.findCreditLots(ADDRESS.toLowerCase()))
            .thenReturn(List.of(expired, active));

        assertThat(service.exportExpiredLots(ADDRESS)).containsExactly(expired);
    }

    @Test
    void exportsSubmittedInvoicesAndCompletedPayouts() {
        ProviderInvoiceRecord invoice = org.mockito.Mockito.mock(ProviderInvoiceRecord.class);
        ProviderPayout payout = org.mockito.Mockito.mock(ProviderPayout.class);
        when(settlementPersistence.findInvoicesByStatus(ProviderInvoiceRecord.Status.SUBMITTED))
            .thenReturn(List.of(invoice));
        when(settlementPersistence.findPayoutsByProvider(ADDRESS.toLowerCase()))
            .thenReturn(List.of(payout));

        assertThat(service.exportProviderReceivableAccruals()).containsExactly(invoice);
        assertThat(service.exportCompletedPayouts(ADDRESS)).containsExactly(payout);
    }

    @Test
    void exportsRollingVolumeNetworkSnapshotAndHistory() {
        ProviderNetworkMembership membership = org.mockito.Mockito.mock(ProviderNetworkMembership.class);
        MicaOfferVolume snapshot = org.mockito.Mockito.mock(MicaOfferVolume.class);
        when(micaPersistence.getLatestRollingVolume()).thenReturn(new BigDecimal("123.45"));
        when(networkPersistence.findAllActive()).thenReturn(List.of(membership));
        when(micaPersistence.findRecentSnapshots(12)).thenReturn(List.of(snapshot));

        assertThat(service.exportRolling12MonthVolume()).isEqualByComparingTo("123.45");
        assertThat(service.exportProviderNetworkSnapshot()).containsExactly(membership);
        assertThat(service.exportMicaVolumeHistory(12)).containsExactly(snapshot);
    }
}
