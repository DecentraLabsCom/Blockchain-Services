package decentralabs.blockchain.service.billing;

import decentralabs.blockchain.domain.*;
import decentralabs.blockchain.service.persistence.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Generates compliance and accounting exports for MiCA
 * Art 4(3) limited-network voucher alignment.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ComplianceExportService {

    private final CreditAccountPersistenceService creditPersistence;
    private final FundingOrderPersistenceService fundingPersistence;
    private final ProviderSettlementPersistenceService settlementPersistence;
    private final ProviderNetworkPersistenceService networkPersistence;
    private final MicaVolumePersistenceService micaPersistence;

    /**
     * Prepaid balances by funding lot.
     */
    public List<CreditLot> exportPrepaidBalancesByLot(String address) {
        return creditPersistence.findCreditLots(address.toLowerCase());
    }

    /**
     * Credit movements (consumed) for a given account, limited.
     */
    public List<CreditMovement> exportConsumedByPeriod(String address, int limit) {
        return creditPersistence.findMovements(address.toLowerCase(), limit).stream()
                .filter(m -> m.getMovementType() == CreditMovement.Type.CAPTURE)
                .collect(Collectors.toList());
    }

    /**
     * Expired credit lots.
     */
    public List<CreditLot> exportExpiredLots(String address) {
        return creditPersistence.findCreditLots(address.toLowerCase()).stream()
                .filter(CreditLot::isExpired)
                .collect(Collectors.toList());
    }

    /**
     * Provider receivable accruals (submitted invoices).
     */
    public List<ProviderInvoiceRecord> exportProviderReceivableAccruals() {
        return settlementPersistence.findInvoicesByStatus(ProviderInvoiceRecord.Status.SUBMITTED);
    }

    /**
     * Completed payouts export.
     */
    public List<ProviderPayout> exportCompletedPayouts(String providerAddress) {
        return settlementPersistence.findPayoutsByProvider(providerAddress.toLowerCase());
    }

    /**
     * Rolling 12-month offer volume (MiCA Art 4(3) threshold).
     */
    public BigDecimal exportRolling12MonthVolume() {
        return micaPersistence.getLatestRollingVolume();
    }

    /**
     * Active provider network snapshot.
     */
    public List<ProviderNetworkMembership> exportProviderNetworkSnapshot() {
        return networkPersistence.findAllActive();
    }

    /**
     * Recent MiCA volume snapshots.
     */
    public List<MicaOfferVolume> exportMicaVolumeHistory(int limit) {
        return micaPersistence.findRecentSnapshots(limit);
    }
}
