package decentralabs.blockchain.service.billing;

import decentralabs.blockchain.domain.ProviderInvoiceRecord;
import decentralabs.blockchain.service.persistence.ProviderSettlementPersistenceService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Flags aged provider receivables (submitted invoices) that may need attention.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ReceivableAgingScheduler {

    private final ProviderSettlementPersistenceService settlementPersistence;

    @Scheduled(fixedDelayString = "${billing.receivable-aging.interval-ms:86400000}")
    public void flagAgedReceivables() {
        try {
            List<ProviderInvoiceRecord> submitted =
                    settlementPersistence.findInvoicesByStatus(ProviderInvoiceRecord.Status.SUBMITTED);
            if (submitted.isEmpty()) return;

            log.info("Receivable aging: {} submitted provider invoices pending review", submitted.size());
            for (ProviderInvoiceRecord record : submitted) {
                log.debug("Aged receivable: invoice {} for lab {} provider {} (EUR {})",
                        record.getInvoiceRef(), record.getLabId(),
                        record.getProviderAddress(), record.getEurAmount());
            }
        } catch (Exception e) {
            log.warn("Receivable aging check failed: {}", e.getMessage());
        }
    }
}
