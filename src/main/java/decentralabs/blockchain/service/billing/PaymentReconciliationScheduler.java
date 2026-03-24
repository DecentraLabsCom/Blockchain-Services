package decentralabs.blockchain.service.billing;

import decentralabs.blockchain.domain.FundingOrder;
import decentralabs.blockchain.service.persistence.FundingOrderPersistenceService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Periodically checks for INVOICED funding orders awaiting payment confirmation.
 * Logs pending orders for manual reconciliation. In production this could poll
 * a payment gateway for confirmation.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class PaymentReconciliationScheduler {

    private final FundingOrderPersistenceService fundingPersistence;

    @Scheduled(fixedDelayString = "${billing.payment-reconciliation.interval-ms:300000}")
    public void reconcilePendingPayments() {
        try {
            List<FundingOrder> invoiced = fundingPersistence.findFundingOrdersByStatus(FundingOrder.Status.INVOICED);
            if (invoiced.isEmpty()) return;

            log.info("Payment reconciliation: {} INVOICED funding orders pending", invoiced.size());
            for (FundingOrder order : invoiced) {
                log.debug("Pending payment for funding order {} (institution: {}, EUR {})",
                        order.getId(), order.getInstitutionAddress(), order.getEurGrossAmount());
            }
        } catch (Exception e) {
            log.warn("Payment reconciliation check failed: {}", e.getMessage());
        }
    }
}
