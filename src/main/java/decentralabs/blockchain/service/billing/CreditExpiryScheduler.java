package decentralabs.blockchain.service.billing;

import decentralabs.blockchain.domain.CreditLot;
import decentralabs.blockchain.service.persistence.CreditAccountPersistenceService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;

/**
 * Periodically scans for expired credit lots and marks them as expired.
 * In production this would also trigger on-chain expireCredits() calls.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CreditExpiryScheduler {

    private final CreditAccountPersistenceService creditPersistence;

    @Scheduled(fixedDelayString = "${billing.credit-expiry.interval-ms:3600000}")
    public void processExpiringLots() {
        try {
            List<CreditLot> expiring = creditPersistence.findExpiringLots(Instant.now());
            if (expiring.isEmpty()) return;

            log.info("Found {} credit lots eligible for expiration", expiring.size());
            for (CreditLot lot : expiring) {
                try {
                    lot.setExpired(true);
                    creditPersistence.upsertCreditLot(lot);
                    log.info("Marked credit lot {}:{} as expired (remaining: {})",
                            lot.getAccountAddress(), lot.getLotIndex(), lot.getRemaining());
                } catch (Exception e) {
                    log.warn("Failed to expire credit lot {}:{}: {}",
                            lot.getAccountAddress(), lot.getLotIndex(), e.getMessage());
                }
            }
        } catch (Exception e) {
            log.warn("Credit expiry processing failed: {}", e.getMessage());
        }
    }
}
