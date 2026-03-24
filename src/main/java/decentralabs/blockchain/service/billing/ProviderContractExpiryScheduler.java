package decentralabs.blockchain.service.billing;

import decentralabs.blockchain.domain.ProviderNetworkMembership;
import decentralabs.blockchain.service.persistence.ProviderNetworkPersistenceService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.List;

/**
 * Alerts when provider merchant agreements are approaching expiry.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ProviderContractExpiryScheduler {

    private final ProviderNetworkPersistenceService networkPersistence;

    @Value("${billing.provider-contract.warning-days:30}")
    private int warningDays;

    @Scheduled(fixedDelayString = "${billing.provider-contract-expiry.interval-ms:86400000}")
    public void checkExpiringContracts() {
        try {
            LocalDate threshold = LocalDate.now().plusDays(warningDays);
            List<ProviderNetworkMembership> expiring = networkPersistence.findExpiringBefore(threshold);
            if (expiring.isEmpty()) return;

            log.warn("Provider contract expiry alert: {} providers have contracts expiring before {}",
                    expiring.size(), threshold);
            for (ProviderNetworkMembership m : expiring) {
                log.warn("Provider {} contract {} expires {}",
                        m.getProviderAddress(), m.getContractId(), m.getExpiryDate());
            }
        } catch (Exception e) {
            log.warn("Provider contract expiry check failed: {}", e.getMessage());
        }
    }
}
