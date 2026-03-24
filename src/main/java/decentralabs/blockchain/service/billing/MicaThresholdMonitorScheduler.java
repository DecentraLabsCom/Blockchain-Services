package decentralabs.blockchain.service.billing;

import decentralabs.blockchain.domain.MicaOfferVolume;
import decentralabs.blockchain.service.persistence.MicaVolumePersistenceService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;

/**
 * Periodically computes the rolling 12-month EUR volume and alerts when
 * approaching the MiCA Art 4(3) limited-network exemption threshold.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class MicaThresholdMonitorScheduler {

    private final MicaVolumePersistenceService micaPersistence;

    @Value("${billing.mica.threshold-eur:1000000}")
    private BigDecimal micaThresholdEur;

    @Value("${billing.mica.warning-pct:80}")
    private int warningPercentage;

    @Scheduled(fixedDelayString = "${billing.mica-threshold.interval-ms:86400000}")
    public void monitorThreshold() {
        try {
            BigDecimal rolling = micaPersistence.getLatestRollingVolume();
            BigDecimal warningLevel = micaThresholdEur.multiply(BigDecimal.valueOf(warningPercentage))
                    .divide(BigDecimal.valueOf(100));

            if (rolling.compareTo(micaThresholdEur) >= 0) {
                log.error("MiCA THRESHOLD EXCEEDED: rolling 12-month EUR volume {} >= threshold {}",
                        rolling, micaThresholdEur);
            } else if (rolling.compareTo(warningLevel) >= 0) {
                log.warn("MiCA threshold warning: rolling 12-month EUR volume {} >= {}% of threshold {}",
                        rolling, warningPercentage, micaThresholdEur);
            } else {
                log.info("MiCA threshold OK: rolling 12-month EUR volume {} (threshold {})",
                        rolling, micaThresholdEur);
            }
        } catch (Exception e) {
            log.warn("MiCA threshold monitoring failed: {}", e.getMessage());
        }
    }
}
