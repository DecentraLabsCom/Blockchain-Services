package decentralabs.blockchain.service.treasury;

import decentralabs.blockchain.dto.treasury.InstitutionalAdminResponse;
import decentralabs.blockchain.dto.wallet.CollectSimulationResult;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import java.math.BigInteger;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
@ConditionalOnProperty(value = "treasury.collect.auto.enabled", havingValue = "true")
public class LabPayoutAutoCollectorService {

    private final InstitutionalWalletService institutionalWalletService;
    private final WalletService walletService;
    private final InstitutionalAdminService adminService;

    @Value("${treasury.collect.auto.max-batch:50}")
    private int autoCollectMaxBatch;

    @Value("${treasury.collect.auto.max-rounds-per-lab:4}")
    private int autoCollectMaxRoundsPerLab;

    private final AtomicBoolean running = new AtomicBoolean(false);

    @Scheduled(
        fixedDelayString = "${treasury.collect.auto.interval.ms:604800000}",
        initialDelayString = "${treasury.collect.auto.initial-delay.ms:120000}"
    )
    public void runAutoCollect() {
        if (!running.compareAndSet(false, true)) {
            log.debug("Auto-collect skipped because a previous run is still active");
            return;
        }

        try {
            String providerAddress = institutionalWalletService.getInstitutionalWalletAddress();
            if (providerAddress == null || providerAddress.isBlank()) {
                log.debug("Auto-collect skipped: institutional wallet not configured");
                return;
            }

            List<BigInteger> labs = walletService.getLabsOwnedByProvider(providerAddress);
            if (labs.isEmpty()) {
                log.debug("Auto-collect skipped: provider {} has no labs", providerAddress);
                return;
            }

            int batch = sanitizeBatch(autoCollectMaxBatch);
            int maxRounds = Math.max(1, autoCollectMaxRoundsPerLab);
            BigInteger batchValue = BigInteger.valueOf(batch);

            int txSubmitted = 0;
            int labsWithCollects = 0;

            for (BigInteger labId : labs) {
                if (labId == null || labId.compareTo(BigInteger.ZERO) <= 0) {
                    continue;
                }

                int rounds = 0;
                while (rounds < maxRounds) {
                    CollectSimulationResult simulation = walletService.simulateCollectLabPayout(
                        providerAddress,
                        labId,
                        batchValue
                    );
                    if (!simulation.canCollect()) {
                        break;
                    }

                    InstitutionalAdminResponse response = adminService.collectLabPayoutInternal(labId, batchValue);
                    if (!response.isSuccess()) {
                        log.warn(
                            "Auto-collect failed for lab {}: {}",
                            labId,
                            response.getMessage()
                        );
                        break;
                    }

                    rounds++;
                    txSubmitted++;
                }

                if (rounds > 0) {
                    labsWithCollects++;
                }
            }

            if (txSubmitted > 0) {
                log.info(
                    "Auto-collect completed: {} tx submitted across {} lab(s)",
                    txSubmitted,
                    labsWithCollects
                );
            } else {
                log.debug("Auto-collect completed: nothing collectable");
            }
        } catch (Exception ex) {
            log.error("Auto-collect execution failed: {}", ex.getMessage(), ex);
        } finally {
            running.set(false);
        }
    }

    private int sanitizeBatch(int value) {
        if (value < 1) {
            return 1;
        }
        if (value > 100) {
            return 100;
        }
        return value;
    }
}
