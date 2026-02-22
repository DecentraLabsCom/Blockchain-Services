package decentralabs.blockchain.service.treasury;

import decentralabs.blockchain.dto.treasury.InstitutionalAdminResponse;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import java.math.BigInteger;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
@ConditionalOnProperty(value = "treasury.prune.auto.enabled", havingValue = "true")
public class LabPayoutHeapAutoPrunerService {

    private final InstitutionalWalletService institutionalWalletService;
    private final WalletService walletService;
    private final InstitutionalAdminService adminService;

    @Value("${treasury.prune.auto.max-iterations:100}")
    private int autoPruneMaxIterations;

    @Value("${treasury.prune.auto.max-labs-per-run:25}")
    private int autoPruneMaxLabsPerRun;

    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicInteger labCursor = new AtomicInteger(0);

    @Scheduled(
        fixedDelayString = "${treasury.prune.auto.interval.ms:1209600000}",
        initialDelayString = "${treasury.prune.auto.initial-delay.ms:300000}"
    )
    public void runAutoPrune() {
        if (!running.compareAndSet(false, true)) {
            log.debug("Auto-prune skipped because a previous run is still active");
            return;
        }

        try {
            String providerAddress = institutionalWalletService.getInstitutionalWalletAddress();
            if (providerAddress == null || providerAddress.isBlank()) {
                log.debug("Auto-prune skipped: institutional wallet not configured");
                return;
            }

            List<BigInteger> labs = walletService.getLabsOwnedByProvider(providerAddress);
            if (labs.isEmpty()) {
                log.debug("Auto-prune skipped: provider {} has no labs", providerAddress);
                return;
            }

            int maxIterations = sanitizeIterations(autoPruneMaxIterations);
            int maxLabs = sanitizeMaxLabs(autoPruneMaxLabsPerRun);
            int labsToProcess = Math.min(maxLabs, labs.size());
            int startIndex = Math.floorMod(labCursor.get(), labs.size());
            BigInteger iterations = BigInteger.valueOf(maxIterations);

            int txSubmitted = 0;
            int labsPruned = 0;
            BigInteger simulatedRemovedTotal = BigInteger.ZERO;

            for (int i = 0; i < labsToProcess; i++) {
                BigInteger labId = labs.get((startIndex + i) % labs.size());
                if (labId == null || labId.compareTo(BigInteger.ZERO) <= 0) {
                    continue;
                }

                Optional<BigInteger> simulatedRemoved = walletService.simulatePrunePayoutHeap(
                    providerAddress,
                    labId,
                    iterations
                );
                if (simulatedRemoved.isEmpty() || simulatedRemoved.get().compareTo(BigInteger.ZERO) <= 0) {
                    continue;
                }

                InstitutionalAdminResponse response = adminService.prunePayoutHeapInternal(labId, iterations);
                if (!response.isSuccess()) {
                    log.warn(
                        "Auto-prune failed for lab {}: {}",
                        labId,
                        response.getMessage()
                    );
                    continue;
                }

                txSubmitted++;
                labsPruned++;
                simulatedRemovedTotal = simulatedRemovedTotal.add(simulatedRemoved.get());
            }

            labCursor.set((startIndex + labsToProcess) % labs.size());

            if (txSubmitted > 0) {
                log.info(
                    "Auto-prune completed: {} tx submitted across {} lab(s), simulated removed entries={}",
                    txSubmitted,
                    labsPruned,
                    simulatedRemovedTotal
                );
            } else {
                log.debug("Auto-prune completed: no labs required pruning");
            }
        } catch (Exception ex) {
            log.error("Auto-prune execution failed: {}", ex.getMessage(), ex);
        } finally {
            running.set(false);
        }
    }

    private int sanitizeIterations(int value) {
        if (value < 1) {
            return 1;
        }
        if (value > 1000) {
            return 1000;
        }
        return value;
    }

    private int sanitizeMaxLabs(int value) {
        if (value < 1) {
            return 1;
        }
        return value;
    }
}
