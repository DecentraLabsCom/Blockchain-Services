package decentralabs.blockchain.service.billing;

import decentralabs.blockchain.config.ProviderConsumerModeCondition;
import decentralabs.blockchain.service.auth.InstitutionalWalletTransactionDispatcher;
import decentralabs.blockchain.service.wallet.InstitutionalTransactionOutboxService;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import java.math.BigInteger;
import java.time.Instant;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Conditional;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * Optional gas payer for the permissionless reservation finalizer.
 *
 * <p>This component is deliberately provider-consumer-only and disabled by
 * default. The chain entry point remains callable by any third party, so this
 * service is a convenience relayer rather than a source of authority.</p>
 */
@Service
@Conditional(ProviderConsumerModeCondition.class)
@Slf4j
public class ReservationFinalizationScheduler {
    private final WalletService walletService;
    private final InstitutionalWalletService institutionalWalletService;
    private final ReservationFinalizationOnChainClient onChainClient;
    private final InstitutionalTransactionOutboxService outboxService;
    private final InstitutionalWalletTransactionDispatcher transactionDispatcher;
    private int nextLabOffset;

    @Value("${reservation.finalization.scheduler.enabled:false}")
    private boolean enabled;

    @Value("${reservation.finalization.scheduler.max-batch:10}")
    private int configuredMaxBatch;

    @Value("${reservation.finalization.scheduler.max-labs-per-run:25}")
    private int configuredMaxLabsPerRun;

    @Value("${reservation.finalization.scheduler.interval-ms:60000}")
    private long intervalMs;

    @Value("${contract.address}")
    private String contractAddress;

    public ReservationFinalizationScheduler(
        WalletService walletService,
        InstitutionalWalletService institutionalWalletService,
        ReservationFinalizationOnChainClient onChainClient,
        InstitutionalTransactionOutboxService outboxService,
        InstitutionalWalletTransactionDispatcher transactionDispatcher
    ) {
        this.walletService = walletService;
        this.institutionalWalletService = institutionalWalletService;
        this.onChainClient = onChainClient;
        this.outboxService = outboxService;
        this.transactionDispatcher = transactionDispatcher;
    }

    @Scheduled(fixedDelayString = "${reservation.finalization.scheduler.interval-ms:60000}")
    public void finalizeScheduled() {
        if (!enabled) {
            return;
        }
        try {
            finalizePending();
        } catch (Exception ex) {
            log.warn("Reservation finalization scheduler unavailable: {}", ex.getMessage());
        }
    }

    int finalizePending() {
        if (!institutionalWalletService.isConfigured()) {
            log.debug("Reservation finalization scheduler skipped: institutional wallet is not configured");
            return 0;
        }

        String walletAddress = institutionalWalletService.getInstitutionalWalletAddress();
        if (walletAddress == null || walletAddress.isBlank()) {
            return 0;
        }

        BigInteger chainId = onChainClient.connectedChainId();
        BigInteger maxBatch = BigInteger.valueOf(Math.max(1, Math.min(10, configuredMaxBatch)));
        int maxLabs = Math.max(1, configuredMaxLabsPerRun);
        long now = Instant.now().getEpochSecond();
        long bucket = Math.max(1_000L, intervalMs) / 1_000L;
        long operationBucket = now / Math.max(1L, bucket);
        int submitted = 0;

        List<BigInteger> labIds = walletService.getLabsOwnedByProvider(walletAddress);
        for (BigInteger labId : selectLabsForRun(labIds, maxLabs)) {
            try {
                ReservationFinalizationOnChainClient.FinalizationStatus status = onChainClient.readStatus(labId);
                if (!status.hasCandidateWork(now)) {
                    continue;
                }

                onChainClient.validatePreflight(labId, maxBatch);
                String operationKey = "reservation-finalization:"
                    + labId + ":" + operationBucket;
                String data = onChainClient.encodedCall(labId, maxBatch);
                InstitutionalTransactionOutboxService.Attempt attempt = outboxService.reserveOrLoad(
                    walletAddress,
                    chainId,
                    onChainClient.pendingNonce(walletAddress),
                    operationKey,
                    onChainClient.gasPriceWei(),
                    onChainClient.gasLimit(),
                    configuredContractAddress(),
                    BigInteger.ZERO,
                    data
                );
                if (!"RESERVED".equals(attempt.status()) && !"RETRYABLE".equals(attempt.status())) {
                    continue;
                }

                transactionDispatcher.dispatchPrepared(
                    walletAddress,
                    chainId,
                    attempt.nonce(),
                    (ignoredChainId, ignoredNonce) -> { },
                    nonce -> onChainClient.prepare(labId, maxBatch, nonce, attempt.attempts(), attempt.originalGasPrice()),
                    prepared -> outboxService.markSigned(attempt, prepared.rawTransaction(), prepared.transactionHash(), prepared.gasPrice()),
                    txHash -> outboxService.markSubmittedAfterPreparation(attempt, txHash)
                );
                submitted++;
            } catch (InstitutionalTransactionOutboxService.TransactionBlockedException ex) {
                log.debug("Reservation finalization wallet is blocked for lab {}: {}", labId, ex.getMessage());
                break;
            } catch (Exception ex) {
                log.warn("Reservation finalization failed for lab {}: {}", labId, ex.getMessage());
            }
        }
        return submitted;
    }

    private List<BigInteger> selectLabsForRun(List<BigInteger> labIds, int maxLabs) {
        if (labIds == null || labIds.isEmpty()) {
            nextLabOffset = 0;
            return List.of();
        }

        int count = Math.min(maxLabs, labIds.size());
        int start = Math.floorMod(nextLabOffset, labIds.size());
        java.util.ArrayList<BigInteger> selected = new java.util.ArrayList<>(count);
        for (int index = 0; index < count; index++) {
            selected.add(labIds.get((start + index) % labIds.size()));
        }
        nextLabOffset = (start + count) % labIds.size();
        return selected;
    }

    private String configuredContractAddress() {
        if (contractAddress == null || contractAddress.isBlank()) {
            throw new IllegalStateException("Contract address is not configured");
        }
        return contractAddress;
    }
}
