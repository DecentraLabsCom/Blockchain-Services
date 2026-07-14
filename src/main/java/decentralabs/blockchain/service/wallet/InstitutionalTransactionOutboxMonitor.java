package decentralabs.blockchain.service.wallet;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.time.Duration;
import java.time.Instant;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Hash;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.utils.Numeric;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthChainId;

/**
 * Reconciles generic institutional transactions after the broadcast worker
 * has handed them to the node.  The outbox, rather than an in-memory map, is
 * the source of truth across restarts and replicas.
 */
@Service
@Slf4j
public class InstitutionalTransactionOutboxMonitor {
    private final InstitutionalTransactionOutboxService outboxService;
    private final WalletService walletService;
    private final InstitutionalWalletService institutionalWalletService;

    public InstitutionalTransactionOutboxMonitor(
        InstitutionalTransactionOutboxService outboxService,
        WalletService walletService,
        InstitutionalWalletService institutionalWalletService
    ) {
        this.outboxService = outboxService;
        this.walletService = walletService;
        this.institutionalWalletService = institutionalWalletService;
    }

    @Value("${institutional.transaction-outbox.monitor.enabled:true}")
    private boolean enabled;

    @Value("${institutional.transaction-outbox.monitor.batch-size:20}")
    private int batchSize;

    @Value("${institutional.transaction-outbox.monitor.submitted-stale-after-ms:120000}")
    private long submittedStaleAfterMs;

    @Value("${institutional.transaction-outbox.monitor.max-attempts:10}")
    private int maxAttempts = 10;

    @Value("${institutional.transaction-outbox.monitor.max-pending-ms:900000}")
    private long maxPendingMs = 900_000L;

    @Value("${institutional.transaction-outbox.monitor.gas-bump-percent:20}")
    private int gasBumpPercent = 20;

    @Value("${institutional.transaction-outbox.monitor.max-gas-price-wei:100000000000}")
    private BigInteger maxGasPriceWei = BigInteger.valueOf(100_000_000_000L);

    @Value("${institutional.transaction-outbox.monitor.max-multiplier:3}")
    private BigDecimal maxMultiplier = BigDecimal.valueOf(3L);

    @Value("${institutional.transaction-outbox.monitor.max-estimated-transaction-cost-wei:100000000000000000}")
    private BigInteger maxEstimatedTransactionCost = BigInteger.valueOf(100_000_000_000_000_000L);

    @Scheduled(fixedDelayString = "${institutional.transaction-outbox.monitor.interval-ms:5000}")
    public void monitorScheduled() {
        if (!enabled) {
            return;
        }
        try {
            monitor(walletService.getWeb3jInstance(), Math.max(1, batchSize));
        } catch (Exception ex) {
            log.warn("Institutional transaction outbox monitor unavailable: {}", ex.getMessage());
        }
    }

    int monitor(Web3j web3j, int limit) {
        if (web3j == null) {
            return 0;
        }
        MonitoringContext context;
        try {
            context = resolveContext(web3j);
        } catch (Exception ex) {
            log.warn("Unable to resolve institutional outbox context: {}", ex.getMessage());
            return 0;
        }
        int updated = 0;
        var recoveryCandidates = outboxService.findRecoveryCandidates(
            context.chainId(), context.walletAddress(), limit
        );
        var matchingRecoveryCandidates = recoveryCandidates.stream()
            .filter(attempt -> matchesContext(context, attempt))
            .toList();
        if (!matchingRecoveryCandidates.isEmpty()) {
            try {
                Credentials credentials = institutionalWalletService.getInstitutionalCredentials();
                if (credentials != null && context.walletAddress().equalsIgnoreCase(credentials.getAddress())) {
                    for (InstitutionalTransactionOutboxService.Attempt attempt : matchingRecoveryCandidates) {
                        updated += recoverReserved(web3j, credentials, attempt) ? 1 : 0;
                    }
                } else {
                    log.warn("Institutional credentials do not match the active wallet; recovery is quarantined");
                }
            } catch (Exception ex) {
                log.warn("Unable to recover reserved institutional transactions: {}", ex.getMessage());
            }
        } else if (!recoveryCandidates.isEmpty()) {
            log.warn("Skipping institutional outbox rows outside the active chain/wallet context");
        }
        for (InstitutionalTransactionOutboxService.Attempt attempt : outboxService.findSubmitted(
            context.chainId(), context.walletAddress(), limit
        )) {
            if (matchesContext(context, attempt)) {
                updated += inspectSubmitted(web3j, attempt) ? 1 : 0;
            }
        }
        for (InstitutionalTransactionOutboxService.Attempt attempt : outboxService.findStuckUnknown(
            context.chainId(), context.walletAddress(), limit
        )) {
            if (matchesContext(context, attempt)) {
                updated += retryUnknown(web3j, attempt) ? 1 : 0;
            }
        }
        return updated;
    }

    private MonitoringContext resolveContext(Web3j web3j) throws Exception {
        EthChainId response = web3j.ethChainId().send();
        BigInteger chainId = response == null ? null : response.getChainId();
        String walletAddress = institutionalWalletService.getInstitutionalWalletAddress();
        if (chainId == null || chainId.signum() <= 0) {
            throw new IllegalStateException("RPC returned no valid chain ID");
        }
        if (walletAddress == null || walletAddress.isBlank()) {
            throw new IllegalStateException("Institutional wallet address is not configured");
        }
        return new MonitoringContext(chainId, walletAddress.trim());
    }

    private boolean matchesContext(
        MonitoringContext context,
        InstitutionalTransactionOutboxService.Attempt attempt
    ) {
        return attempt != null
            && context.chainId().equals(attempt.chainId())
            && context.walletAddress().equalsIgnoreCase(attempt.walletAddress());
    }

    private boolean recoverReserved(
        Web3j web3j,
        Credentials credentials,
        InstitutionalTransactionOutboxService.Attempt attempt
    ) {
        try {
            if (attempt == null || credentials == null
                || !credentials.getAddress().equalsIgnoreCase(attempt.walletAddress())) {
                return false;
            }
            boolean reconstructingReservedMaterial = needsReconstruction(attempt);
            if (!reconstructingReservedMaterial && requiresManualIntervention(attempt)) {
                outboxService.markStuckUnknown(
                    attempt, "Institutional transaction exceeded the retry budget; manual intervention required"
                );
                return true;
            }
            String raw = attempt.signedRawTransaction();
            String hash = attempt.txHash();
            boolean replacementPending = "REPLACEMENT_PENDING".equals(attempt.status());
            boolean retryableReplacement = "RETRYABLE".equals(attempt.status()) && attempt.attempts() > 0;
            boolean unknownReplacement = "STUCK_UNKNOWN".equals(attempt.status())
                && attempt.txHash() != null && !attempt.txHash().isBlank();
            boolean replacementPrepared = false;
            boolean materialPrepared = false;
            if (raw == null || raw.isBlank()) {
                if (attempt.gasPrice() == null || attempt.gasLimit() == null || attempt.toAddress() == null
                    || attempt.value() == null || attempt.data() == null || attempt.nonce() == null) {
                    return false;
                }
                BigInteger gasPrice = gasPriceForAttempt(attempt, replacementPending || retryableReplacement || unknownReplacement
                    ? attempt.attempts() + 1 : attempt.attempts());
                raw = sign(attempt, credentials, gasPrice);
                hash = Hash.sha3(raw);
                if ((replacementPending || retryableReplacement || unknownReplacement) && attempt.txHash() != null
                    && !attempt.txHash().isBlank()) {
                    outboxService.markReplacementPrepared(attempt, attempt.txHash(), raw, hash, gasPrice);
                    replacementPrepared = true;
                } else {
                    outboxService.markSigned(attempt, raw, hash);
                    materialPrepared = true;
                }
            } else if (replacementPending || retryableReplacement) {
                // A retryable error was classified before the broadcast outcome
                // became uncertain. Check the persisted material first; only
                // then create a same-nonce replacement with a bounded gas bump.
                MaterialState state = inspectPersistedMaterial(web3j, attempt, hash);
                if (state == MaterialState.MINED_SUCCESS || state == MaterialState.MINED_FAILED
                    || (state == MaterialState.VISIBLE && !replacementPending)) {
                    return true;
                }
                BigInteger gasPrice = gasPriceForAttempt(attempt, attempt.attempts() + 1);
                raw = sign(attempt, credentials, gasPrice);
                hash = Hash.sha3(raw);
                if (attempt.txHash() != null && !attempt.txHash().isBlank()) {
                    outboxService.markReplacementPrepared(attempt, attempt.txHash(), raw, hash, gasPrice);
                    replacementPrepared = true;
                } else {
                    // There is no prior hash to reconcile when a legacy row has
                    // only partial signed material; persist the bounded material
                    // without inventing history for an unknown hash.
                    outboxService.markSigned(attempt, raw, hash, gasPrice);
                    materialPrepared = true;
                }
            } else if (hash != null && !hash.isBlank()) {
                MaterialState state = inspectPersistedMaterial(web3j, attempt, hash);
                if (state == MaterialState.MINED_SUCCESS || state == MaterialState.MINED_FAILED
                    || state == MaterialState.VISIBLE) {
                    return true;
                }
            }
            if (hash != null && !hash.isBlank()) {
                var receipt = web3j.ethGetTransactionReceipt(hash).send();
                if (receipt != null && receipt.getTransactionReceipt().isPresent()) {
                    if (receipt.getTransactionReceipt().orElseThrow().isStatusOK()) {
                        markMinedSuccess(attempt, hash);
                    } else {
                        outboxService.markMinedFailed(
                            attempt, hash, "Institutional transaction reverted on-chain"
                        );
                    }
                    return true;
                }
            }
            var response = web3j.ethSendRawTransaction(raw).send();
            if (response != null && !response.hasError()
                && response.getTransactionHash() != null && !response.getTransactionHash().isBlank()) {
                markBroadcastSubmitted(attempt, response.getTransactionHash(), replacementPrepared, materialPrepared);
                return true;
            }
            if (response != null && response.hasError() && response.getError() != null
                && response.getError().getMessage() != null
                && response.getError().getMessage().toLowerCase().contains("already known")) {
                markBroadcastSubmitted(attempt, hash, replacementPrepared, materialPrepared);
                return true;
            }
            if (response != null && response.hasError()) {
                outboxService.markRetryable(
                    attempt,
                    response.getError() != null ? response.getError().getMessage() : "Institutional transaction broadcast failed"
                );
            }
        } catch (Exception ex) {
            outboxService.markRetryable(attempt, ex.getMessage());
            long attemptId = attempt == null ? -1L : attempt.id();
            log.warn("Unable to recover reserved institutional transaction {}: {}", attemptId, ex.getMessage());
        }
        return false;
    }

    private enum MaterialState { ABSENT, VISIBLE, MINED_SUCCESS, MINED_FAILED }

    private MaterialState inspectPersistedMaterial(
        Web3j web3j,
        InstitutionalTransactionOutboxService.Attempt attempt,
        String hash
    ) throws Exception {
        MaterialState receiptState = inspectReceipts(web3j, attempt);
        if (receiptState != MaterialState.ABSENT) {
            return receiptState;
        }
        for (String candidateHash : monitoredHashes(attempt)) {
            var transaction = web3j.ethGetTransactionByHash(candidateHash).send();
            if (transaction != null && transaction.getTransaction().isPresent()) {
                if (hash != null && !hash.isBlank()
                    && !"REPLACEMENT_PENDING".equals(attempt.status())) {
                    outboxService.markVisibleSubmitted(attempt, hash);
                }
                return MaterialState.VISIBLE;
            }
        }
        return MaterialState.ABSENT;
    }

    private MaterialState inspectReceipts(
        Web3j web3j,
        InstitutionalTransactionOutboxService.Attempt attempt
    ) throws Exception {
        for (String candidateHash : monitoredHashes(attempt)) {
            var receipt = web3j.ethGetTransactionReceipt(candidateHash).send();
            if (receipt != null && receipt.getTransactionReceipt().isPresent()) {
                if (receipt.getTransactionReceipt().orElseThrow().isStatusOK()) {
                    markMinedSuccess(attempt, candidateHash);
                    return MaterialState.MINED_SUCCESS;
                }
                outboxService.markMinedFailed(
                    attempt, candidateHash, "Institutional transaction reverted on-chain"
                );
                return MaterialState.MINED_FAILED;
            }
        }
        return MaterialState.ABSENT;
    }

    private void markMinedSuccess(
        InstitutionalTransactionOutboxService.Attempt attempt,
        String minedTxHash
    ) {
        if (minedTxHash != null && attempt != null && attempt.txHash() != null
            && minedTxHash.equalsIgnoreCase(attempt.txHash())) {
            outboxService.markMinedSuccess(attempt);
            return;
        }
        outboxService.markMinedSuccess(attempt, minedTxHash);
    }

    private void markBroadcastSubmitted(
        InstitutionalTransactionOutboxService.Attempt attempt,
        String txHash,
        boolean replacementPrepared,
        boolean materialPrepared
    ) {
        if (replacementPrepared) {
            outboxService.markReplacementSubmitted(attempt, txHash);
        } else if (materialPrepared) {
            outboxService.markSubmittedAfterPreparation(attempt, txHash);
        } else {
            outboxService.markVisibleSubmitted(attempt, txHash);
        }
    }

    private java.util.List<String> monitoredHashes(InstitutionalTransactionOutboxService.Attempt attempt) {
        java.util.List<String> hashes = new java.util.ArrayList<>();
        if (attempt != null && attempt.txHash() != null && !attempt.txHash().isBlank()) {
            hashes.add(attempt.txHash());
        }
        if (attempt != null) {
            java.util.List<String> history = outboxService.findReplacedHashes(attempt.id());
            if (history != null) {
                history.stream()
                    .filter(hash -> hash != null && !hash.isBlank())
                    .filter(hash -> hashes.stream().noneMatch(existing -> existing.equalsIgnoreCase(hash)))
                    .forEach(hashes::add);
            }
        }
        return hashes;
    }

    private String sign(
        InstitutionalTransactionOutboxService.Attempt attempt,
        Credentials credentials,
        BigInteger gasPrice
    ) {
        RawTransaction transaction = RawTransaction.createTransaction(
            attempt.nonce(), gasPrice, attempt.gasLimit(), attempt.toAddress(),
            attempt.value(), attempt.data()
        );
        return Numeric.toHexString(TransactionEncoder.signMessage(
            transaction, attempt.chainId().longValueExact(), credentials
        ));
    }

    private BigInteger gasPriceForAttempt(
        InstitutionalTransactionOutboxService.Attempt attempt,
        int replacementAttempt
    ) {
        BigInteger original = attempt.originalGasPrice() != null
            ? attempt.originalGasPrice() : attempt.gasPrice();
        if (original == null || original.signum() <= 0) {
            throw new IllegalStateException("Institutional transaction original gas price is missing");
        }
        int bump = Math.max(0, gasBumpPercent);
        int retries = Math.max(0, replacementAttempt);
        BigInteger multiplier = BigInteger.valueOf(100L + (long) bump * retries);
        BigInteger desired = original.multiply(multiplier).add(BigInteger.valueOf(99)).divide(BigInteger.valueOf(100));
        BigInteger allowed = null;

        if (maxMultiplier != null && maxMultiplier.signum() > 0) {
            allowed = maxMultiplier.multiply(new BigDecimal(original))
                .setScale(0, RoundingMode.FLOOR).toBigInteger();
        }
        if (maxGasPriceWei != null && maxGasPriceWei.signum() > 0) {
            allowed = cap(allowed, maxGasPriceWei);
        }
        if (maxEstimatedTransactionCost != null && maxEstimatedTransactionCost.signum() > 0
            && attempt.gasLimit() != null && attempt.gasLimit().signum() > 0) {
            allowed = cap(allowed, maxEstimatedTransactionCost.divide(attempt.gasLimit()));
        }
        if (allowed == null) {
            allowed = desired;
        }
        if (allowed.compareTo(original) < 0) {
            throw new IllegalStateException("Institutional transaction original gas price exceeds configured limits");
        }
        return min(desired, allowed);
    }

    private boolean needsReconstruction(InstitutionalTransactionOutboxService.Attempt attempt) {
        return attempt != null
            && (attempt.signedRawTransaction() == null || attempt.signedRawTransaction().isBlank())
            && (attempt.txHash() == null || attempt.txHash().isBlank());
    }

    private BigInteger min(BigInteger left, BigInteger right) {
        return left.compareTo(right) <= 0 ? left : right;
    }

    private BigInteger cap(BigInteger current, BigInteger candidate) {
        return current == null ? candidate : min(current, candidate);
    }

    private boolean requiresManualIntervention(InstitutionalTransactionOutboxService.Attempt attempt) {
        int allowedAttempts = Math.max(1, maxAttempts);
        if (attempt.attempts() >= allowedAttempts) {
            return true;
        }
        Instant startedAt = attempt.createdAt() != null ? attempt.createdAt() : attempt.updatedAt();
        long maxAge = Math.max(1L, maxPendingMs);
        return startedAt != null && startedAt.plusMillis(maxAge).isBefore(Instant.now());
    }

    private record MonitoringContext(BigInteger chainId, String walletAddress) { }

    private boolean inspectSubmitted(
        Web3j web3j,
        InstitutionalTransactionOutboxService.Attempt attempt
    ) {
        try {
            MaterialState receiptState = inspectReceipts(web3j, attempt);
            if (receiptState == MaterialState.MINED_SUCCESS || receiptState == MaterialState.MINED_FAILED) {
                return true;
            }

            boolean visible = false;
            for (String hash : monitoredHashes(attempt)) {
                var transactionResponse = web3j.ethGetTransactionByHash(hash).send();
                if (transactionResponse != null && transactionResponse.getTransaction().isPresent()) {
                    visible = true;
                    break;
                }
            }
            if (visible) {
                if (isSubmittedStale(attempt)) {
                    if (requiresManualIntervention(attempt)) {
                        outboxService.markStuckUnknown(
                            attempt,
                            "Institutional transaction exceeded the replacement budget; manual intervention required"
                        );
                    } else {
                        outboxService.markReplacementPending(
                            attempt,
                            "Submitted transaction remained visible without a receipt; replacement required"
                        );
                    }
                    return true;
                }
                return false;
            }

            BigInteger pendingNonce = web3j.ethGetTransactionCount(
                attempt.walletAddress(), DefaultBlockParameterName.PENDING
            ).send().getTransactionCount();
            if (pendingNonce != null && attempt.nonce() != null && pendingNonce.compareTo(attempt.nonce()) > 0) {
                outboxService.markStuckUnknown(attempt, "Transaction disappeared after the node consumed its nonce");
                return true;
            }
            if (isSubmittedStale(attempt)) {
                // A SUBMITTED row with no receipt, no node visibility and an
                // unconsumed nonce is a missing transaction, not a successful
                // submission. Move it to the existing exact-material recovery
                // path so later producers cannot create a nonce hole.
                outboxService.markStuckUnknown(
                    attempt,
                    "Submitted transaction is no longer visible and the node has not consumed its nonce"
                );
                return true;
            }
        } catch (Exception ex) {
            log.warn("Unable to monitor institutional transaction {}: {}", attempt.id(), ex.getMessage());
        }
        return false;
    }

    private boolean isSubmittedStale(InstitutionalTransactionOutboxService.Attempt attempt) {
        Instant updatedAt = attempt.updatedAt();
        if (updatedAt == null) {
            return true;
        }
        long threshold = Math.max(1L, submittedStaleAfterMs);
        return updatedAt.plus(Duration.ofMillis(threshold)).isBefore(Instant.now());
    }

    private boolean retryUnknown(
        Web3j web3j,
        InstitutionalTransactionOutboxService.Attempt attempt
    ) {
        if (attempt == null || attempt.nonce() == null) {
            return false;
        }
        try {
            if (attempt.txHash() != null && !attempt.txHash().isBlank()) {
                MaterialState receiptState = inspectReceipts(web3j, attempt);
                if (receiptState == MaterialState.MINED_SUCCESS || receiptState == MaterialState.MINED_FAILED) {
                    return true;
                }
                boolean visible = false;
                for (String hash : monitoredHashes(attempt)) {
                    var transactionResponse = web3j.ethGetTransactionByHash(hash).send();
                    if (transactionResponse != null && transactionResponse.getTransaction().isPresent()) {
                        visible = true;
                        break;
                    }
                }
                if (visible) {
                    outboxService.markVisibleSubmitted(attempt, attempt.txHash());
                    return true;
                }
            }
            if (attempt.signedRawTransaction() == null || attempt.signedRawTransaction().isBlank()) {
                return false;
            }
            BigInteger pendingNonce = web3j.ethGetTransactionCount(
                attempt.walletAddress(), DefaultBlockParameterName.PENDING
            ).send().getTransactionCount();
            if (pendingNonce == null || pendingNonce.compareTo(attempt.nonce()) > 0) {
                return false;
            }
            var response = web3j.ethSendRawTransaction(attempt.signedRawTransaction()).send();
            if (response != null && !response.hasError()
                && response.getTransactionHash() != null && !response.getTransactionHash().isBlank()) {
                outboxService.markVisibleSubmitted(attempt, response.getTransactionHash());
                return true;
            }
            if (response != null && response.hasError() && response.getError() != null
                && response.getError().getMessage() != null
                && response.getError().getMessage().toLowerCase().contains("already known")) {
                outboxService.markVisibleSubmitted(attempt, attempt.txHash());
                return true;
            }
        } catch (Exception ex) {
            log.warn("Unable to rebroadcast institutional transaction {}: {}", attempt.id(), ex.getMessage());
        }
        return false;
    }
}
