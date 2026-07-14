package decentralabs.blockchain.service.wallet;

import java.math.BigInteger;
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
        int updated = 0;
        try {
            Credentials credentials = institutionalWalletService.getInstitutionalCredentials();
            for (InstitutionalTransactionOutboxService.Attempt attempt : outboxService.findRecoveryCandidates(limit)) {
                updated += recoverReserved(web3j, credentials, attempt) ? 1 : 0;
            }
        } catch (Exception ex) {
            log.warn("Unable to recover reserved institutional transactions: {}", ex.getMessage());
        }
        for (InstitutionalTransactionOutboxService.Attempt attempt : outboxService.findSubmitted(limit)) {
            updated += inspectSubmitted(web3j, attempt) ? 1 : 0;
        }
        for (InstitutionalTransactionOutboxService.Attempt attempt : outboxService.findStuckUnknown(limit)) {
            updated += retryUnknown(web3j, attempt) ? 1 : 0;
        }
        return updated;
    }

    private boolean recoverReserved(
        Web3j web3j,
        Credentials credentials,
        InstitutionalTransactionOutboxService.Attempt attempt
    ) {
        try {
            String raw = attempt.signedRawTransaction();
            String hash = attempt.txHash();
            if (raw == null || raw.isBlank()) {
                if (attempt.gasPrice() == null || attempt.gasLimit() == null || attempt.toAddress() == null
                    || attempt.value() == null || attempt.data() == null || attempt.nonce() == null) {
                    return false;
                }
                RawTransaction transaction = RawTransaction.createTransaction(
                    attempt.nonce(), attempt.gasPrice(), attempt.gasLimit(), attempt.toAddress(),
                    attempt.value(), attempt.data()
                );
                raw = Numeric.toHexString(TransactionEncoder.signMessage(
                    transaction, attempt.chainId().longValueExact(), credentials
                ));
                hash = Hash.sha3(raw);
                outboxService.markSigned(attempt, raw, hash);
            }
            if (hash != null && !hash.isBlank()) {
                var receipt = web3j.ethGetTransactionReceipt(hash).send();
                if (receipt != null && receipt.getTransactionReceipt().isPresent()) {
                    if (receipt.getTransactionReceipt().orElseThrow().isStatusOK()) {
                        outboxService.markMinedSuccess(attempt);
                    } else {
                        outboxService.markMinedFailed(attempt, "Institutional transaction reverted on-chain");
                    }
                    return true;
                }
            }
            var response = web3j.ethSendRawTransaction(raw).send();
            if (response != null && !response.hasError()
                && response.getTransactionHash() != null && !response.getTransactionHash().isBlank()) {
                outboxService.markSubmitted(attempt, response.getTransactionHash());
                return true;
            }
            if (response != null && response.hasError() && response.getError() != null
                && response.getError().getMessage() != null
                && response.getError().getMessage().toLowerCase().contains("already known")) {
                outboxService.markSubmitted(attempt, hash);
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
            log.warn("Unable to recover reserved institutional transaction {}: {}", attempt.id(), ex.getMessage());
        }
        return false;
    }

    private boolean inspectSubmitted(
        Web3j web3j,
        InstitutionalTransactionOutboxService.Attempt attempt
    ) {
        try {
            var receiptResponse = web3j.ethGetTransactionReceipt(attempt.txHash()).send();
            if (receiptResponse != null && receiptResponse.getTransactionReceipt().isPresent()) {
                if (receiptResponse.getTransactionReceipt().orElseThrow().isStatusOK()) {
                    outboxService.markMinedSuccess(attempt);
                } else {
                    outboxService.markMinedFailed(attempt, "Institutional transaction reverted on-chain");
                }
                return true;
            }

            var transactionResponse = web3j.ethGetTransactionByHash(attempt.txHash()).send();
            if (transactionResponse != null && transactionResponse.getTransaction().isPresent()) {
                return false;
            }

            BigInteger pendingNonce = web3j.ethGetTransactionCount(
                attempt.walletAddress(), DefaultBlockParameterName.PENDING
            ).send().getTransactionCount();
            if (pendingNonce != null && attempt.nonce() != null && pendingNonce.compareTo(attempt.nonce()) > 0) {
                outboxService.markStuckUnknown(attempt, "Transaction disappeared after the node consumed its nonce");
                return true;
            }
        } catch (Exception ex) {
            log.warn("Unable to monitor institutional transaction {}: {}", attempt.id(), ex.getMessage());
        }
        return false;
    }

    private boolean retryUnknown(
        Web3j web3j,
        InstitutionalTransactionOutboxService.Attempt attempt
    ) {
        if (attempt.signedRawTransaction() == null || attempt.signedRawTransaction().isBlank()
            || attempt.nonce() == null) {
            return false;
        }
        try {
            BigInteger pendingNonce = web3j.ethGetTransactionCount(
                attempt.walletAddress(), DefaultBlockParameterName.PENDING
            ).send().getTransactionCount();
            if (pendingNonce == null || pendingNonce.compareTo(attempt.nonce()) > 0) {
                return false;
            }
            var response = web3j.ethSendRawTransaction(attempt.signedRawTransaction()).send();
            if (response != null && !response.hasError()
                && response.getTransactionHash() != null && !response.getTransactionHash().isBlank()) {
                outboxService.markSubmitted(attempt, response.getTransactionHash());
                return true;
            }
            if (response != null && response.hasError() && response.getError() != null
                && response.getError().getMessage() != null
                && response.getError().getMessage().toLowerCase().contains("already known")) {
                outboxService.markSubmitted(attempt, attempt.txHash());
                return true;
            }
        } catch (Exception ex) {
            log.warn("Unable to rebroadcast institutional transaction {}: {}", attempt.id(), ex.getMessage());
        }
        return false;
    }
}
