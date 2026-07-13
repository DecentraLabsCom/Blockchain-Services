package decentralabs.blockchain.service.auth;

import java.time.Instant;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import decentralabs.blockchain.service.wallet.BlockchainBookingService;
import java.math.BigInteger;
import java.util.Map;

/** Monitors receipts for hashes already persisted by the submission worker. */
@Service
@RequiredArgsConstructor
@Slf4j
public class InstitutionalCheckInReceiptMonitor {
    private final InstitutionalCheckInOutboxService outboxService;
    private final CheckInOnChainService checkInOnChainService;
    private final BlockchainBookingService bookingService;

    @Value("${institutional.checkin.outbox.batch-size:10}")
    private int batchSize;

    @Value("${institutional.checkin.outbox.stuck-transaction-ms:15000}")
    private long stuckTransactionMs;

    @Value("${institutional.checkin.outbox.max-attempts:8}")
    private int maxAttempts;

    @Scheduled(fixedDelayString = "${institutional.checkin.outbox.receipt-interval-ms:2000}")
    public void monitorSubmittedCheckIns() {
        List<InstitutionalCheckInOutboxRecord> submitted = outboxService.findSubmitted(
            Instant.now(), Math.max(1, batchSize)
        );
        if (submitted == null) {
            return;
        }
        for (InstitutionalCheckInOutboxRecord record : submitted) {
            monitor(record);
        }
        List<InstitutionalCheckInOutboxRecord> unknown = outboxService.findStuckUnknown(Math.max(1, batchSize));
        if (unknown != null) {
            for (InstitutionalCheckInOutboxRecord record : unknown) {
                reconcileUnknown(record);
            }
        }
    }

    void reconcileUnknown(InstitutionalCheckInOutboxRecord record) {
        if (record == null || record.txHash() == null || record.txHash().isBlank()) {
            return;
        }
        try {
            if (isAccessAlreadyAuthorized(record)) {
                outboxService.markUnknownMinedSuccess(record);
                return;
            }
            CheckInOnChainService.TransactionState state =
                checkInOnChainService.transactionStateStrict(record.txHash());
            if (state == CheckInOnChainService.TransactionState.SUCCEEDED) {
                outboxService.markUnknownMinedSuccess(record);
                return;
            }
            if (state == CheckInOnChainService.TransactionState.FAILED) {
                outboxService.markUnknownMinedFailed(record, "Check-in transaction reverted on-chain");
                return;
            }
            if (record.nonce() == null || record.walletAddress() == null
                    || checkInOnChainService.transactionVisible(record.txHash())) {
                return;
            }
            BigInteger pendingNonce = checkInOnChainService.pendingNonce(record.walletAddress());
            if (pendingNonce.compareTo(record.nonce()) <= 0) {
                outboxService.markUnknownRetry(
                    record,
                    Instant.now(),
                    "Reconciler proved the transaction absent and its nonce unconsumed; retrying the same nonce"
                );
            }
        } catch (RuntimeException ex) {
            log.warn("Unable to reconcile institutional check-in {}: {}", record.id(), ex.getMessage());
        }
    }

    private boolean isAccessAlreadyAuthorized(InstitutionalCheckInOutboxRecord record) {
        Map<String, Object> bookingInfo = bookingService.getCheckInBookingInfo(
            record.institutionalWallet(), record.reservationKey(), record.labId(), null
        );
        Object value = bookingInfo.get("reservationStatus");
        if (value instanceof Number status) {
            return status.longValue() == 2L;
        }
        try {
            return value != null && new BigInteger(value.toString()).longValue() == 2L;
        } catch (RuntimeException ignored) {
            return false;
        }
    }

    void monitor(InstitutionalCheckInOutboxRecord record) {
        if (record == null || record.txHash() == null || record.txHash().isBlank()) {
            return;
        }
        try {
            CheckInOnChainService.TransactionState state = checkInOnChainService.transactionState(record.txHash());
            if (state == CheckInOnChainService.TransactionState.SUCCEEDED) {
                outboxService.markSubmittedMinedSuccess(record);
            } else if (state == CheckInOnChainService.TransactionState.FAILED) {
                outboxService.markSubmittedMinedFailed(record, "Check-in transaction reverted on-chain");
            } else if (isStuck(record)) {
                int nextAttempt = record.attempts() + 1;
                if (nextAttempt >= Math.max(1, maxAttempts)) {
                    outboxService.markStuckUnknown(
                        record,
                        nextAttempt,
                        "Check-in transaction remained pending after the maximum number of broadcasts"
                    );
                } else {
                    outboxService.markSubmittedRetry(
                        record,
                        nextAttempt,
                        Instant.now(),
                        "Check-in transaction is still pending; retrying with the same nonce and higher gas"
                    );
                }
            }
        } catch (RuntimeException ex) {
            log.warn("Unable to monitor institutional check-in {}: {}", record.id(), ex.getMessage());
        }
    }

    private boolean isStuck(InstitutionalCheckInOutboxRecord record) {
        if (record.submittedAt() == null) {
            return false;
        }
        return record.submittedAt().plusMillis(Math.max(1L, stuckTransactionMs)).isBefore(Instant.now());
    }
}
