package decentralabs.blockchain.service.auth;

import java.time.Instant;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/** Monitors receipts for hashes already persisted by the submission worker. */
@Service
@RequiredArgsConstructor
@Slf4j
public class InstitutionalCheckInReceiptMonitor {
    private final InstitutionalCheckInOutboxService outboxService;
    private final CheckInOnChainService checkInOnChainService;

    @Value("${institutional.checkin.outbox.batch-size:10}")
    private int batchSize;

    @Value("${institutional.checkin.outbox.stuck-transaction-ms:120000}")
    private long stuckTransactionMs;

    @Scheduled(fixedDelayString = "${institutional.checkin.outbox.receipt-interval-ms:5000}")
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
    }

    void monitor(InstitutionalCheckInOutboxRecord record) {
        if (record == null || record.txHash() == null || record.txHash().isBlank()) {
            return;
        }
        try {
            CheckInOnChainService.TransactionState state = checkInOnChainService.transactionState(record.txHash());
            if (state == CheckInOnChainService.TransactionState.SUCCEEDED) {
                outboxService.markMinedSuccess(record.id(), record.txHash());
            } else if (state == CheckInOnChainService.TransactionState.FAILED) {
                outboxService.markMinedFailed(record.id(), "Check-in transaction reverted on-chain");
            } else if (isStuck(record)) {
                outboxService.markRetry(
                    record.id(),
                    record.attempts() + 1,
                    Instant.now(),
                    "Check-in transaction is still pending; retrying with the same nonce and higher gas"
                );
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
