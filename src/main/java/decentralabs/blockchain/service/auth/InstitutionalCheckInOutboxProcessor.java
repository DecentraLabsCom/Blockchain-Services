package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.service.wallet.BlockchainBookingService;
import decentralabs.blockchain.util.LogSanitizer;
import java.math.BigInteger;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class InstitutionalCheckInOutboxProcessor {
    private static final BigInteger STATUS_ACCESS_AUTHORIZED = BigInteger.valueOf(2);

    private final InstitutionalCheckInOutboxService outboxService;
    private final BlockchainBookingService bookingService;
    private final InstitutionalWalletNonceDispatcher nonceDispatcher;

    @Value("${institutional.checkin.outbox.batch-size:10}")
    private int batchSize;

    @Value("${institutional.checkin.outbox.max-attempts:8}")
    private int maxAttempts;

    @Value("${institutional.checkin.outbox.retry-base-delay-ms:30000}")
    private long retryBaseDelayMs;

    @Value("${institutional.checkin.outbox.retry-max-delay-ms:900000}")
    private long retryMaxDelayMs;

    @Scheduled(fixedDelayString = "${institutional.checkin.outbox.interval-ms:2000}")
    public void processDueCheckIns() {
        List<InstitutionalCheckInOutboxRecord> due = outboxService.findDue(
            Instant.now(),
            Math.max(1, batchSize)
        );
        for (InstitutionalCheckInOutboxRecord record : due) {
            process(record);
        }
    }

    void process(InstitutionalCheckInOutboxRecord record) {
        if (record == null || !outboxService.claim(record.id())) {
            return;
        }

        InstitutionalCheckInOutboxRecord claimed;
        try {
            claimed = outboxService.findById(record.id());
        } catch (RuntimeException ex) {
            claimed = record;
        }
        if (claimed == null) {
            claimed = record;
        }

        try {
            if (isAccessAlreadyAuthorized(claimed)) {
                outboxService.markMinedSuccess(claimed.id(), null);
                return;
            }

            nonceDispatcher.dispatch(claimed);
        } catch (InstitutionalWalletDispatchException ex) {
            switch (ex.outcome()) {
                case PRE_BROADCAST_BLOCKED -> scheduleBlockedRetry(claimed, ex);
                case PRE_BROADCAST_TRANSIENT -> handleFailure(claimed, ex);
                case PRE_BROADCAST_PERMANENT -> outboxService.markFailed(
                    claimed.id(), claimed.attempts() + 1, LogSanitizer.sanitize(ex.getMessage())
                );
                case BROADCAST_OUTCOME_UNKNOWN -> {
                    int attempts = claimed.attempts() + 1;
                    String message = LogSanitizer.sanitize(ex.getMessage());
                    log.warn(
                        "Institutional check-in broadcast outcome is uncertain for reservation {}: {}",
                        LogSanitizer.sanitize(claimed.reservationKey()), message
                    );
                    outboxService.markBroadcastUncertain(claimed.id(), attempts, message);
                }
            }
        } catch (Exception ex) {
            handleFailure(claimed, ex);
        }
    }

    private boolean isAccessAlreadyAuthorized(InstitutionalCheckInOutboxRecord record) {
        Map<String, Object> bookingInfo = bookingService.getCheckInBookingInfo(
            record.institutionalWallet(),
            record.reservationKey(),
            record.labId(),
            null
        );
        return isAccessAuthorizedStatus(bookingInfo.get("reservationStatus"));
    }

    private boolean isAccessAuthorizedStatus(Object value) {
        if (value instanceof BigInteger status) {
            return STATUS_ACCESS_AUTHORIZED.equals(status);
        }
        if (value instanceof Number status) {
            return status.longValue() == STATUS_ACCESS_AUTHORIZED.longValue();
        }
        if (value != null) {
            try {
                return STATUS_ACCESS_AUTHORIZED.equals(new BigInteger(value.toString()));
            } catch (RuntimeException ignored) {
                return false;
            }
        }
        return false;
    }

    private void handleFailure(InstitutionalCheckInOutboxRecord record, Exception ex) {
        int attempts = record.attempts() + 1;
        String message = LogSanitizer.sanitize(ex.getMessage());
        if (attempts >= Math.max(1, maxAttempts)) {
            log.warn(
                "Institutional check-in outbox failed permanently for reservation {} after {} attempt(s): {}",
                LogSanitizer.sanitize(record.reservationKey()),
                attempts,
                message
            );
            outboxService.markFailed(record.id(), attempts, message);
            return;
        }

        Instant nextAttempt = Instant.now().plusMillis(retryDelayMs(attempts));
        log.warn(
            "Institutional check-in outbox retry scheduled for reservation {} attempt {}: {}",
            LogSanitizer.sanitize(record.reservationKey()),
            attempts,
            message
        );
        outboxService.markRetry(record.id(), attempts, nextAttempt, message);
    }

    private void scheduleBlockedRetry(InstitutionalCheckInOutboxRecord record, Exception ex) {
        String message = LogSanitizer.sanitize(ex.getMessage());
        outboxService.markRetry(
            record.id(), record.attempts(), Instant.now().plusMillis(retryDelayMs(Math.max(1, record.attempts()))), message
        );
    }

    private long retryDelayMs(int attempts) {
        long base = Math.max(1L, retryBaseDelayMs);
        long max = Math.max(base, retryMaxDelayMs);
        int exponent = Math.min(Math.max(0, attempts - 1), 10);
        long delay = base * (1L << exponent);
        return Math.min(delay, max);
    }
}
