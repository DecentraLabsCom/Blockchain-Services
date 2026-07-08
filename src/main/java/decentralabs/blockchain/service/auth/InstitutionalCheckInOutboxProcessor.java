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
    private static final BigInteger STATUS_IN_USE = BigInteger.valueOf(2);

    private final InstitutionalCheckInOutboxService outboxService;
    private final BlockchainBookingService bookingService;
    private final InstitutionalCheckInSubmissionService submissionService;

    @Value("${institutional.checkin.outbox.enabled:true}")
    private boolean enabled;

    @Value("${institutional.checkin.outbox.batch-size:10}")
    private int batchSize;

    @Value("${institutional.checkin.outbox.max-attempts:8}")
    private int maxAttempts;

    @Value("${institutional.checkin.outbox.retry-base-delay-ms:30000}")
    private long retryBaseDelayMs;

    @Value("${institutional.checkin.outbox.retry-max-delay-ms:900000}")
    private long retryMaxDelayMs;

    @Scheduled(fixedDelayString = "${institutional.checkin.outbox.interval-ms:10000}")
    public void processDueCheckIns() {
        if (!enabled) {
            return;
        }
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

        try {
            if (isAccessAlreadyAuthorized(record)) {
                outboxService.markSucceeded(record.id(), null);
                return;
            }

            var response = submissionService.submit(record.reservationKey(), record.pucHash());
            outboxService.markSucceeded(record.id(), response.getTxHash());
        } catch (Exception ex) {
            handleFailure(record, ex);
        }
    }

    private boolean isAccessAlreadyAuthorized(InstitutionalCheckInOutboxRecord record) {
        Map<String, Object> bookingInfo = bookingService.getCheckInBookingInfo(
            record.institutionalWallet(),
            record.reservationKey(),
            record.labId(),
            null
        );
        return isInUseStatus(bookingInfo.get("reservationStatus"));
    }

    private boolean isInUseStatus(Object value) {
        if (value instanceof BigInteger status) {
            return STATUS_IN_USE.equals(status);
        }
        if (value instanceof Number status) {
            return status.longValue() == STATUS_IN_USE.longValue();
        }
        if (value != null) {
            try {
                return STATUS_IN_USE.equals(new BigInteger(value.toString()));
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

    private long retryDelayMs(int attempts) {
        long base = Math.max(1L, retryBaseDelayMs);
        long max = Math.max(base, retryMaxDelayMs);
        int exponent = Math.min(Math.max(0, attempts - 1), 10);
        long delay = base * (1L << exponent);
        return Math.min(delay, max);
    }
}
