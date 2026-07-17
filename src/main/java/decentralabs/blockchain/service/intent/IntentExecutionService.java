package decentralabs.blockchain.service.intent;

import decentralabs.blockchain.config.ContractEventListenerConfig;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.ObjectProvider;
import io.micrometer.observation.annotation.Observed;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import decentralabs.blockchain.dto.intent.IntentStatus;
import decentralabs.blockchain.util.LogSanitizer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class IntentExecutionService {

    private final IntentService intentService;
    private final IntentOnChainExecutor onChainExecutor;
    private final IntentRegistrationVerifier registrationVerifier;
    private final ObjectProvider<ContractEventListenerConfig> reservationAutoApprovalProcessor;
    private final ConcurrentHashMap<String, AtomicBoolean> executionGuards = new ConcurrentHashMap<>();

    @Value("${intent.execution-interval-ms:1000}")
    private long executionIntervalMs;

    @Observed(name = "intent.execution", contextualName = "process-queued-intent")
    public void processQueuedIntent(String requestId) {
        if (requestId == null || requestId.isBlank()) {
            return;
        }
        Optional<IntentRecord> record = intentService.findByRequestId(requestId);
        if (record.isEmpty()) {
            // codeql[java/log-injection]
            log.warn("Intent {} not found for immediate execution",
                LogSanitizer.maskIdentifier(requestId));
            return;
        }
        processRecord(record.get());
    }

    @Observed(name = "intent.execution", contextualName = "process-queued-intents")
    @Scheduled(fixedDelayString = "${intent.execution-interval-ms:1000}")
    public void processQueuedIntents() {
        Map<String, IntentRecord> current = intentService.getQueuedIntents();
        List<IntentRecord> pending = current.values().stream()
            .filter(r -> r.getStatus() == IntentStatus.QUEUED)
            .collect(Collectors.toList());

        if (pending.isEmpty()) {
            return;
        }

        log.info("Processing {} queued intents", pending.size());
        for (IntentRecord record : pending) {
            processRecord(record);
        }
    }

    @Observed(name = "intent.registration", contextualName = "process-pending-registrations")
    @Scheduled(fixedDelayString = "${intent.registration-poll-interval-ms:5000}")
    public void processPendingRegistrations() {
        Map<String, IntentRecord> current = intentService.getQueuedIntents();
        List<IntentRecord> pending = current.values().stream()
            .filter(r -> r.getStatus() == IntentStatus.AUTHORIZED_PENDING_REGISTRATION)
            .collect(Collectors.toList());

        for (IntentRecord record : pending) {
            processRecord(record);
        }
    }

    private void processRecord(IntentRecord record) {
        if (record == null || record.getRequestId() == null || record.getRequestId().isBlank()) {
            return;
        }
        AtomicBoolean guard = executionGuards.computeIfAbsent(record.getRequestId(), ignored -> new AtomicBoolean(false));
        if (!guard.compareAndSet(false, true)) {
            log.info("Intent {} is already being executed. Skipping duplicate attempt.", record.getRequestId());
            return;
        }
        try {
            if (record.getStatus() == IntentStatus.AUTHORIZED_PENDING_REGISTRATION) {
                IntentRegistrationVerifier.RegistrationVerificationResult verification =
                    registrationVerifier.verifyRegistration(record);
                if (!verification.verified()) {
                    if (!verification.retryable()) {
                        intentService.markFailed(record, verification.reason());
                    } else {
                        log.info("Intent {} remains pending registration: {}", record.getRequestId(), verification.reason());
                    }
                    return;
                }
                record.setStatus(IntentStatus.QUEUED);
                intentService.markQueued(record);
            }
            if (record.getStatus() != IntentStatus.QUEUED) {
                log.debug("Intent {} has status {}. Skipping execution.", record.getRequestId(), record.getStatus());
                return;
            }
            if (record.getExpiresAt() != null && record.getExpiresAt() <= Instant.now().getEpochSecond()) {
                intentService.markFailed(record, "expired");
                return;
            }
            intentService.markInProgress(record);
            IntentOnChainExecutor.ExecutionResult result = onChainExecutor.execute(record);
            if (result.success()) {
                intentService.markExecuted(record, result.txHash(), result.blockNumber(), result.labId(), result.reservationKey());
                triggerReservationPostflight(record, result);
            } else {
                log.warn("Intent {} failed on-chain: reason={} txHash={} blockNumber={}",
                    record.getRequestId(), result.reason(), result.txHash(), result.blockNumber());
                if (result.txHash() == null && result.blockNumber() == null) {
                    intentService.markFailed(record, result.reason());
                } else {
                    intentService.markFailed(record, result.reason(), result.txHash(), result.blockNumber());
                }
            }
        } catch (Exception ex) {
            log.warn("Intent {} failed during execution: {}",
                String.valueOf(record.getRequestId()).replaceAll("[\\r\\n\\t]+", "_"),
                String.valueOf(ex.getMessage()).replaceAll("[\\r\\n\\t]+", "_"), ex);
            intentService.markFailed(record, "execution_error: " + ex.getMessage());
        } finally {
            executionGuards.remove(record.getRequestId(), guard);
        }
    }

    private void triggerReservationPostflight(IntentRecord record, IntentOnChainExecutor.ExecutionResult result) {
        if (!"RESERVATION_REQUEST".equalsIgnoreCase(record.getAction())) {
            return;
        }
        String reservationKey = result.reservationKey();
        if (reservationKey == null || reservationKey.isBlank()) {
            reservationKey = record.getReservationKey();
        }
        if (reservationKey == null || reservationKey.isBlank()) {
            log.warn("Reservation intent {} executed without reservation key; skipping auto-approval postflight", record.getRequestId());
            return;
        }
        String key = reservationKey;
        reservationAutoApprovalProcessor.ifAvailable(processor -> {
            try {
                processor.processReservationRequestFromChain(key);
            } catch (Exception ex) {
                log.warn(
                    "Reservation postflight failed for intent {} key {}: {}",
                    record.getRequestId(),
                    key,
                    ex.getMessage()
                );
            }
        });
    }
}
