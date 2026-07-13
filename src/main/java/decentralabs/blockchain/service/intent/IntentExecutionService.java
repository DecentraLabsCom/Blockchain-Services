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

    @Value("${intent.execution-stale-after-seconds:60}")
    private long executionStaleAfterSeconds;

    @Observed(name = "intent.execution", contextualName = "process-queued-intent")
    public void processQueuedIntent(String requestId) {
        if (requestId == null || requestId.isBlank()) {
            return;
        }
        Optional<IntentRecord> record = intentService.findByRequestId(requestId);
        if (record.isEmpty()) {
            log.warn("Intent {} not found for immediate execution", requestId);
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

    @Observed(name = "intent.execution", contextualName = "recover-stale-intent-claims")
    @Scheduled(fixedDelayString = "${intent.execution-recovery-interval-ms:30000}")
    public void recoverStaleExecutions() {
        long staleAfter = Math.max(10L, executionStaleAfterSeconds);
        int recovered = intentService.recoverStaleExecutions(Instant.now().minusSeconds(staleAfter));
        if (recovered > 0) {
            log.warn("Recovered {} stale institutional intent execution claim(s)", recovered);
        }
    }

    @Observed(name = "intent.receipt", contextualName = "monitor-submitted-intents")
    @Scheduled(fixedDelayString = "${intent.receipt-poll-interval-ms:5000}")
    public void monitorSubmittedIntents() {
        intentService.getQueuedIntents().values().stream()
            .filter(record -> record.getStatus() == IntentStatus.SUBMITTED)
            .forEach(this::monitorSubmittedRecord);
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
                if (result.txHash() != null && result.blockNumber() == null
                    && result.reason() != null && result.reason().startsWith("receipt_error:")) {
                    intentService.markSubmitted(record, result.txHash(), result.reason());
                } else if (result.txHash() == null && result.blockNumber() == null
                    && "dispatch_uncertain".equals(result.reason())) {
                    intentService.markRetryable(record, result.reason());
                } else if (result.txHash() == null && result.blockNumber() == null) {
                    intentService.markFailed(record, result.reason());
                } else {
                    intentService.markFailed(record, result.reason(), result.txHash(), result.blockNumber());
                }
            }
        } catch (IntentClaimRejectedException ex) {
            log.info("Intent {} is owned by another backend worker", record.getRequestId());
        } catch (Exception ex) {
            log.warn("Intent {} failed during execution: {}", record.getRequestId(), ex.getMessage(), ex);
            intentService.markFailed(record, "execution_error: " + ex.getMessage());
        } finally {
            executionGuards.remove(record.getRequestId(), guard);
        }
    }

    private void monitorSubmittedRecord(IntentRecord record) {
        try {
            IntentOnChainExecutor.ReceiptResult receipt = onChainExecutor.inspectReceipt(record);
            if (receipt.state() == IntentOnChainExecutor.ReceiptState.PENDING) {
                return;
            }
            if (receipt.state() == IntentOnChainExecutor.ReceiptState.MINED_SUCCESS) {
                intentService.markExecuted(
                    record,
                    record.getTxHash(),
                    receipt.blockNumber(),
                    receipt.labId(),
                    record.getReservationKey()
                );
                triggerReservationPostflight(
                    record,
                    new IntentOnChainExecutor.ExecutionResult(
                        true, record.getTxHash(), receipt.blockNumber(), receipt.labId(),
                        record.getReservationKey(), null
                    )
                );
            } else {
                intentService.markFailed(record, receipt.reason(), record.getTxHash(), receipt.blockNumber());
            }
        } catch (Exception ex) {
            log.debug("Receipt for intent {} remains unresolved: {}", record.getRequestId(), ex.getMessage());
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
