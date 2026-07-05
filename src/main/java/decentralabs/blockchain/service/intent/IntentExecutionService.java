package decentralabs.blockchain.service.intent;

import decentralabs.blockchain.config.ContractEventListenerConfig;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

import io.micrometer.core.instrument.MeterRegistry;
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
    private final MeterRegistry meterRegistry;
    private final ConcurrentHashMap<String, AtomicBoolean> executionGuards = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> registrationFailures = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, RegistrationSignal> registrationSignals = new ConcurrentHashMap<>();

    @Value("${intent.execution-interval-ms:1000}")
    private long executionIntervalMs;

    @Value("${intent.registration-pending-max-age-seconds:900}")
    private long registrationPendingMaxAgeSeconds;

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

    public Map<String, String> handleRegistrationSignal(String requestId, String event, String txHash, Long blockNumber, String reason) {
        if (requestId == null || requestId.isBlank()) {
            return Map.of("status", "ignored", "reason", "missing_request_id");
        }
        String normalizedEvent = event == null ? "" : event.trim().toLowerCase();
        if ("registration_submitted".equals(normalizedEvent)) {
            rememberRegistrationSignal(requestId, txHash, blockNumber);
            recordMetric("intent.registration.signal.submitted");
            return Map.of("status", "accepted", "requestId", requestId);
        }
        if ("registration_failed".equals(normalizedEvent)) {
            rememberRegistrationSignal(requestId, txHash, blockNumber);
            registrationFailures.put(requestId, reason == null || reason.isBlank() ? "registration_failed" : reason);
            intentService.findByRequestId(requestId).ifPresent(record -> {
                applyRegistrationSignal(record);
                if (record.getStatus() == IntentStatus.AUTHORIZED_PENDING_REGISTRATION) {
                    intentService.markFailed(record, registrationFailures.remove(requestId));
                }
            });
            recordMetric("intent.registration.signal.failed");
            return Map.of("status", "accepted", "requestId", requestId);
        }
        if (!"registration_mined".equals(normalizedEvent)) {
            return Map.of("status", "ignored", "requestId", requestId, "reason", "unsupported_event");
        }
        rememberRegistrationSignal(requestId, txHash, blockNumber);
        recordMetric("intent.registration.signal.mined");
        processQueuedIntent(requestId);
        return Map.of("status", "accepted", "requestId", requestId);
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
                applyRegistrationSignal(record);
                if (isRegistrationPendingTimedOut(record)) {
                    String reason = "registration_pending_timeout";
                    log.warn(
                        "Intent {} exceeded AUTHORIZED_PENDING_REGISTRATION max age. ageSeconds={} maxAgeSeconds={} registrationTxHash={}",
                        record.getRequestId(),
                        registrationPendingAgeSeconds(record),
                        registrationPendingMaxAgeSeconds,
                        record.getRegistrationTxHash()
                    );
                    recordMetric("intent.registration.pending.timeout");
                    intentService.markFailed(record, reason);
                    return;
                }
                String failedRegistration = registrationFailures.remove(record.getRequestId());
                if (failedRegistration != null && !failedRegistration.isBlank()) {
                    intentService.markFailed(record, failedRegistration);
                    return;
                }
                IntentRegistrationVerifier.RegistrationVerificationResult verification =
                    registrationVerifier.verifyRegistration(record);
                if (!verification.verified()) {
                    if (!verification.retryable()) {
                        recordMetric("intent.registration.verification.terminal");
                        intentService.markFailed(record, verification.reason());
                    } else {
                        log.info(
                            "Intent {} remains pending registration: reason={} registrationTxHash={} ageSeconds={}",
                            record.getRequestId(),
                            verification.reason(),
                            record.getRegistrationTxHash(),
                            registrationPendingAgeSeconds(record)
                        );
                        recordMetric("intent.registration.verification.retryable");
                    }
                    return;
                }
                recordMetric("intent.registration.verification.success");
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
            log.warn("Intent {} failed during execution: {}", record.getRequestId(), ex.getMessage(), ex);
            intentService.markFailed(record, "execution_error: " + ex.getMessage());
        } finally {
            executionGuards.remove(record.getRequestId(), guard);
        }
    }

    private void rememberRegistrationSignal(String requestId, String txHash, Long blockNumber) {
        if (txHash == null || txHash.isBlank()) {
            return;
        }
        if (!isTransactionHash(txHash)) {
            log.warn("Ignoring malformed registration txHash for intent {}", requestId);
            recordMetric("intent.registration.signal.malformed_tx_hash");
            return;
        }
        registrationSignals.put(requestId, new RegistrationSignal(txHash, blockNumber));
        boolean persisted = intentService.recordRegistrationSignal(requestId, txHash, blockNumber);
        if (!persisted) {
            log.info("Intent {} registration signal stored until WebAuthn authorization creates the record", requestId);
        }
    }

    private void applyRegistrationSignal(IntentRecord record) {
        RegistrationSignal signal = registrationSignals.remove(record.getRequestId());
        if (signal == null) {
            return;
        }
        if (record.getRegistrationTxHash() == null || record.getRegistrationTxHash().isBlank()) {
            record.setRegistrationTxHash(signal.txHash());
        }
        if (record.getRegistrationBlockNumber() == null && signal.blockNumber() != null) {
            record.setRegistrationBlockNumber(signal.blockNumber());
        }
        intentService.recordRegistrationSignal(record.getRequestId(), signal.txHash(), signal.blockNumber());
    }

    private boolean isRegistrationPendingTimedOut(IntentRecord record) {
        return registrationPendingMaxAgeSeconds > 0
            && record.getCreatedAt() != null
            && registrationPendingAgeSeconds(record) >= registrationPendingMaxAgeSeconds;
    }

    private long registrationPendingAgeSeconds(IntentRecord record) {
        if (record == null || record.getCreatedAt() == null) {
            return 0L;
        }
        return Math.max(0L, Instant.now().getEpochSecond() - record.getCreatedAt().getEpochSecond());
    }

    private void recordMetric(String name) {
        try {
            meterRegistry.counter(name).increment();
        } catch (Exception ex) {
            log.debug("Unable to record metric {}", name, ex);
        }
    }

    private boolean isTransactionHash(String txHash) {
        return txHash != null && txHash.matches("(?i)^0x[0-9a-f]{64}$");
    }

    private record RegistrationSignal(String txHash, Long blockNumber) {}

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
