package decentralabs.blockchain.service.intent;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
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

    @Value("${intent.execution-interval-ms:5000}")
    private long executionIntervalMs;

    @Scheduled(fixedDelayString = "${intent.execution-interval-ms:5000}")
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
            try {
                if (record.getExpiresAt() != null && record.getExpiresAt() <= Instant.now().getEpochSecond()) {
                    intentService.markFailed(record, "expired");
                    continue;
                }
                intentService.markInProgress(record);
                IntentOnChainExecutor.ExecutionResult result = onChainExecutor.execute(record);
                if (result.success()) {
                    intentService.markExecuted(record, result.txHash(), result.blockNumber(), result.labId(), result.reservationKey());
                } else {
                    log.warn("Intent {} failed on-chain: reason={} txHash={} blockNumber={}",
                        record.getRequestId(), result.reason(), result.txHash(), result.blockNumber());
                    intentService.markFailed(record, result.reason(), result.txHash(), result.blockNumber());
                }
            } catch (Exception ex) {
                log.warn("Intent {} failed during execution: {}", record.getRequestId(), ex.getMessage(), ex);
                intentService.markFailed(record, "execution_error: " + ex.getMessage());
            }
        }
    }
}
