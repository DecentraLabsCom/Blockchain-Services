package decentralabs.blockchain.config;

import io.reactivex.disposables.Disposable;
import java.math.BigInteger;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.web3j.abi.EventEncoder;
import org.web3j.abi.datatypes.Event;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameter;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.EthFilter;
import org.web3j.protocol.core.methods.response.EthLog;
import org.web3j.protocol.core.methods.response.EthBlock;
import org.web3j.protocol.core.methods.response.Log;

/**
 * Provides reliable event capture through a combination of WebSocket subscriptions
 * and periodic HTTP polling. This fallback mechanism ensures events are not lost
 * when using unreliable/free RPC nodes.
 *
 * <p>Features:
 * <ul>
 *   <li>Tracks last processed block per event type</li>
 *   <li>Periodic polling catches missed events</li>
 *   <li>Deduplication prevents double-processing</li>
 *   <li>Automatic reconnection on subscription failures</li>
 * </ul>
 */
@Service
@Slf4j
public class EventPollingFallbackService {

    @Value("${contract.event.polling.enabled:true}")
    private boolean pollingEnabled;

    @Value("${contract.event.websocket.enabled:true}")
    private boolean websocketEnabled;

    @Value("${contract.event.polling.interval.seconds:15}")
    private int pollingIntervalSeconds;

    @Value("${contract.event.polling.block.range:1000}")
    private int maxBlockRange;

    @Value("${contract.event.polling.lookback.blocks:100}")
    private int lookbackBlocks;

    @Value("${contract.event.persistence.required:true}")
    private boolean durableJournalRequired = true;

    @Value("${contract.event.processing.max-attempts:10}")
    private int maxProcessingAttempts = 10;

    @Value("${contract.event.processing.retry-delay.seconds:15}")
    private int retryDelaySeconds = 15;

    @Value("${contract.event.processing.lease-timeout.seconds:120}")
    private int processingLeaseTimeoutSeconds = 120;

    @Value("${contract.event.confirmations.required:12}")
    private int requiredConfirmations = 12;

    @Value("${contract.event.canonicality.verification.enabled:true}")
    private boolean canonicalityVerificationEnabled = true;

    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "event-polling-fallback");
        t.setDaemon(true);
        return t;
    });

    /** In-process mirror of the last successfully scanned block per event signature. */
    private final Map<String, BigInteger> lastProcessedBlock = new ConcurrentHashMap<>();

    /** In-process fallback deduplication for isolated tests/deployments without JDBC. */
    private final Map<String, Instant> recentlyProcessed = new ConcurrentHashMap<>();
    private final Map<String, Boolean> inMemoryProcessing = new ConcurrentHashMap<>();
    private static final Duration DEDUP_TTL = Duration.ofMinutes(10);

    private final String processingInstanceId = UUID.randomUUID().toString();

    /** Optional only for isolated deployments; production event listening requires it. */
    private final JdbcTemplate jdbcTemplate;

    /** Active subscriptions for cleanup */
    private final Map<String, Disposable> activeSubscriptions = new ConcurrentHashMap<>();

    /** Registered event handlers */
    private final Map<String, EventRegistration> registeredEvents = new ConcurrentHashMap<>();

    private volatile Web3j web3j;
    private volatile String contractAddress;
    private volatile BigInteger chainId = BigInteger.ZERO;
    private volatile boolean started = false;

    EventPollingFallbackService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    /**
     * Initialize the service with Web3j instance and contract address.
     */
    public void initialize(Web3j web3j, String contractAddress) {
        this.web3j = web3j;
        this.contractAddress = contractAddress;
        log.info("EventPollingFallbackService initialized for contract {}", contractAddress);
    }

    /**
     * Register an event to be monitored with both WebSocket and polling.
     *
     * @param eventName      Human-readable event name for logging
     * @param event          Web3j Event definition
     * @param startBlock     Block to start listening from (null for latest)
     * @param handler        Consumer to process matching logs
     */
    public void registerEvent(String eventName, Event event, BigInteger startBlock, Consumer<Log> handler) {
        String signature = EventEncoder.encode(event);
        
        EventRegistration registration = new EventRegistration(eventName, event, signature, startBlock, handler);
        registeredEvents.put(signature, registration);

        // Prefer the durable cursor. The configured start block is only the initial baseline.
        BigInteger durableCursor = loadDurableCursor(signature);
        if (durableCursor != null) {
            lastProcessedBlock.put(signature, durableCursor);
        } else if (startBlock != null) {
            lastProcessedBlock.put(signature, startBlock);
        } else {
            lastProcessedBlock.remove(signature);
        }

        log.info("Registered event '{}' with signature {} for monitoring", eventName, signature);
    }

    /**
     * Start both WebSocket subscriptions and polling fallback.
     */
    public synchronized void start() {
        if (started) {
            log.warn("EventPollingFallbackService already started");
            return;
        }
        if (web3j == null || contractAddress == null) {
            log.error("Cannot start: Web3j or contract address not initialized");
            return;
        }
        if (durableJournalRequired && jdbcTemplate == null) {
            log.error("Cannot start contract event listeners: durable event journal is unavailable");
            return;
        }

        if (jdbcTemplate != null) {
            try {
                chainId = web3j.ethChainId().send().getChainId();
            } catch (Exception ex) {
                log.error("Cannot start contract event listeners: chain ID could not be resolved", ex);
                return;
            }
        }

        started = true;

        // Start WebSocket subscriptions for real-time events
        if (websocketEnabled) {
            startWebSocketSubscriptions();
        } else {
            log.info("WebSocket contract event subscriptions are disabled");
        }

        // Start polling fallback
        if (pollingEnabled) {
            int effectiveRange = Math.max(1, maxBlockRange);
            int effectiveLookback = Math.max(0, lookbackBlocks);
            scheduler.scheduleWithFixedDelay(
                this::pollForMissedEvents,
                pollingIntervalSeconds, // initial delay
                pollingIntervalSeconds,
                TimeUnit.SECONDS
            );
            log.info("Event polling fallback started (interval={}s, range={} blocks, lookback={} blocks)",
                pollingIntervalSeconds, effectiveRange, effectiveLookback);
        } else {
            log.info("Event polling fallback is disabled");
        }

        // Schedule periodic cleanup of deduplication cache
        scheduler.scheduleAtFixedRate(this::cleanupDeduplicationCache, 5, 5, TimeUnit.MINUTES);
    }

    /**
     * Stop all subscriptions and polling.
     */
    public synchronized void stop() {
        if (!started) {
            return;
        }
        started = false;

        // Dispose WebSocket subscriptions
        activeSubscriptions.forEach((sig, disposable) -> {
            if (disposable != null && !disposable.isDisposed()) {
                disposable.dispose();
            }
        });
        activeSubscriptions.clear();

        // Note: scheduler is daemon thread, will stop with JVM
        log.info("EventPollingFallbackService stopped");
    }

    /**
     * Reset state for network switch - clears subscriptions but keeps registrations.
     */
    public synchronized void resetForNetworkSwitch(Web3j newWeb3j, String newContractAddress) {
        stop();
        this.web3j = newWeb3j;
        this.contractAddress = newContractAddress;
        lastProcessedBlock.clear();
        recentlyProcessed.clear();
        inMemoryProcessing.clear();
        log.info("EventPollingFallbackService reset for new network");
        start();
    }

    private void startWebSocketSubscriptions() {
        if (!websocketEnabled) {
            return;
        }
        for (EventRegistration reg : registeredEvents.values()) {
            setupWebSocketSubscription(reg);
        }
    }

    private void setupWebSocketSubscription(EventRegistration registration) {
        try {
            EthFilter filter = new EthFilter(
                DefaultBlockParameterName.LATEST,
                DefaultBlockParameterName.LATEST,
                contractAddress
            );

            Disposable subscription = web3j.ethLogFlowable(filter).subscribe(
                eventLog -> handleEventLog(registration, eventLog, "websocket"),
                error -> {
                    log.warn("WebSocket subscription error for '{}': {} - polling fallback will catch missed events",
                        registration.eventName, error.getMessage());
                    // Schedule reconnection attempt
                    scheduleReconnection(registration);
                },
                () -> {
                    log.info("WebSocket subscription completed for '{}'", registration.eventName);
                    scheduleReconnection(registration);
                }
            );

            activeSubscriptions.put(registration.signature, subscription);
            log.debug("WebSocket subscription active for '{}'", registration.eventName);

        } catch (Exception e) {
            log.error("Failed to setup WebSocket subscription for '{}': {}", registration.eventName, e.getMessage());
        }
    }

    private void scheduleReconnection(EventRegistration registration) {
        if (!started || !websocketEnabled) {
            return;
        }
        scheduler.schedule(() -> {
            if (started) {
                log.info("Attempting to reconnect WebSocket for '{}'", registration.eventName);
                setupWebSocketSubscription(registration);
            }
        }, 30, TimeUnit.SECONDS);
    }

    private void pollForMissedEvents() {
        if (!started || web3j == null) {
            return;
        }

        try {
            BigInteger currentBlock = web3j.ethBlockNumber().send().getBlockNumber();
            BigInteger confirmedHead = confirmedHead(currentBlock);
            if (confirmedHead.signum() < 0) {
                return;
            }
            
            for (EventRegistration reg : registeredEvents.values()) {
                pollEventsForRegistration(reg, confirmedHead);
            }
        } catch (Exception e) {
            log.warn("Polling cycle failed: {}", e.getMessage());
        }
    }

    private void pollEventsForRegistration(EventRegistration registration, BigInteger currentBlock) {
        try {
            if (jdbcTemplate != null && canonicalityVerificationEnabled && !reconcileReorgs(registration, currentBlock)) {
                return;
            }
            int effectiveLookback = Math.max(0, lookbackBlocks);
            int effectiveRange = Math.max(1, maxBlockRange);
            BigInteger lastBlock = loadDurableCursor(registration.signature);
            if (lastBlock != null) {
                lastProcessedBlock.put(registration.signature, lastBlock);
            } else {
                lastBlock = lastProcessedBlock.get(registration.signature);
            }
            BigInteger fromBlock;

            if (lastBlock == null) {
                // First poll - look back a reasonable amount
                BigInteger initialCursor = registration.startBlock;
                if (initialCursor != null) {
                    fromBlock = initialCursor.add(BigInteger.ONE);
                } else {
                    fromBlock = currentBlock.subtract(BigInteger.valueOf(effectiveLookback));
                }
                if (fromBlock.compareTo(BigInteger.ZERO) < 0) {
                    fromBlock = BigInteger.ZERO;
                }
            } else {
                // Continue from last processed + 1
                fromBlock = lastBlock.add(BigInteger.ONE);
            }

            // Don't poll if we're already up to date
            if (fromBlock.compareTo(currentBlock) > 0) {
                return;
            }

            // Limit range to avoid timeout on large ranges (range is inclusive)
            BigInteger toBlock = fromBlock.add(BigInteger.valueOf(effectiveRange - 1L));
            if (toBlock.compareTo(currentBlock) > 0) {
                toBlock = currentBlock;
            }

            // Guard against invalid ranges after clamping
            if (fromBlock.compareTo(toBlock) > 0) {
                log.debug("Skipping poll for '{}' due to invalid range {}-{} (current={})",
                    registration.eventName, fromBlock, toBlock, currentBlock);
                return;
            }

            EthFilter filter = new EthFilter(
                DefaultBlockParameter.valueOf(fromBlock),
                DefaultBlockParameter.valueOf(toBlock),
                contractAddress
            );
            filter.addSingleTopic(registration.signature);

            EthLog ethLog = web3j.ethGetLogs(filter).send();
            
            if (ethLog.hasError()) {
                log.warn("Error polling logs for '{}': {} (range {}-{}, current={})",
                    registration.eventName,
                    ethLog.getError().getMessage(),
                    fromBlock,
                    toBlock,
                    currentBlock
                );
                return;
            }

            @SuppressWarnings("unchecked")
            List<EthLog.LogResult<?>> logs = (List<EthLog.LogResult<?>>) (List<?>) ethLog.getLogs();
            int processed = 0;
            boolean rangeSuccessful = true;
            
            for (EthLog.LogResult<?> logResult : logs) {
                if (logResult instanceof EthLog.LogObject) {
                    Log eventLog = ((EthLog.LogObject) logResult).get();
                    EventProcessingResult result = processEventLog(registration, eventLog, "polling");
                    if (!result.isRangeSafe()) {
                        rangeSuccessful = false;
                    }
                    if (result == EventProcessingResult.PROCESSED
                        || result == EventProcessingResult.ALREADY_COMPLETED
                        || result == EventProcessingResult.DEAD_LETTERED) {
                        processed++;
                    }
                }
            }

            // Never skip a range containing a retryable or in-flight event. The same
            // range is replayed on the next cycle and durable deduplication makes this
            // safe after restarts and across multiple backend instances.
            if (!rangeSuccessful) {
                log.warn("Polling paused for '{}' at blocks {}-{} because at least one event needs retry",
                    registration.eventName, fromBlock, toBlock);
                return;
            }

            persistCursor(registration.signature, toBlock);
            lastProcessedBlock.merge(registration.signature, toBlock,
                (current, candidate) -> current.compareTo(candidate) >= 0 ? current : candidate);

            if (processed > 0) {
                log.info("Polling recovered {} '{}' events from blocks {}-{}",
                    processed, registration.eventName, fromBlock, toBlock);
            } else {
                log.debug("Polling '{}' blocks {}-{}: no new events", registration.eventName, fromBlock, toBlock);
            }

        } catch (Exception e) {
            log.warn("Error polling events for '{}': {}", registration.eventName, e.getMessage());
        }
    }

    /**
     * Handle an event log, with deduplication.
     * @return true if the event was processed (not a duplicate)
     */
    private boolean handleEventLog(EventRegistration registration, Log eventLog, String source) {
        EventProcessingResult result = processEventLog(registration, eventLog, source);
        return result == EventProcessingResult.PROCESSED;
    }

    private EventProcessingResult processEventLog(
        EventRegistration registration,
        Log eventLog,
        String source
    ) {
        List<String> topics = eventLog.getTopics();
        if (topics == null || topics.isEmpty()) {
            return EventProcessingResult.INVALID;
        }

        // Verify event signature matches
        if (!registration.signature.equals(topics.get(0))) {
            return EventProcessingResult.INVALID;
        }

        EventObservation observation = verifyCanonicalityAndDepth(eventLog);
        if (observation == null) {
            return EventProcessingResult.RETRY_REQUIRED;
        }

        EventKey key = eventKey(registration, eventLog, observation.confirmations());
        if (key == null) {
            log.warn("Ignoring '{}' event with incomplete identity (tx={}, logIndex={}, block={})",
                registration.eventName, eventLog.getTransactionHash(), eventLog.getLogIndex(), eventLog.getBlockNumber());
            return EventProcessingResult.INVALID;
        }

        DurableClaim durableClaim;
        try {
            durableClaim = claimDurableEvent(registration, key);
        } catch (Exception ex) {
            log.warn("Unable to claim durable event '{}' (tx={}): {}",
                registration.eventName, key.transactionHash(), ex.getMessage());
            return EventProcessingResult.RETRY_REQUIRED;
        }
        if (durableClaim == null) {
            String dedupKey = key.dedupKey();
            if (recentlyProcessed.containsKey(dedupKey)) {
                log.trace("Skipping duplicate event {} (already processed via {})", dedupKey, source);
                return EventProcessingResult.ALREADY_COMPLETED;
            }
            if (inMemoryProcessing.putIfAbsent(dedupKey, Boolean.TRUE) != null) {
                log.trace("Event {} is already being processed", dedupKey);
                return EventProcessingResult.RETRY_REQUIRED;
            }
        } else if (durableClaim.state() != DurableClaimState.CLAIMED) {
            return switch (durableClaim.state()) {
                case ALREADY_COMPLETED -> EventProcessingResult.ALREADY_COMPLETED;
                case DEAD_LETTERED -> EventProcessingResult.DEAD_LETTERED;
                case RETRY_REQUIRED -> EventProcessingResult.RETRY_REQUIRED;
                case CLAIMED -> throw new IllegalStateException("Unexpected durable claim state");
            };
        }

        try {
            log.debug("Processing '{}' event from {} (tx={}, block={})",
                registration.eventName, source, eventLog.getTransactionHash(), eventLog.getBlockNumber());
            registration.handler.accept(eventLog);

            if (durableClaim != null) {
                EventProcessingResult completionResult;
                try {
                    completionResult = markDurableEventCompleted(key, durableClaim.leaseId());
                } catch (Exception ex) {
                    log.warn("Event '{}' handler completed but journal acknowledgement failed (tx={}): {}",
                        registration.eventName, eventLog.getTransactionHash(), ex.getMessage());
                    return EventProcessingResult.RETRY_REQUIRED;
                }
                if (completionResult != EventProcessingResult.PROCESSED) {
                    log.warn("Event '{}' handler completed but journal acknowledgement failed (tx={})",
                        registration.eventName, eventLog.getTransactionHash());
                    return EventProcessingResult.RETRY_REQUIRED;
                }
            } else {
                recentlyProcessed.put(key.dedupKey(), Instant.now());
            }

            return EventProcessingResult.PROCESSED;
        } catch (Exception e) {
            log.error("Error handling '{}' event (tx={}): {}", 
                registration.eventName, eventLog.getTransactionHash(), e.getMessage(), e);
            if (durableClaim != null) {
                return markDurableEventFailed(registration, key, durableClaim, e.getMessage());
            }
            return EventProcessingResult.RETRY_REQUIRED;
        } finally {
            if (durableClaim == null) {
                inMemoryProcessing.remove(key.dedupKey());
            }
        }
    }

    private BigInteger confirmedHead(BigInteger currentBlock) {
        return currentBlock.subtract(BigInteger.valueOf(Math.max(0, requiredConfirmations)));
    }

    /**
     * A log is eligible only after the configured confirmation depth and a
     * positive canonicality check against its block hash. A transient RPC
     * failure deliberately returns null so the journal does not acknowledge it.
     */
    private EventObservation verifyCanonicalityAndDepth(Log eventLog) {
        if (jdbcTemplate == null || !canonicalityVerificationEnabled) {
            return new EventObservation(true, BigInteger.ZERO);
        }
        String blockHash = eventLog.getBlockHash();
        BigInteger blockNumber = eventLog.getBlockNumber();
        if (blockHash == null || blockHash.isBlank() || blockNumber == null) {
            return null;
        }
        try {
            BigInteger currentBlock = web3j.ethBlockNumber().send().getBlockNumber();
            BigInteger confirmations = currentBlock.subtract(blockNumber);
            if (confirmations.compareTo(BigInteger.valueOf(Math.max(0, requiredConfirmations))) < 0) {
                return null;
            }
            EthBlock response = web3j.ethGetBlockByHash(blockHash, false).send();
            EthBlock.Block block = response == null ? null : response.getBlock();
            if (block == null || block.getHash() == null
                || !blockHash.equalsIgnoreCase(block.getHash())
                || block.getNumber() == null
                || !blockNumber.equals(block.getNumber())) {
                return null;
            }
            return new EventObservation(true, confirmations);
        } catch (Exception ex) {
            log.warn("Unable to verify canonicality for event block {}: {}", blockNumber, ex.getMessage());
            return null;
        }
    }

    private EventKey eventKey(EventRegistration registration, Log eventLog, BigInteger confirmations) {
        String transactionHash = eventLog.getTransactionHash();
        BigInteger logIndex = eventLog.getLogIndex();
        BigInteger blockNumber = eventLog.getBlockNumber();
        String blockHash = eventLog.getBlockHash();
        if (transactionHash == null || transactionHash.isBlank()
            || logIndex == null
            || blockNumber == null
            || (jdbcTemplate != null && (blockHash == null || blockHash.isBlank()))
            || (jdbcTemplate != null && (contractAddress == null || contractAddress.isBlank()))) {
            return null;
        }
        try {
            return new EventKey(
                chainId,
                contractAddress == null || contractAddress.isBlank()
                    ? "in-memory"
                    : contractAddress.trim().toLowerCase(Locale.ROOT),
                registration.signature,
                transactionHash.trim().toLowerCase(Locale.ROOT),
                logIndex,
                blockNumber,
                jdbcTemplate == null ? "in-memory" : blockHash.trim().toLowerCase(Locale.ROOT),
                confirmations
            );
        } catch (RuntimeException ex) {
            return null;
        }
    }

    private DurableClaim claimDurableEvent(EventRegistration registration, EventKey key) {
        if (jdbcTemplate == null) {
            return null;
        }

        String insert = "INSERT IGNORE INTO contract_event_journal "
            + "(chain_id, contract_address, event_signature, transaction_hash, log_index, block_number, block_hash, "
            + "confirmations, canonical_status, event_name, status, attempts, next_attempt_at, first_seen_at, updated_at) "
            + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'CANONICAL', ?, 'PENDING', 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)";
        jdbcTemplate.update(insert,
            key.chainId(),
            key.contractAddress(),
            key.eventSignature(),
            key.transactionHash(),
            new java.math.BigDecimal(key.logIndex()),
            new java.math.BigDecimal(key.blockNumber()),
            key.blockHash(),
            new java.math.BigDecimal(key.confirmations()),
            registration.eventName
        );

        String leaseId = processingInstanceId + ":" + UUID.randomUUID();
        Timestamp staleBefore = Timestamp.from(
            Instant.now().minusSeconds(Math.max(1, processingLeaseTimeoutSeconds))
        );
        int claimed = jdbcTemplate.update(
            "UPDATE contract_event_journal SET status='PROCESSING', lease_id=?, attempts=attempts+1, "
                + "updated_at=CURRENT_TIMESTAMP, last_error=NULL "
                + "WHERE chain_id=? AND contract_address=? AND event_signature=? AND transaction_hash=? AND log_index=? AND block_hash=? AND block_number=? "
                + "AND status NOT IN ('DONE', 'DEAD_LETTER') "
                + "AND (status <> 'PROCESSING' OR updated_at < ?) "
                + "AND (status <> 'FAILED' OR next_attempt_at <= CURRENT_TIMESTAMP) "
                + "AND attempts < ?",
            leaseId,
            key.chainId(),
            key.contractAddress(),
            key.eventSignature(),
            key.transactionHash(),
            new java.math.BigDecimal(key.logIndex()),
            key.blockHash(),
            new java.math.BigDecimal(key.blockNumber()),
            staleBefore,
            effectiveMaxAttempts()
        );

        if (claimed == 1) {
            Integer attempts = jdbcTemplate.queryForObject(
                "SELECT attempts FROM contract_event_journal "
                    + "WHERE chain_id=? AND contract_address=? AND event_signature=? AND transaction_hash=? AND log_index=? AND block_hash=? AND block_number=? "
                    + "AND lease_id=?",
                    Integer.class,
                    key.chainId(),
                    key.contractAddress(),
                    key.eventSignature(),
                    key.transactionHash(),
                    new java.math.BigDecimal(key.logIndex()),
                    key.blockHash(),
                    new java.math.BigDecimal(key.blockNumber()),
                    leaseId
            );
            return DurableClaim.claimed(leaseId, attempts == null ? 1 : attempts);
        }

        String status = jdbcTemplate.query(
            "SELECT status FROM contract_event_journal "
                + "WHERE chain_id=? AND contract_address=? AND event_signature=? AND transaction_hash=? AND log_index=? AND block_hash=? AND block_number=?",
            ps -> {
                ps.setBigDecimal(1, new java.math.BigDecimal(key.chainId()));
                ps.setString(2, key.contractAddress());
                ps.setString(3, key.eventSignature());
                ps.setString(4, key.transactionHash());
                ps.setBigDecimal(5, new java.math.BigDecimal(key.logIndex()));
                ps.setString(6, key.blockHash());
                ps.setBigDecimal(7, new java.math.BigDecimal(key.blockNumber()));
            },
            (rs, rowNum) -> rs.getString(1)
        ).stream().findFirst().orElse(null);
        if ("DONE".equals(status)) {
            return DurableClaim.completed();
        }
        if ("DEAD_LETTER".equals(status)) {
            return DurableClaim.deadLettered();
        }
        return DurableClaim.retryRequired();
    }

    private EventProcessingResult markDurableEventCompleted(EventKey key, String leaseId) {
        int updated = jdbcTemplate.update(
            "UPDATE contract_event_journal SET status='DONE', canonical_status='CANONICAL', confirmations=?, "
                + "lease_id=NULL, processed_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP, last_error=NULL "
                + "WHERE chain_id=? AND contract_address=? AND event_signature=? AND transaction_hash=? AND log_index=? AND block_hash=? AND block_number=? "
                + "AND status='PROCESSING' AND lease_id=?",
            new java.math.BigDecimal(key.confirmations()),
            key.chainId(),
            key.contractAddress(),
            key.eventSignature(),
            key.transactionHash(),
            new java.math.BigDecimal(key.logIndex()),
            key.blockHash(),
            new java.math.BigDecimal(key.blockNumber()),
            leaseId
        );
        return updated == 1 ? EventProcessingResult.PROCESSED : EventProcessingResult.RETRY_REQUIRED;
    }

    private EventProcessingResult markDurableEventFailed(
        EventRegistration registration,
        EventKey key,
        DurableClaim claim,
        String errorMessage
    ) {
        boolean deadLetter = claim.attempts() >= effectiveMaxAttempts();
        Timestamp nextAttempt = Timestamp.from(
            Instant.now().plusSeconds(Math.max(1, retryDelaySeconds))
        );
        int updated;
        try {
            updated = jdbcTemplate.update(
                "UPDATE contract_event_journal SET status=?, canonical_status='UNKNOWN', lease_id=NULL, next_attempt_at=?, "
                    + "last_error=?, updated_at=CURRENT_TIMESTAMP "
                    + "WHERE chain_id=? AND contract_address=? AND event_signature=? AND transaction_hash=? AND log_index=? AND block_hash=? AND block_number=? "
                    + "AND status='PROCESSING' AND lease_id=?",
                deadLetter ? "DEAD_LETTER" : "FAILED",
                nextAttempt,
                truncateError(errorMessage),
                key.chainId(),
                key.contractAddress(),
                key.eventSignature(),
                key.transactionHash(),
                new java.math.BigDecimal(key.logIndex()),
                key.blockHash(),
                new java.math.BigDecimal(key.blockNumber()),
                claim.leaseId()
            );
        } catch (Exception ex) {
            log.warn("Unable to persist failure for durable event '{}' (tx={}): {}",
                registration.eventName, key.transactionHash(), ex.getMessage());
            return EventProcessingResult.RETRY_REQUIRED;
        }
        if (updated != 1) {
            return EventProcessingResult.RETRY_REQUIRED;
        }
        if (deadLetter) {
            log.error("Event '{}' moved to durable dead-letter state after {} attempts (tx={})",
                registration.eventName, claim.attempts(), key.transactionHash());
            return EventProcessingResult.DEAD_LETTERED;
        }
        return EventProcessingResult.RETRY_REQUIRED;
    }

    private String truncateError(String errorMessage) {
        if (errorMessage == null || errorMessage.isBlank()) {
            return "handler failure";
        }
        return errorMessage.length() <= 1024 ? errorMessage : errorMessage.substring(0, 1024);
    }

    private int effectiveMaxAttempts() {
        return Math.max(1, maxProcessingAttempts);
    }

    private BigInteger loadDurableCursor(String eventSignature) {
        if (jdbcTemplate == null || contractAddress == null || contractAddress.isBlank()) {
            return null;
        }
        return jdbcTemplate.query(
            "SELECT last_processed_block FROM contract_event_cursor WHERE chain_id=? AND contract_address=? AND event_signature=?",
            ps -> {
                ps.setBigDecimal(1, new java.math.BigDecimal(chainId));
                ps.setString(2, contractAddress.trim().toLowerCase(Locale.ROOT));
                ps.setString(3, eventSignature);
            },
            (rs, rowNum) -> new BigInteger(rs.getString(1))
        ).stream().findFirst().orElse(null);
    }

    private void persistCursor(String eventSignature, BigInteger blockNumber) {
        if (jdbcTemplate == null || contractAddress == null || contractAddress.isBlank()) {
            return;
        }
        String blockHash = canonicalBlockHash(blockNumber);
        if (blockHash == null) {
            log.warn("Not advancing event cursor at block {} because canonical block hash is unavailable", blockNumber);
            return;
        }
        jdbcTemplate.update(
            "INSERT INTO contract_event_cursor "
                + "(chain_id, contract_address, event_signature, last_processed_block, last_processed_block_hash, updated_at) "
                + "VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP) "
                + "ON DUPLICATE KEY UPDATE "
                + "last_processed_block=GREATEST(last_processed_block, VALUES(last_processed_block)), "
                + "last_processed_block_hash=IF(last_processed_block <= VALUES(last_processed_block), VALUES(last_processed_block_hash), last_processed_block_hash), "
                + "updated_at=CURRENT_TIMESTAMP",
            chainId,
            contractAddress.trim().toLowerCase(Locale.ROOT),
            eventSignature,
            blockNumber,
            blockHash
        );
    }

    private String canonicalBlockHash(BigInteger blockNumber) {
        if (web3j == null || blockNumber == null) {
            return null;
        }
        try {
            EthBlock response = web3j.ethGetBlockByNumber(
                DefaultBlockParameter.valueOf(blockNumber), false
            ).send();
            EthBlock.Block block = response == null ? null : response.getBlock();
            return block == null ? null : block.getHash();
        } catch (Exception ex) {
            log.warn("Unable to resolve canonical hash for cursor block {}: {}", blockNumber, ex.getMessage());
            return null;
        }
    }

    /**
     * Re-checks recent DONE rows. A block hash disappearing from the canonical
     * chain marks the row orphaned and rewinds the cursor to replay that range.
     * Side effects remain idempotent and are driven again only by the canonical
     * replacement log.
     */
    private boolean reconcileReorgs(EventRegistration registration, BigInteger confirmedHead) {
        BigInteger from = confirmedHead.subtract(BigInteger.valueOf(Math.max(0, lookbackBlocks)));
        if (from.signum() < 0) {
            from = BigInteger.ZERO;
        }
        BigInteger scanFrom = from;
        List<JournalBlock> blocks = jdbcTemplate.query(
            "SELECT chain_id, block_number, block_hash FROM contract_event_journal "
                + "WHERE chain_id=? AND contract_address=? AND event_signature=? "
                + "AND canonical_status='CANONICAL' AND block_number BETWEEN ? AND ?",
            ps -> {
                ps.setBigDecimal(1, new java.math.BigDecimal(chainId));
                ps.setString(2, normalizedContractAddress());
                ps.setString(3, registration.signature);
                ps.setBigDecimal(4, new java.math.BigDecimal(scanFrom));
                ps.setBigDecimal(5, new java.math.BigDecimal(confirmedHead));
            },
            (rs, rowNum) -> new JournalBlock(
                rs.getBigDecimal("chain_id").toBigIntegerExact(),
                rs.getBigDecimal("block_number").toBigIntegerExact(),
                rs.getString("block_hash")
            )
        );

        for (JournalBlock journalBlock : blocks) {
            CanonicalState state = canonicalState(journalBlock.blockHash(), journalBlock.blockNumber());
            if (state == CanonicalState.UNKNOWN) {
                return false;
            }
            if (state == CanonicalState.ORPHANED) {
                markOrphaned(registration, journalBlock);
            }
        }
        return true;
    }

    private CanonicalState canonicalState(String blockHash, BigInteger blockNumber) {
        try {
            EthBlock response = web3j.ethGetBlockByHash(blockHash, false).send();
            EthBlock.Block block = response == null ? null : response.getBlock();
            if (block == null || block.getHash() == null || block.getNumber() == null) {
                return CanonicalState.ORPHANED;
            }
            return blockHash.equalsIgnoreCase(block.getHash()) && blockNumber.equals(block.getNumber())
                ? CanonicalState.CANONICAL
                : CanonicalState.ORPHANED;
        } catch (Exception ex) {
            log.warn("Unable to reconcile canonical block {}: {}", blockNumber, ex.getMessage());
            return CanonicalState.UNKNOWN;
        }
    }

    private void markOrphaned(EventRegistration registration, JournalBlock journalBlock) {
        int updated = jdbcTemplate.update(
            "UPDATE contract_event_journal SET status='ORPHANED', canonical_status='ORPHANED', "
                + "lease_id=NULL, last_error=?, updated_at=CURRENT_TIMESTAMP "
                + "WHERE chain_id=? AND contract_address=? AND event_signature=? "
                + "AND block_number=? AND block_hash=?",
            "block hash is no longer canonical",
            journalBlock.chainId(),
            normalizedContractAddress(),
            registration.signature,
            new java.math.BigDecimal(journalBlock.blockNumber()),
            journalBlock.blockHash()
        );
        if (updated > 0) {
            jdbcTemplate.update(
                "UPDATE contract_event_cursor SET last_processed_block=?, last_processed_block_hash=NULL "
                    + "WHERE chain_id=? AND contract_address=? AND event_signature=? "
                    + "AND last_processed_block >= ?",
                journalBlock.blockNumber().subtract(BigInteger.ONE),
                journalBlock.chainId(),
                normalizedContractAddress(),
                registration.signature,
                journalBlock.blockNumber()
            );
            log.error(
                "Contract event reorg detected for '{}' at block {} (hash={}); cursor rewound",
                registration.eventName,
                journalBlock.blockNumber(),
                journalBlock.blockHash()
            );
        }
    }

    private String normalizedContractAddress() {
        return contractAddress.trim().toLowerCase(Locale.ROOT);
    }

    private void cleanupDeduplicationCache() {
        Instant cutoff = Instant.now().minus(DEDUP_TTL);
        int removed = 0;
        
        var iterator = recentlyProcessed.entrySet().iterator();
        while (iterator.hasNext()) {
            if (iterator.next().getValue().isBefore(cutoff)) {
                iterator.remove();
                removed++;
            }
        }
        
        if (removed > 0) {
            log.debug("Cleaned up {} expired entries from deduplication cache", removed);
        }
    }

    /**
     * Get the last processed block for an event (useful for diagnostics).
     */
    public BigInteger getLastProcessedBlock(String eventSignature) {
        return lastProcessedBlock.get(eventSignature);
    }

    /**
     * Get count of registered events.
     */
    public int getRegisteredEventCount() {
        return registeredEvents.size();
    }

    /**
     * Check if a specific subscription is active.
     */
    public boolean isSubscriptionActive(String eventSignature) {
        Disposable sub = activeSubscriptions.get(eventSignature);
        return sub != null && !sub.isDisposed();
    }

    private enum EventProcessingResult {
        PROCESSED,
        ALREADY_COMPLETED,
        DEAD_LETTERED,
        RETRY_REQUIRED,
        INVALID;

        private boolean isRangeSafe() {
            return this == PROCESSED || this == ALREADY_COMPLETED || this == DEAD_LETTERED;
        }
    }

    private enum CanonicalState {
        CANONICAL,
        ORPHANED,
        UNKNOWN
    }

    private enum DurableClaimState {
        CLAIMED,
        ALREADY_COMPLETED,
        DEAD_LETTERED,
        RETRY_REQUIRED
    }

    private record DurableClaim(DurableClaimState state, String leaseId, int attempts) {
        private static DurableClaim claimed(String leaseId, int attempts) {
            return new DurableClaim(DurableClaimState.CLAIMED, leaseId, attempts);
        }

        private static DurableClaim completed() {
            return new DurableClaim(DurableClaimState.ALREADY_COMPLETED, null, 0);
        }

        private static DurableClaim deadLettered() {
            return new DurableClaim(DurableClaimState.DEAD_LETTERED, null, 0);
        }

        private static DurableClaim retryRequired() {
            return new DurableClaim(DurableClaimState.RETRY_REQUIRED, null, 0);
        }
    }

    private record EventKey(
        BigInteger chainId,
        String contractAddress,
        String eventSignature,
        String transactionHash,
        BigInteger logIndex,
        BigInteger blockNumber,
        String blockHash,
        BigInteger confirmations
    ) {
        private String dedupKey() {
            return chainId + ":" + contractAddress + ":" + eventSignature + ":" + transactionHash
                + ":" + blockHash + ":" + logIndex;
        }
    }

    private record EventObservation(boolean canonical, BigInteger confirmations) { }

    private record JournalBlock(BigInteger chainId, BigInteger blockNumber, String blockHash) { }

    private record EventRegistration(
        String eventName,
        Event event,
        String signature,
        BigInteger startBlock,
        Consumer<Log> handler
    ) {}
}
