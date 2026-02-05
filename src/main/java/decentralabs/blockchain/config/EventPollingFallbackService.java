package decentralabs.blockchain.config;

import io.reactivex.disposables.Disposable;
import java.math.BigInteger;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.web3j.abi.EventEncoder;
import org.web3j.abi.datatypes.Event;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameter;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.EthFilter;
import org.web3j.protocol.core.methods.response.EthLog;
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

    @Value("${contract.event.polling.interval.seconds:60}")
    private int pollingIntervalSeconds;

    @Value("${contract.event.polling.block.range:1000}")
    private int maxBlockRange;

    @Value("${contract.event.polling.lookback.blocks:100}")
    private int lookbackBlocks;

    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "event-polling-fallback");
        t.setDaemon(true);
        return t;
    });

    /** Last successfully processed block per event signature */
    private final Map<String, BigInteger> lastProcessedBlock = new ConcurrentHashMap<>();

    /** Recently seen transaction hashes for deduplication (TTL ~10 min) */
    private final Map<String, Instant> recentlyProcessed = new ConcurrentHashMap<>();
    private static final Duration DEDUP_TTL = Duration.ofMinutes(10);

    /** Active subscriptions for cleanup */
    private final Map<String, Disposable> activeSubscriptions = new ConcurrentHashMap<>();

    /** Registered event handlers */
    private final Map<String, EventRegistration> registeredEvents = new ConcurrentHashMap<>();

    private volatile Web3j web3j;
    private volatile String contractAddress;
    private volatile boolean started = false;

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
        
        EventRegistration registration = new EventRegistration(eventName, event, signature, handler);
        registeredEvents.put(signature, registration);

        // Initialize last processed block
        if (startBlock != null) {
            lastProcessedBlock.put(signature, startBlock);
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

        started = true;

        // Start WebSocket subscriptions for real-time events
        startWebSocketSubscriptions();

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
        log.info("EventPollingFallbackService reset for new network");
        start();
    }

    private void startWebSocketSubscriptions() {
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
        if (!started) {
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
            
            for (EventRegistration reg : registeredEvents.values()) {
                pollEventsForRegistration(reg, currentBlock);
            }
        } catch (Exception e) {
            log.warn("Polling cycle failed: {}", e.getMessage());
        }
    }

    private void pollEventsForRegistration(EventRegistration registration, BigInteger currentBlock) {
        try {
            int effectiveLookback = Math.max(0, lookbackBlocks);
            int effectiveRange = Math.max(1, maxBlockRange);
            BigInteger lastBlock = lastProcessedBlock.get(registration.signature);
            BigInteger fromBlock;

            if (lastBlock == null) {
                // First poll - look back a reasonable amount
                fromBlock = currentBlock.subtract(BigInteger.valueOf(effectiveLookback));
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
            
            for (EthLog.LogResult<?> logResult : logs) {
                if (logResult instanceof EthLog.LogObject) {
                    Log eventLog = ((EthLog.LogObject) logResult).get();
                    if (handleEventLog(registration, eventLog, "polling")) {
                        processed++;
                    }
                }
            }

            // Update last processed block
            lastProcessedBlock.put(registration.signature, toBlock);

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
        List<String> topics = eventLog.getTopics();
        if (topics == null || topics.isEmpty()) {
            return false;
        }

        // Verify event signature matches
        if (!registration.signature.equals(topics.get(0))) {
            return false;
        }

        // Deduplication key: txHash + logIndex
        String dedupKey = eventLog.getTransactionHash() + "-" + eventLog.getLogIndex();
        
        Instant existing = recentlyProcessed.putIfAbsent(dedupKey, Instant.now());
        if (existing != null) {
            log.trace("Skipping duplicate event {} (already processed via {})", dedupKey, source);
            return false;
        }

        try {
            log.debug("Processing '{}' event from {} (tx={}, block={})",
                registration.eventName, source, eventLog.getTransactionHash(), eventLog.getBlockNumber());
            registration.handler.accept(eventLog);
            
            // Update last processed block if this is newer
            BigInteger blockNumber = eventLog.getBlockNumber();
            lastProcessedBlock.compute(registration.signature, (sig, current) -> 
                current == null || blockNumber.compareTo(current) > 0 ? blockNumber : current
            );
            
            return true;
        } catch (Exception e) {
            log.error("Error handling '{}' event (tx={}): {}", 
                registration.eventName, eventLog.getTransactionHash(), e.getMessage(), e);
            return false;
        }
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

    private record EventRegistration(
        String eventName,
        Event event,
        String signature,
        Consumer<Log> handler
    ) {}
}
