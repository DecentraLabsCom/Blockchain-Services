package decentralabs.blockchain.service.persistence;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Anti-replay protection service using timestamp tracking
 * 
 * Current implementation uses in-memory storage (ConcurrentHashMap).
 * For production deployment with multiple instances, use Redis:
 * 
 * Redis implementation:
 *   1. Add dependency: spring-boot-starter-data-redis
 *   2. Use RedisTemplate or Spring Cache with Redis
 *   3. Store timestamps with automatic expiration (TTL = 5 minutes)
 *   4. Key format: "replay:{walletAddress}:{timestamp}"
 *   5. Command: SET key "used" EX 300 NX (atomic check-and-set)
 * 
 * Benefits of Redis:
 * - Shared state across multiple service instances
 * - Automatic expiration (no manual cleanup needed)
 * - Atomic operations prevent race conditions
 * - Persistence survives service restarts
 * 
 * Alternative: Database with indexed timestamps and cleanup job
 */
@Service
@Slf4j
public class AntiReplayService {

    private static final long TIMESTAMP_EXPIRATION_MS = 5 * 60 * 1000; // 5 minutes

    @Value("${antireplay.persistence.enabled:false}")
    private boolean persistenceEnabled;

    // In-memory fallback: wallet-timestamp -> insertion time
    private final Map<String, Long> usedTimestamps = new ConcurrentHashMap<>();

    /**
     * Checks if a timestamp has been used and marks it as used
     * 
     * @param walletAddress The wallet address
     * @param timestamp The timestamp to check
     * @return true if timestamp was already used (replay attack), false if it's new
     */
    public boolean isTimestampUsed(String walletAddress, long timestamp) {
        String key = walletAddress + "-" + timestamp;
        
        if (persistenceEnabled) {
            // TODO: Implement Redis SETNX with expiration
            log.warn("Anti-replay persistence enabled but not implemented. Using in-memory storage.");
        }
        
        // Check if already used
        if (usedTimestamps.containsKey(key)) {
            log.warn("Replay attack detected for wallet {} with timestamp {}", walletAddress, timestamp);
            return true;
        }
        
        // Mark as used
        usedTimestamps.put(key, System.currentTimeMillis());
        
        // Cleanup old entries (over 5 minutes old)
        cleanupExpiredTimestamps();
        
        return false;
    }

    /**
     * Removes timestamps older than expiration time
     * Called periodically to prevent memory leaks
     */
    private void cleanupExpiredTimestamps() {
        long now = System.currentTimeMillis();
        long cutoff = now - TIMESTAMP_EXPIRATION_MS;
        
        // Remove entries older than 5 minutes
        usedTimestamps.entrySet().removeIf(entry -> entry.getValue() < cutoff);
        
        if (usedTimestamps.size() > 10000) {
            log.warn("Anti-replay cache has {} entries. Consider enabling Redis persistence.", 
                usedTimestamps.size());
        }
    }

    /**
     * Gets the count of tracked timestamps (for monitoring)
     */
    public int getTrackedTimestampCount() {
        return usedTimestamps.size();
    }

    /**
     * Clears all tracked timestamps (use with caution)
     */
    public void clearAll() {
        usedTimestamps.clear();
        log.info("Anti-replay cache cleared");
    }
}
