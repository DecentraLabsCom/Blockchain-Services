package decentralabs.blockchain.service.persistence;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Anti-replay protection service using timestamp tracking with optional disk persistence.
 */
@Service
@Slf4j
public class AntiReplayService {

    private static final long TIMESTAMP_EXPIRATION_MS = 5 * 60 * 1000; // 5 minutes

    @Value("${antireplay.persistence.enabled:false}")
    private boolean persistenceEnabled;

    @Value("${antireplay.persistence.file.path:./data/antireplay-cache.json}")
    private String persistenceFilePath;

    // In-memory storage: wallet-timestamp -> insertion time
    private final Map<String, Long> usedTimestamps = new ConcurrentHashMap<>();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @PostConstruct
    public void loadPersistentCache() {
        if (!persistenceEnabled) {
            return;
        }
        Path path = Path.of(persistenceFilePath);
        if (!Files.exists(path)) {
            return;
        }
        try {
            Map<String, Long> stored = objectMapper.readValue(path.toFile(), new TypeReference<>() {});
            long cutoff = System.currentTimeMillis() - TIMESTAMP_EXPIRATION_MS;
            stored.entrySet().stream()
                .filter(entry -> entry.getValue() >= cutoff)
                .forEach(entry -> usedTimestamps.put(entry.getKey(), entry.getValue()));
            cleanupExpiredTimestamps();
            log.info("Anti-replay cache loaded from {}", persistenceFilePath);
        } catch (IOException ex) {
            log.warn("Failed to load anti-replay cache from {}: {}", persistenceFilePath, ex.getMessage());
        }
    }

    /**
     * Checks if a timestamp has been used and marks it as used.
     *
     * @param walletAddress The wallet address
     * @param timestamp     The timestamp to check
     * @return true if timestamp was already used (replay attack), false if it's new
     */
    public boolean isTimestampUsed(String walletAddress, long timestamp) {
        String key = walletAddress + "-" + timestamp;

        cleanupExpiredTimestamps();

        // Check if already used
        if (usedTimestamps.containsKey(key)) {
            log.warn("Replay attack detected for wallet {} with timestamp {}", walletAddress, timestamp);
            return true;
        }

        // Mark as used
        usedTimestamps.put(key, System.currentTimeMillis());

        if (persistenceEnabled) {
            persistToDisk();
        }

        return false;
    }

    /**
     * Removes timestamps older than expiration time.
     */
    private void cleanupExpiredTimestamps() {
        long now = System.currentTimeMillis();
        long cutoff = now - TIMESTAMP_EXPIRATION_MS;

        // Remove entries older than 5 minutes
        usedTimestamps.entrySet().removeIf(entry -> entry.getValue() < cutoff);

        if (usedTimestamps.size() > 10000) {
            log.warn("Anti-replay cache has {} entries. Consider enabling a shared store such as Redis.",
                usedTimestamps.size());
        }
    }

    /**
     * Gets the count of tracked timestamps (for monitoring).
     */
    public int getTrackedTimestampCount() {
        return usedTimestamps.size();
    }

    /**
     * Clears all tracked timestamps (use with caution).
     */
    public void clearAll() {
        usedTimestamps.clear();
        if (persistenceEnabled) {
            persistToDisk();
        }
        log.info("Anti-replay cache cleared");
    }

    private void persistToDisk() {
        Path path = Path.of(persistenceFilePath);
        try {
            if (path.getParent() != null) {
                Files.createDirectories(path.getParent());
            }
            objectMapper.writerWithDefaultPrettyPrinter().writeValue(path.toFile(), usedTimestamps);
        } catch (IOException ex) {
            log.warn("Failed to persist anti-replay cache to {}: {}", persistenceFilePath, ex.getMessage());
        }
    }
}
