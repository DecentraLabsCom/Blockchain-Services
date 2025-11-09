package decentralabs.blockchain.service.treasury;

import java.time.Instant;
import java.util.Comparator;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Collectors;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Keeps lightweight analytics in-memory so the dashboard can show recent activity
 * without requiring on-chain indexing.
 */
@Service
@Slf4j
public class InstitutionalAnalyticsService {

    private static final int MAX_TRANSACTIONS_PER_PROVIDER = 100;
    private static final int MAX_TRACKED_USERS_PER_PROVIDER = 200;

    private final ConcurrentMap<String, Deque<TransactionRecord>> transactionHistory = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Map<String, UserActivity>> providerUsers = new ConcurrentHashMap<>();

    public void recordTransaction(String providerAddress, TransactionRecord record) {
        String provider = normalize(providerAddress);
        transactionHistory
            .computeIfAbsent(provider, k -> new ConcurrentLinkedDeque<>())
            .addFirst(record);

        Deque<TransactionRecord> deque = transactionHistory.get(provider);
        while (deque.size() > MAX_TRANSACTIONS_PER_PROVIDER) {
            deque.removeLast();
        }
        log.debug("Recorded transaction {} for provider {}", record.getHash(), provider);
    }

    public List<TransactionRecord> getRecentTransactions(String providerAddress, int limit) {
        String provider = normalize(providerAddress);
        Deque<TransactionRecord> deque = transactionHistory.get(provider);
        if (deque == null) {
            return List.of();
        }
        return deque.stream()
            .limit(Math.max(0, limit))
            .collect(Collectors.toList());
    }

    public void recordUserActivity(String providerAddress, String puc) {
        if (puc == null || puc.isBlank()) {
            return;
        }
        String provider = normalize(providerAddress);
        providerUsers
            .computeIfAbsent(provider, k -> new ConcurrentHashMap<>())
            .put(puc, new UserActivity(puc, Instant.now().toEpochMilli()));

        Map<String, UserActivity> users = providerUsers.get(provider);
        if (users.size() > MAX_TRACKED_USERS_PER_PROVIDER) {
            users.entrySet().stream()
                .sorted(Comparator.comparingLong(e -> e.getValue().getLastSeenEpochMillis()))
                .limit(users.size() - MAX_TRACKED_USERS_PER_PROVIDER)
                .forEach(entry -> users.remove(entry.getKey()));
        }
    }

    public List<UserActivity> getKnownUsers(String providerAddress, int limit) {
        String provider = normalize(providerAddress);
        Map<String, UserActivity> users = providerUsers.get(provider);
        if (users == null || users.isEmpty()) {
            return List.of();
        }
        return users.values().stream()
            .sorted(Comparator.comparingLong(UserActivity::getLastSeenEpochMillis).reversed())
            .limit(Math.max(0, limit))
            .collect(Collectors.toList());
    }

    private String normalize(String providerAddress) {
        return providerAddress == null ? "" : providerAddress.toLowerCase();
    }

    @Value
    public static class TransactionRecord {
        String hash;
        String type;
        String description;
        String amountTokens;
        long timestamp;
        String status;
    }

    @Value
    public static class UserActivity {
        String puc;
        long lastSeenEpochMillis;
    }
}
