package decentralabs.blockchain.service;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service for rate limiting using Bucket4j token bucket algorithm
 */
@Service
@Slf4j
public class RateLimitService {

    @Value("${wallet.max.transactions.per.hour:100}")
    private int maxTransactionsPerHour;

    @Value("${wallet.max.balance.checks.per.minute:60}")
    private int maxBalanceChecksPerMinute;

    // Separate buckets for transactions and balance checks per wallet
    private final Map<String, Bucket> transactionBuckets = new ConcurrentHashMap<>();
    private final Map<String, Bucket> balanceCheckBuckets = new ConcurrentHashMap<>();

    /**
     * Check if transaction is allowed for the given wallet
     * @param walletAddress Wallet address
     * @return true if allowed, false if rate limit exceeded
     */
    public boolean allowTransaction(String walletAddress) {
        Bucket bucket = transactionBuckets.computeIfAbsent(walletAddress, k -> createTransactionBucket());
        boolean allowed = bucket.tryConsume(1);
        
        if (!allowed) {
            log.warn("Transaction rate limit exceeded for wallet");
        }
        
        return allowed;
    }

    /**
     * Check if balance check is allowed for the given wallet
     * @param walletAddress Wallet address
     * @return true if allowed, false if rate limit exceeded
     */
    public boolean allowBalanceCheck(String walletAddress) {
        Bucket bucket = balanceCheckBuckets.computeIfAbsent(walletAddress, k -> createBalanceCheckBucket());
        boolean allowed = bucket.tryConsume(1);
        
        if (!allowed) {
            log.warn("Balance check rate limit exceeded for wallet");
        }
        
        return allowed;
    }

    /**
     * Create bucket for transaction rate limiting (per hour)
     */
    private Bucket createTransactionBucket() {
        return Bucket.builder()
            .addLimit(Bandwidth.builder()
                .capacity(maxTransactionsPerHour)
                .refillIntervally(maxTransactionsPerHour, Duration.ofHours(1))
                .build())
            .build();
    }

    /**
     * Create bucket for balance check rate limiting (per minute)
     */
    private Bucket createBalanceCheckBucket() {
        return Bucket.builder()
            .addLimit(Bandwidth.builder()
                .capacity(maxBalanceChecksPerMinute)
                .refillIntervally(maxBalanceChecksPerMinute, Duration.ofMinutes(1))
                .build())
            .build();
    }

    /**
     * Get remaining transactions available for wallet
     */
    public long getRemainingTransactions(String walletAddress) {
        Bucket bucket = transactionBuckets.get(walletAddress);
        return bucket != null ? bucket.getAvailableTokens() : maxTransactionsPerHour;
    }

    /**
     * Get remaining balance checks available for wallet
     */
    public long getRemainingBalanceChecks(String walletAddress) {
        Bucket bucket = balanceCheckBuckets.get(walletAddress);
        return bucket != null ? bucket.getAvailableTokens() : maxBalanceChecksPerMinute;
    }

    /**
     * Clean up old buckets (should be called periodically)
     */
    public void cleanupOldBuckets() {
        // Remove buckets that haven't been used (this is a simple cleanup)
        // In production, you might want to use a more sophisticated eviction policy
        if (transactionBuckets.size() > 10000) {
            log.info("Cleaning up transaction buckets, current size: {}", transactionBuckets.size());
            transactionBuckets.clear();
        }
        if (balanceCheckBuckets.size() > 10000) {
            log.info("Cleaning up balance check buckets, current size: {}", balanceCheckBuckets.size());
            balanceCheckBuckets.clear();
        }
    }
}
