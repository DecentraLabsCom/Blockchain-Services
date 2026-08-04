package decentralabs.blockchain.service.provider;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.LongAdder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * Serializes provider reservation-capacity decisions across backend replicas.
 *
 * <p>The action runs while the same MySQL connection owns a named advisory lock.
 * Keeping the connection inside one JdbcTemplate callback is essential: acquiring
 * and releasing GET_LOCK through separate JdbcTemplate calls could use different
 * pooled connections and would not protect the critical section.</p>
 */
@Service
@Slf4j
public class DistributedReservationAvailabilityLockService {

    private static final String ACQUIRE_LOCK_SQL = "SELECT GET_LOCK(?, ?)";
    private static final String RELEASE_LOCK_SQL = "SELECT RELEASE_LOCK(?)";
    private static final String HEALTH_PROBE_LOCK_NAME =
        "decentralabs:provider-reservation-availability:health-probe";
    private static final int MYSQL_LOCK_NAME_LENGTH = 64;

    private final ObjectProvider<JdbcTemplate> jdbcTemplateProvider;
    private final LongAdder waitNanos = new LongAdder();
    private final LongAdder waitSamples = new LongAdder();
    private final LongAdder timeoutCount = new LongAdder();
    private final LongAdder retryCount = new LongAdder();
    private final AtomicInteger locksHeld = new AtomicInteger();
    private final AtomicReference<Boolean> getLockAvailable = new AtomicReference<>(false);

    /** A blocked provider worker is retried; it must not deny the reservation. */
    @Value("${provider.reservation.availability.lock-timeout.seconds:60}")
    private int lockTimeoutSeconds = 60;

    public DistributedReservationAvailabilityLockService(ObjectProvider<JdbcTemplate> jdbcTemplateProvider) {
        this.jdbcTemplateProvider = jdbcTemplateProvider;
    }

    public <T> T withLock(ReservationAvailabilityLockKey key, LockAction<T> action) throws Exception {
        if (key == null) {
            throw new IllegalArgumentException("Reservation availability lock key is required");
        }
        if (action == null) {
            throw new IllegalArgumentException("Reservation availability lock action is required");
        }

        JdbcTemplate jdbcTemplate = jdbcTemplateProvider.getIfAvailable();
        if (jdbcTemplate == null) {
            getLockAvailable.set(false);
            throw new DistributedLockException(
                "Provider reservation availability requires a configured JdbcTemplate"
            );
        }

        String lockName = lockNameFor(key);
        try {
            return jdbcTemplate.execute((ConnectionCallback<T>) connection ->
                executeWhileLocked(connection, lockName, key, action));
        } catch (ActionFailureException failure) {
            return rethrowActionFailure(failure.getCause());
        } catch (DataAccessException ex) {
            throw new DistributedLockException(
                "Unable to acquire provider reservation availability lock for lab " + key.labId(), ex
            );
        }
    }

    /** Exposed package-wide for deterministic tests and operational diagnostics. */
    String lockNameFor(ReservationAvailabilityLockKey key) {
        String material = "decentralabs:provider-reservation-availability:v1|"
            + key.chainId() + "|" + key.contractAddress() + "|" + key.labId();
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(material.getBytes(StandardCharsets.UTF_8));
            String lockName = java.util.HexFormat.of().formatHex(digest);
            if (lockName.length() != MYSQL_LOCK_NAME_LENGTH) {
                throw new IllegalStateException("Unexpected MySQL advisory lock name length");
            }
            return lockName;
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is unavailable", ex);
        }
    }

    private <T> T executeWhileLocked(
        Connection connection,
        String lockName,
        ReservationAvailabilityLockKey key,
        LockAction<T> action
    ) throws java.sql.SQLException {
        long waitStarted = System.nanoTime();
        Integer result;
        try {
            result = executeLockQuery(connection, ACQUIRE_LOCK_SQL, lockName, lockTimeoutSeconds());
            recordWait(waitStarted);
            getLockAvailable.set(result != null);
        } catch (java.sql.SQLException ex) {
            recordWait(waitStarted);
            getLockAvailable.set(false);
            throw ex;
        }
        if (result == null) {
            throw new DistributedLockException(
                "MySQL GET_LOCK returned NULL for provider reservation lab " + key.labId()
            );
        }
        if (result != 1) {
            timeoutCount.increment();
            throw new DistributedLockException(
                "Provider reservation availability lock timeout for lab " + key.labId()
            );
        }

        locksHeld.incrementAndGet();
        try {
            try {
                return action.run();
            } catch (Throwable failure) {
                throw new ActionFailureException(failure);
            }
        } finally {
            try {
                releaseLock(connection, lockName, key);
            } finally {
                locksHeld.decrementAndGet();
            }
        }
    }

    /**
     * Probes the MySQL advisory-lock function on a disposable named lock and
     * returns the current lock telemetry for the detailed health endpoint.
     * A result of {@code 0} still proves that GET_LOCK is available; it only
     * means another session owns the probe name at that instant.
     */
    public LockHealthSnapshot healthSnapshot() {
        JdbcTemplate jdbcTemplate = jdbcTemplateProvider.getIfAvailable();
        if (jdbcTemplate == null) {
            getLockAvailable.set(false);
            return currentHealthSnapshot();
        }

        try {
            Boolean available = jdbcTemplate.execute((ConnectionCallback<Boolean>) connection -> {
                Integer result = executeLockQuery(connection, ACQUIRE_LOCK_SQL, HEALTH_PROBE_LOCK_NAME, 0);
                if (result == null) {
                    return false;
                }
                if (result == 1) {
                    releaseHealthProbeLock(connection);
                }
                return result == 0 || result == 1;
            });
            getLockAvailable.set(Boolean.TRUE.equals(available));
        } catch (Exception ex) {
            getLockAvailable.set(false);
            log.warn("MySQL GET_LOCK health probe failed: {}", ex.getMessage());
        }
        return currentHealthSnapshot();
    }

    /** Records a provider reservation attempt scheduled after a previous failure. */
    public void recordReservationRetry() {
        retryCount.increment();
    }

    /** Exposed package-wide for deterministic tests and operational diagnostics. */
    LockHealthSnapshot currentHealthSnapshot() {
        return new LockHealthSnapshot(
            Boolean.TRUE.equals(getLockAvailable.get()),
            averageWaitMillis(),
            timeoutCount.sum(),
            locksHeld.get(),
            retryCount.sum()
        );
    }

    private Integer executeLockQuery(
        Connection connection,
        String sql,
        String lockName,
        int timeoutSeconds
    ) throws java.sql.SQLException {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, lockName);
            if (ACQUIRE_LOCK_SQL.equals(sql)) {
                statement.setInt(2, timeoutSeconds);
            }
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    return null;
                }
                int value = result.getInt(1);
                return result.wasNull() ? null : value;
            }
        }
    }

    private void releaseLock(
        Connection connection,
        String lockName,
        ReservationAvailabilityLockKey key
    ) throws java.sql.SQLException {
        releaseLock(connection, lockName, key.labId().toString());
    }

    private void releaseLock(
        Connection connection,
        String lockName,
        String labId
    ) throws java.sql.SQLException {
        try {
            Integer result = executeLockQuery(connection, RELEASE_LOCK_SQL, lockName, 0);
            if (result == null || result != 1) {
                log.warn(
                    "MySQL RELEASE_LOCK did not confirm release for provider reservation lab {}",
                    labId
                );
            }
        } catch (java.sql.SQLException ex) {
            // Connection termination releases GET_LOCK implicitly. Do not turn a
            // completed on-chain confirmation into an auto-denial because cleanup
            // could not run on a broken connection.
            log.warn(
                "Unable to explicitly release provider reservation availability lock for lab {}: {}",
                labId,
                ex.getMessage()
            );
        }
    }

    private void releaseHealthProbeLock(Connection connection) {
        try {
            releaseLock(connection, HEALTH_PROBE_LOCK_NAME, "health-probe");
        } catch (java.sql.SQLException ex) {
            // The connection will release the named lock if it is terminated.
            log.warn("Unable to release MySQL GET_LOCK health probe: {}", ex.getMessage());
        }
    }

    private void recordWait(long waitStarted) {
        waitNanos.add(Math.max(0, System.nanoTime() - waitStarted));
        waitSamples.increment();
    }

    private double averageWaitMillis() {
        long samples = waitSamples.sum();
        if (samples == 0) {
            return 0.0;
        }
        return waitNanos.sum() / (double) samples / 1_000_000.0;
    }

    private int lockTimeoutSeconds() {
        return Math.max(0, lockTimeoutSeconds);
    }

    private <T> T rethrowActionFailure(Throwable failure) throws Exception {
        if (failure instanceof Error error) {
            throw error;
        }
        if (failure instanceof Exception exception) {
            throw exception;
        }
        throw new IllegalStateException("Provider reservation availability action failed", failure);
    }

    @FunctionalInterface
    public interface LockAction<T> {
        T run() throws Exception;
    }

    public static class DistributedLockException extends RuntimeException {
        public DistributedLockException(String message) {
            super(message);
        }

        public DistributedLockException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private static final class ActionFailureException extends RuntimeException {
        private ActionFailureException(Throwable cause) {
            super(cause);
        }
    }

    public record LockHealthSnapshot(
        boolean getLockAvailable,
        double averageWaitMs,
        long timeouts,
        int locksHeld,
        long retries
    ) {
        public Map<String, Object> asMap() {
            return Map.of(
                "get_lock_available", getLockAvailable,
                "average_wait_ms", averageWaitMs,
                "timeouts", timeouts,
                "locks_held", locksHeld,
                "retries", retries
            );
        }
    }
}
